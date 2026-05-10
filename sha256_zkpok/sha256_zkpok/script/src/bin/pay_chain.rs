//! Multi-hop pay-chain simulator for the dPay payment protocol.
//!
//! Walks the full Setup / Lock / Release / Cash flow across an n-hop
//! payment path U_0 -> U_1 -> ... -> U_{n-1} -> U_n. The wormhole-resistant
//! lock mechanism Π_wr is stubbed as a plain hash lock under r = SHA256(σ);
//! everything else (the blind-Schnorr setup, the SP1 ZKPoK, the unblinded
//! cash-out signature, and the payee redeem) is real.
//!
//! The signer-side ZKPoK is the same one proved by the `sha256-zkpok` ELF:
//!     { σ : r = SHA256(σ)  ∧  σ·G = R + e·X }.
//!
//! Modes:
//!   --execute      run the simulation in the SP1 emulator (fast, no proof)
//!   --prove        generate a real STARK proof of the setup-phase ZKPoK
//!
//! Failure injection:
//!   --break-release-at-hop <i>   release with garbage instead of σ at hop i;
//!                                expect the next intermediary to abort.

use clap::{ArgGroup, Parser};
use hex::FromHex;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use sha256_zkpok_script::blind_schnorr::{
    self, point_to_compressed, scalar_from_bytes, scalar_to_bytes, PayerBlind, SignerNonce,
    SignerSecret,
};
use sha256_zkpok_script::cashout::CashoutTx;
use sha256_zkpok_script::wormhole::{self, WrSecrets};
use sha256_zkpok_script::{
    assert_public_matches_transcript, build_zkpok_stdin, defaults, timed, Public,
};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey,
};
use std::num::NonZeroUsize;
use std::time::Instant;

const ELF: Elf = include_elf!("sha256-zkpok-program");
const DEFAULT_PAYEE_PK: &str =
    "020202020202020202020202020202020202020202020202020202020202020202";
const DEFAULT_Y_SEED: &str =
    "0000000000000000000000000000000000000000000000000000000000000099";

fn hex32(s: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::from_hex(s.trim_start_matches("0x")).map_err(|e| e.to_string())
}

fn hex33(s: &str) -> Result<[u8; 33], String> {
    <[u8; 33]>::from_hex(s.trim_start_matches("0x")).map_err(|e| e.to_string())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(group(ArgGroup::new("mode").required(true).args(["execute", "prove"])))]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// Number of hops on the lock/release path (= number of edges
    /// U_0..U_{n-1}). Total nodes including payee = n + 1.
    #[arg(long, default_value_t = NonZeroUsize::new(4).unwrap())]
    n: NonZeroUsize,

    /// Cash-out amount (atomic units).
    #[arg(long, default_value_t = 100_000)]
    amount: u64,

    /// Inject a failure: release with garbage σ at hop i.
    /// 0 means "the final intermediary releases bogus σ to U_{n-2}".
    #[arg(long, value_name = "HOP")]
    break_release_at_hop: Option<usize>,

    /// Inject a wormhole-collusion attempt: U_{i+1} and U_{i-1} collude to
    /// skip U_i. After releasing channel i honestly, the AMHL scalar is
    /// forwarded unchanged to channel i-1 (no y_i subtraction). Π_wr must
    /// reject — channel i-1 verification fails because (k_i)·G != K_{i-1}.
    /// Valid range: [1, n_routed_edges - 1] where n_routed_edges = n - 1.
    #[arg(long, value_name = "HOP")]
    wormhole_skip_at: Option<usize>,

    /// Seed for the AMHL secrets y_1..y_L (hex, 32 bytes).
    #[arg(long, value_parser = hex32, default_value = DEFAULT_Y_SEED)]
    y_seed: [u8; 32],

    /// Signer secret key x (final intermediary U_{n-1}).
    #[arg(long, value_parser = hex32, default_value = defaults::X)]
    x: [u8; 32],

    /// Signer per-signing nonce k.
    #[arg(long, value_parser = hex32, default_value = defaults::K)]
    k: [u8; 32],

    /// Payer blinding factor α.
    #[arg(long, value_parser = hex32, default_value = defaults::ALPHA)]
    alpha: [u8; 32],

    /// Payer blinding factor β.
    #[arg(long, value_parser = hex32, default_value = defaults::BETA)]
    beta: [u8; 32],

    /// Payee public key (SEC1 compressed, 33 bytes).
    #[arg(long, value_parser = hex33, default_value = DEFAULT_PAYEE_PK)]
    payee_pk: [u8; 33],
}

/// Per-edge state installed during Lock and consumed during Release.
/// `amount` would be checked here in a real PCN; the demo doesn't enforce
/// per-edge fee accounting so it isn't read after install.
#[derive(Clone, Debug)]
struct Lock {
    /// Hash-lock value r = SHA256(σ).
    r: [u8; 32],
    /// Π_wr commitment K_i = (y_0 + ... + y_i) · G for this routed edge.
    wr_commit: ProjectivePoint,
    sid: u64,
    listid: Vec<usize>,
    #[allow(dead_code)]
    amount: u64,
}

/// Stand-in PCN channel between U_i and U_{i+1}; the only piece of state
/// the simulator needs is whether a lock is currently installed.
#[derive(Default)]
struct Channel {
    locked: Option<Lock>,
}

impl Channel {
    fn install(&mut self, lock: Lock) {
        assert!(self.locked.is_none(), "channel already locked");
        self.locked = Some(lock);
    }

    /// Release the lock if all four conditions hold:
    ///   1. Hash-lock: SHA256(revealed) == r
    ///   2. Π_wr lock: (wr_release) · G == K_i (the AMHL commitment)
    ///   3. Routed-session sid binding
    ///   4. Routed-session listid binding (path-bound descriptor)
    /// Returns the reason on failure instead of panicking.
    fn release(
        &mut self,
        revealed: &[u8; 32],
        wr_release: &Scalar,
        expected_sid: u64,
        expected_listid: &[usize],
    ) -> Result<(), String> {
        let lock = self.locked.as_ref().ok_or("no lock to release")?;
        let h: [u8; 32] = Sha256::digest(revealed).into();
        if h != lock.r {
            return Err("hash lock failed: H(σ) != r".to_string());
        }
        let lhs = ProjectivePoint::GENERATOR * (*wr_release);
        if lhs.to_affine() != lock.wr_commit.to_affine() {
            return Err("Π_wr lock failed: k·G != K_i".to_string());
        }
        if lock.sid != expected_sid {
            return Err("Π_wr: sid mismatch".to_string());
        }
        if lock.listid != expected_listid {
            return Err("Π_wr: listid mismatch".to_string());
        }
        self.locked = None;
        Ok(())
    }
}

struct Network {
    /// channels[i] connects U_i and U_{i+1}.
    channels: Vec<Channel>,
}

impl Network {
    fn open(n_hops: usize) -> Self {
        Network { channels: (0..n_hops).map(|_| Channel::default()).collect() }
    }
}

/// Canonical state produced by the dPay setup phase. Bytes derived at use
/// sites — see Phase A simplify lessons.
struct Setup {
    cash_tx: CashoutTx,
    sigma: k256::Scalar,
    blind: PayerBlind,
    x_pt: ProjectivePoint,
    r_pt: ProjectivePoint,
    sid: u64,
    listid: Vec<usize>,
    /// AMHL secrets (one per routed edge). Length = n_routed_edges = n - 1.
    wr: WrSecrets,
}

fn build_setup(args: &Args) -> Setup {
    let secret = SignerSecret { x: scalar_from_bytes(args.x).expect("--x out of range") };
    let nonce = SignerNonce { k: scalar_from_bytes(args.k).expect("--k out of range") };
    let alpha = scalar_from_bytes(args.alpha).expect("--alpha out of range");
    let beta = scalar_from_bytes(args.beta).expect("--beta out of range");

    // Derive a deterministic 32-byte channel id from a session string so the
    // simulator doesn't carry a magic ASCII tag in a fixed-size buffer.
    let chan_id: [u8; 32] = Sha256::digest(b"dpay-channel-Un-1-Un").into();
    let cash_tx =
        CashoutTx { channel_id: chan_id, payee_pk: args.payee_pk, amount: args.amount, version: 1 };
    let m = cash_tx.sighash();

    let x_pt = blind_schnorr::pubkey(&secret);
    let r_pt = blind_schnorr::nonce_commit(&nonce);
    let blind = blind_schnorr::blind(r_pt, x_pt, &m, alpha, beta);
    let sigma = blind_schnorr::respond(&secret, &nonce, &blind.e);

    // Routed-session descriptor desc = (sid, listid, r). sid is arbitrary
    // per-session; listid is the route U_1..U_{n-1} (intermediaries on the
    // payer-side route, not including U_0 or U_n).
    let sid: u64 = 0xd0a4_5e55_1014_b00b;
    let listid: Vec<usize> = (1..args.n.get()).collect();

    // n_routed = n - 1 routed edges. Π_wr installs one commitment per.
    let n_routed = args.n.get() - 1;
    let wr = WrSecrets::from_seed(args.y_seed, n_routed);

    Setup { cash_tx, sigma, blind, x_pt, r_pt, sid, listid, wr }
}

fn print_setup_phase(s: &Setup, n_hops: usize) {
    println!("=== setup ===");
    println!("payment path     : U_0 -> U_1 -> ... -> U_{n_hops} (payee)");
    println!("amount           : {} units", s.cash_tx.amount);
    println!("tx_co.sighash    = {}", hex::encode(s.cash_tx.sighash()));
    println!("X (signer pk)    = {}", hex::encode(point_to_compressed(&s.x_pt)));
    println!("R (signer nonce) = {}", hex::encode(point_to_compressed(&s.r_pt)));
    println!("R'(blinded nonce)= {}", hex::encode(point_to_compressed(&s.blind.r_prime)));
    println!("e  (sent to U_{})= {}", n_hops - 1, hex::encode(scalar_to_bytes(&s.blind.e)));
    println!(
        "σ  (signer hides)= {}  [held by U_{} until release]",
        hex::encode(scalar_to_bytes(&s.sigma)),
        n_hops - 1
    );
    println!(
        "r = SHA256(σ)    = {}  [routed-lock value]",
        hex::encode(blind_schnorr::lock_value(&s.sigma))
    );
    println!("desc.sid         = {:#x}", s.sid);
    println!("desc.listid      = {:?}", s.listid);
    println!("Π_wr secrets     : {} y_i scalars (one per routed edge)", s.wr.n_edges());
    for i in 0..s.wr.n_edges() {
        let k_i = point_compressed_short(&s.wr.lock_at(i));
        println!("  K_{i} = (Σ y_0..y_{i})·G = {k_i}");
    }
}

fn point_compressed_short(p: &ProjectivePoint) -> String {
    let ep = p.to_affine().to_encoded_point(true);
    let bytes = ep.as_bytes();
    let hex = hex::encode(bytes);
    format!("{}…{}", &hex[..8], &hex[hex.len() - 8..])
}

fn build_stdin(s: &Setup) -> sp1_sdk::SP1Stdin {
    build_zkpok_stdin(&s.sigma, &s.x_pt, &s.r_pt, &s.blind.e)
}

fn cross_check(public: &Public, s: &Setup) {
    assert_public_matches_transcript(public, &s.sigma, &s.x_pt, &s.r_pt, &s.blind.e);
}

fn run_setup_zkpok_execute<P: Prover>(client: &P, s: &Setup) {
    println!("=== setup ZKPoK (--execute, no proof) ===");
    let (output, report) = client.execute(ELF, build_stdin(s)).run().unwrap();
    let public = Public::parse(output.as_slice()).expect("malformed public outputs");
    cross_check(&public, s);
    println!(
        "guest executed; cycles = {}; public values match",
        report.total_instruction_count()
    );
}

fn run_setup_zkpok_prove<P: Prover>(client: &P, s: &Setup) {
    println!("=== setup ZKPoK (--prove) ===");
    let t0 = Instant::now();
    let pk: P::ProvingKey = client.setup(ELF).expect("failed to setup ELF");
    let setup_ms = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let proof = client.prove(&pk, build_stdin(s)).run().expect("failed to generate core proof");
    let prove_ms = t1.elapsed().as_millis();

    let t2 = Instant::now();
    client.verify(&proof, pk.verifying_key(), None).expect("proof failed to verify");
    let verify_ms = t2.elapsed().as_millis();

    let public = Public::parse(proof.public_values.as_slice()).expect("malformed public outputs");
    cross_check(&public, s);
    println!(
        "STARK proof generated and verified; setup={setup_ms}ms prove={prove_ms}ms \
         verify={verify_ms}ms"
    );
}

fn run_lock_phase(net: &mut Network, s: &Setup) {
    println!("=== lock (forward) ===");
    let r = blind_schnorr::lock_value(&s.sigma);
    let n_routed = s.wr.n_edges();
    for i in 0..n_routed {
        let lock = Lock {
            r,
            wr_commit: s.wr.lock_at(i),
            sid: s.sid,
            listid: s.listid.clone(),
            amount: s.cash_tx.amount,
        };
        net.channels[i].install(lock);
        println!("  U_{i} -> U_{} : routed lock installed (r, K_{i})", i + 1);
    }
    let last = n_routed;
    println!("  U_{last} -> U_{} : cash-out edge (no routed lock)", last + 1);
}

fn run_release_phase(
    net: &mut Network,
    s: &Setup,
    break_at_hop: Option<usize>,
    wormhole_skip_at: Option<usize>,
) -> Result<(), String> {
    println!("=== release (backward) ===");
    let n_routed = s.wr.n_edges();
    // U_{n-1} kicks the cascade off with σ + the bootstrap AMHL release seed.
    let mut sigma_bytes = scalar_to_bytes(&s.sigma);
    let mut wr_release = s.wr.final_release();

    for i in (0..n_routed).rev() {
        // Failure injection #1: garbage σ revealed at this hop.
        let sigma_to_send = if Some(i) == break_at_hop {
            println!("  [INJECT FAILURE] hop {i} revealing garbage instead of σ");
            let mut g = sigma_bytes;
            g[0] ^= 0xff;
            g
        } else {
            sigma_bytes
        };

        match net.channels[i].release(&sigma_to_send, &wr_release, s.sid, &s.listid) {
            Ok(()) => {
                println!(
                    "  U_{} -> U_{i} : release OK; hash lock + Π_wr both verified",
                    i + 1
                );
                sigma_bytes = sigma_to_send;
            }
            Err(reason) => return Err(format!("U_{i} aborts at hop {i}: {reason}")),
        }

        // Step the AMHL release for the next iteration. Only U_i (i ≥ 1) does
        // this; U_0 is the payer and the loop terminates after their release.
        if i == 0 {
            break;
        }
        if Some(i) == wormhole_skip_at {
            println!(
                "  [WORMHOLE] U_{} and U_{} collude to skip U_{i};",
                i + 1,
                i - 1
            );
            println!(
                "             k_{i} forwarded unchanged; U_{} cannot derive k_{}.",
                i - 1,
                i - 1
            );
            // wr_release stays unchanged — channel i-1 will reject it.
        } else {
            wr_release = wormhole::step(wr_release, s.wr.y(i));
        }
    }
    Ok(())
}

fn run_cash_phase(s: &Setup) {
    println!("=== cash ===");
    let s_prime = blind_schnorr::unblind(&s.sigma, &s.blind);
    let ok = blind_schnorr::verify_final(&s.blind.r_prime, &s_prime, &s.blind.e_prime, &s.x_pt);
    assert!(ok, "unblind produced an invalid signature — protocol bug");

    let final_sig_r = point_to_compressed(&s.blind.r_prime);
    let final_sig_s = scalar_to_bytes(&s_prime);
    println!("  payer unblinds: s' = σ + α");
    println!("  cash-out signature (R', s'):");
    println!("    R' = {}", hex::encode(final_sig_r));
    println!("    s' = {}", hex::encode(final_sig_s));
    println!("  verifying (R', s') against (X, e') over m = tx_co.sighash() ... OK");

    println!("  payer sends A_{{0,n}} to payee via anonymous endpoint channel");
    println!(
        "  payee redeems tx_co from U_{} for {} units (channel_id={})",
        s.listid.last().map(|i| *i + 1).unwrap_or(1),
        s.cash_tx.amount,
        hex::encode(&s.cash_tx.channel_id[..16]) // first half for brevity
    );
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    let n_hops = args.n.get();
    let n_routed = n_hops.saturating_sub(1);
    if let Some(h) = args.break_release_at_hop {
        if h >= n_routed {
            eprintln!(
                "error: --break-release-at-hop must be < n-1 (number of routed edges = {n_routed})"
            );
            std::process::exit(2);
        }
    }
    if let Some(h) = args.wormhole_skip_at {
        if !(1..n_routed).contains(&h) {
            eprintln!(
                "error: --wormhole-skip-at must be in [1, n-2]; with n={n_hops} that's [1, {}]",
                n_routed.saturating_sub(1)
            );
            std::process::exit(2);
        }
    }

    let total_t0 = Instant::now();

    let (setup, d_setup) = timed(|| build_setup(&args));
    print_setup_phase(&setup, n_hops);

    let (client, d_prover_init) = timed(ProverClient::from_env);

    let (_, d_zkpok) = timed(|| {
        if args.execute {
            run_setup_zkpok_execute(&client, &setup);
        } else {
            run_setup_zkpok_prove(&client, &setup);
        }
    });

    let mut net = Network::open(n_hops);
    let (_, d_lock) = timed(|| run_lock_phase(&mut net, &setup));
    let (release_result, d_release) = timed(|| {
        run_release_phase(&mut net, &setup, args.break_release_at_hop, args.wormhole_skip_at)
    });

    let d_cash = match release_result {
        Ok(()) => {
            let (_, d) = timed(|| run_cash_phase(&setup));
            println!("=== done: payment completed ===");
            Some(d)
        }
        Err(reason) => {
            println!("=== release aborted: {reason} ===");
            println!("=== payment did NOT complete; locks remain installed upstream ===");
            None
        }
    };

    let total_ms = total_t0.elapsed().as_millis();

    let zkpok_label = if args.execute { "zkpok (execute)" } else { "zkpok (prove)" };
    println!();
    println!("=== timings ===");
    println!("{:<17}: {} µs", "build_setup", d_setup.as_micros());
    println!("{:<17}: {} ms", "prover init", d_prover_init.as_millis());
    println!("{:<17}: {} ms", zkpok_label, d_zkpok.as_millis());
    println!("{:<17}: {} µs", "lock phase", d_lock.as_micros());
    println!("{:<17}: {} µs", "release phase", d_release.as_micros());
    match d_cash {
        Some(d) => println!("{:<17}: {} µs", "cash phase", d.as_micros()),
        None => println!("{:<17}: skipped (release aborted)", "cash phase"),
    }
    println!("{:<17}: {} ms", "total wall clock", total_ms);

    if d_cash.is_none() {
        std::process::exit(3);
    }
}
