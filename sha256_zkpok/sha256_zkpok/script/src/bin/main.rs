//! Host driver for the dPay blind-Schnorr ZKPoK demo.
//!
//! Walks through the full flow that lives off-chain in the dPay payment
//! protocol's setup phase:
//!
//!   1. Signer (final intermediary U_{n-1}) holds keypair (x, X = x·G).
//!   2. Signer generates per-signing nonce (k, R = k·G); R is sent to payer.
//!   3. Payer receives the cash-out message m and computes blinded challenge
//!         e = H(R' || X || m) + β  mod n
//!         R' = R + α·G + β·X
//!      and sends e to the signer.
//!   4. Signer responds with σ = k + e·x mod n and produces an SP1 proof of
//!         { σ : r = SHA256(σ)  ∧  σ·G = R + e·X }
//!      where r becomes the routed-lock value and (X, R, e) is the public
//!      transcript.
//!   5. Payer verifies the SP1 proof, accepts r as the routed-lock value.
//!   6. (Routed lock + release happen across U_0..U_{n-1} on a real PCN —
//!      simulated here by the signer simply revealing σ.)
//!   7. Payer unblinds: s' = σ + α mod n.
//!   8. Payer verifies the unblinded final signature: s'·G == R' + e'·X.

use clap::{ArgGroup, Parser, ValueEnum};
use hex::FromHex;
use k256::ProjectivePoint;
use sha256_zkpok_script::blind_schnorr::{
    self, point_to_compressed, scalar_from_bytes, scalar_to_bytes, PayerBlind, SignerNonce,
    SignerSecret,
};
use sha256_zkpok_script::{
    assert_public_matches_transcript, build_zkpok_stdin, defaults, timed, Public,
};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1ProofWithPublicValues, SP1PublicValues,
};

const ELF: Elf = include_elf!("sha256-zkpok-program");
const SHA256_BINDING_ELF: Elf = include_elf!("sha256_binding");

fn hex32(s: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::from_hex(s.trim_start_matches("0x")).map_err(|e| e.to_string())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(group(ArgGroup::new("mode").required(true).args(["execute", "prove"])))]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// After verifying the SP1 proof, flip a public output byte and re-verify.
    /// The second verify is expected to FAIL. Only valid with --prove.
    #[arg(long)]
    tamper: bool,

    /// Cash-out message m to be (blind-)signed, hex.
    #[arg(long, default_value = "dpay-cash-out-message-placeholder")]
    m: String,

    /// Signer secret key x (hex, 32 bytes).
    #[arg(long, value_parser = hex32, default_value = defaults::X)]
    x: [u8; 32],

    /// Signer per-signing nonce k (hex, 32 bytes).
    #[arg(long, value_parser = hex32, default_value = defaults::K)]
    k: [u8; 32],

    /// Payer blinding factor α (hex, 32 bytes).
    #[arg(long, value_parser = hex32, default_value = defaults::ALPHA)]
    alpha: [u8; 32],

    /// Payer blinding factor β (hex, 32 bytes).
    #[arg(long, value_parser = hex32, default_value = defaults::BETA)]
    beta: [u8; 32],

    /// ZKP relation to prove. `validresp` is the richer blind-response
    /// relation; `sha256` proves only r = SHA256(response).
    #[arg(long, value_enum, default_value_t = Relation::Validresp)]
    relation: Relation,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Relation {
    Validresp,
    Sha256,
}

/// Canonical state produced by the blind-signing protocol; everything the
/// host needs to drive setup, prove, and cash-out flows downstream.
struct Transcript {
    x_pt: ProjectivePoint,
    r_pt: ProjectivePoint,
    blind: PayerBlind,
    sigma: k256::Scalar,
    m: Vec<u8>,
}

fn build_transcript(args: &Args) -> Transcript {
    let secret = SignerSecret { x: scalar_from_bytes(args.x).expect("--x out of range") };
    let nonce = SignerNonce { k: scalar_from_bytes(args.k).expect("--k out of range") };
    let alpha = scalar_from_bytes(args.alpha).expect("--alpha out of range");
    let beta = scalar_from_bytes(args.beta).expect("--beta out of range");

    // Accept m as either a plain UTF-8 string or 0x-prefixed hex.
    let m: Vec<u8> = if let Some(rest) = args.m.strip_prefix("0x") {
        hex::decode(rest).expect("--m: invalid hex after 0x prefix")
    } else {
        args.m.as_bytes().to_vec()
    };

    let x_pt = blind_schnorr::pubkey(&secret);
    let r_pt = blind_schnorr::nonce_commit(&nonce);

    let blind = blind_schnorr::blind(r_pt, x_pt, &m, alpha, beta);
    let sigma = blind_schnorr::respond(&secret, &nonce, &blind.e);

    Transcript { x_pt, r_pt, blind, sigma, m }
}

fn print_setup(t: &Transcript) {
    println!("--- setup ---");
    println!("m                = {}", hex::encode(&t.m));
    println!("X (signer pk)    = {}", hex::encode(point_to_compressed(&t.x_pt)));
    println!("R (signer nonce) = {}", hex::encode(point_to_compressed(&t.r_pt)));
    println!("R'(blinded nonce)= {}", hex::encode(point_to_compressed(&t.blind.r_prime)));
    println!("e (blinded chal) = {}", hex::encode(scalar_to_bytes(&t.blind.e)));
    println!("e'(unblinded)    = {}", hex::encode(scalar_to_bytes(&t.blind.e_prime)));
    println!(
        "σ (signer resp)  = {}  [private during setup]",
        hex::encode(scalar_to_bytes(&t.sigma))
    );
    println!(
        "r = SHA256(σ)    = {}  [routed-lock value]",
        hex::encode(blind_schnorr::lock_value(&t.sigma))
    );
}

fn build_stdin(t: &Transcript) -> sp1_sdk::SP1Stdin {
    build_zkpok_stdin(&t.sigma, &t.x_pt, &t.r_pt, &t.blind.e)
}

fn build_sha256_stdin(t: &Transcript) -> sp1_sdk::SP1Stdin {
    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write_vec(scalar_to_bytes(&t.sigma).to_vec());
    stdin
}

fn cross_check_public(public: &Public, t: &Transcript) {
    assert_public_matches_transcript(public, &t.sigma, &t.x_pt, &t.r_pt, &t.blind.e);
}

fn cross_check_sha256_public(output: &[u8], t: &Transcript) {
    assert_eq!(output, blind_schnorr::lock_value(&t.sigma), "guest-committed r != host SHA256(σ)");
}

fn run_routed_release_and_cashout(t: &Transcript) {
    println!("--- routed release (simulated) ---");
    println!("signer reveals σ = {}", hex::encode(scalar_to_bytes(&t.sigma)));

    let s_prime = blind_schnorr::unblind(&t.sigma, &t.blind);
    let ok = blind_schnorr::verify_final(&t.blind.r_prime, &s_prime, &t.blind.e_prime, &t.x_pt);

    println!("--- payer unblinds + verifies cash-out signature ---");
    println!("s' = σ + α       = {}", hex::encode(scalar_to_bytes(&s_prime)));
    println!("Final sig (R',s') verifies under (X, e'): {}", if ok { "OK" } else { "FAIL" });
    assert!(ok, "unblinded signature failed final verification");
}

fn run_execute<P: Prover>(client: &P, t: &Transcript, relation: Relation) {
    let elf = if relation == Relation::Sha256 { SHA256_BINDING_ELF } else { ELF };
    let stdin = if relation == Relation::Sha256 { build_sha256_stdin(t) } else { build_stdin(t) };
    let (output, report) = client.execute(elf, stdin).run().unwrap();
    println!("--- guest executed (no proof) ---");
    if relation == Relation::Sha256 {
        cross_check_sha256_public(output.as_slice(), t);
    } else {
        let public = Public::parse(output.as_slice()).expect("malformed public outputs");
        cross_check_public(&public, t);
    }
    println!("Public values match expected transcript.");
    println!("cycles           = {}", report.total_instruction_count());
    run_routed_release_and_cashout(t);
}

fn run_prove<P: Prover>(client: &P, t: &Transcript, tamper: bool, relation: Relation) {
    let elf = if relation == Relation::Sha256 { SHA256_BINDING_ELF } else { ELF };
    let stdin = if relation == Relation::Sha256 { build_sha256_stdin(t) } else { build_stdin(t) };
    let (pk, d_setup) = timed(|| client.setup(elf).expect("failed to setup ELF"));
    let (proof, d_prove) =
        timed(|| client.prove(&pk, stdin).run().expect("failed to generate core proof"));
    println!("--- SP1 proof of ZKPoK generated ---");
    let proof_path = std::env::temp_dir().join("sha256_zkpok_sp1_proof.bin");
    proof.save(&proof_path).expect("failed to serialize proof for sizing");
    let proof_size = std::fs::metadata(&proof_path).expect("failed to stat serialized proof").len();
    println!("proof size bytes : {}", proof_size);

    let (_, d_verify) = timed(|| {
        client.verify(&proof, pk.verifying_key(), None).expect("proof failed to verify")
    });
    println!("SP1 proof verified.");

    if relation == Relation::Sha256 {
        cross_check_sha256_public(proof.public_values.as_slice(), t);
    } else {
        let public = Public::parse(proof.public_values.as_slice()).expect("malformed public outputs");
        cross_check_public(&public, t);
    }
    println!("Public values match expected transcript.");

    if tamper {
        run_tamper_check(client, &pk, &proof);
    }

    run_routed_release_and_cashout(t);

    println!();
    println!("=== timings ===");
    println!("{:<17}: {} ms", "setup", d_setup.as_millis());
    println!("{:<17}: {} ms", "prove (STARK)", d_prove.as_millis());
    println!("{:<17}: {} ms", "verify (SP1)", d_verify.as_millis());
}

fn run_tamper_check<P: Prover>(
    client: &P,
    pk: &P::ProvingKey,
    proof: &SP1ProofWithPublicValues,
) {
    let mut tampered = proof.clone();
    let mut buf = tampered.public_values.to_vec();
    let original = buf[0];
    buf[0] ^= 0x01;
    tampered.public_values = SP1PublicValues::from(&buf);
    println!("--- tamper test --- r[0] {:02x} -> {:02x}", original, buf[0]);
    match client.verify(&tampered, pk.verifying_key(), None) {
        Ok(()) => {
            eprintln!("SOUNDNESS BUG: tampered proof verified OK");
            std::process::exit(1);
        }
        Err(e) => println!("Tampered proof correctly rejected: {e}"),
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    if args.tamper && !args.prove {
        eprintln!("error: --tamper is only valid with --prove");
        std::process::exit(2);
    }

    let transcript = build_transcript(&args);
    print_setup(&transcript);

    let client = ProverClient::from_env();
    if args.execute {
        run_execute(&client, &transcript, args.relation);
    } else {
        run_prove(&client, &transcript, args.tamper, args.relation);
    }
}
