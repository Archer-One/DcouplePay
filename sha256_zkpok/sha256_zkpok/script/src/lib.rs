//! Host-side support library for the dPay-style blind-Schnorr ZKPoK demo.
//!
//! Exposes the cryptographic primitives needed to drive the protocol around
//! the SP1 proof. The SP1 guest only checks the relation
//! `r = SHA256(σ) ∧ σ·G = R + e·X`; the rest of the blind-signing
//! workflow (keygen, nonce commit, blinding, unblinding, final-signature
//! verification) lives in this library so that it can be unit-tested and
//! re-used by the binaries.

pub mod blind_schnorr;
pub mod cashout;
pub mod wormhole;

use crate::blind_schnorr::{lock_value, point_to_compressed, scalar_to_bytes};
use k256::{ProjectivePoint, Scalar};
use sp1_sdk::SP1Stdin;
use std::time::{Duration, Instant};

/// Run `f` and return its result alongside the wall-clock duration.
/// Tiny helper to keep timing call-sites readable when we have many of
/// them in the same function.
pub fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let t0 = Instant::now();
    let v = f();
    (v, t0.elapsed())
}

/// Deterministic test scalars used by the demo binaries when the user does
/// not override them on the CLI. Centralized so the two binaries cannot
/// drift.
pub mod defaults {
    pub const X: &str = "0000000000000000000000000000000000000000000000000000000000000042";
    pub const K: &str = "0000000000000000000000000000000000000000000000000000000000000007";
    pub const ALPHA: &str = "0000000000000000000000000000000000000000000000000000000000000011";
    pub const BETA: &str = "0000000000000000000000000000000000000000000000000000000000000022";
}

/// 130-byte public-output payload committed by the guest, in commit order.
/// The guest's `commit_slice(&output)` and `Public::parse` are duals;
/// changing one must change the other.
pub struct Public {
    pub r: [u8; 32],
    pub x_compressed: [u8; 33],
    pub r_commit_compressed: [u8; 33],
    pub e: [u8; 32],
}

impl Public {
    pub const LEN: usize = 32 + 33 + 33 + 32;

    pub fn parse(pv: &[u8]) -> Result<Self, String> {
        if pv.len() != Self::LEN {
            return Err(format!("expected {} public bytes, got {}", Self::LEN, pv.len()));
        }
        let (r, rest) = pv.split_at(32);
        let (x, rest) = rest.split_at(33);
        let (rc, e) = rest.split_at(33);
        Ok(Public {
            r: r.try_into().unwrap(),
            x_compressed: x.try_into().unwrap(),
            r_commit_compressed: rc.try_into().unwrap(),
            e: e.try_into().unwrap(),
        })
    }
}

/// Build the SP1Stdin for the dPay setup-phase ZKPoK guest. The write order
/// here must match the guest's read_vec order: σ, X, R, e. Centralized so
/// guest/host stay in lockstep.
pub fn build_zkpok_stdin(
    sigma: &Scalar,
    x_pt: &ProjectivePoint,
    r_pt: &ProjectivePoint,
    e: &Scalar,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(scalar_to_bytes(sigma).to_vec());
    stdin.write_vec(point_to_compressed(x_pt).to_vec());
    stdin.write_vec(point_to_compressed(r_pt).to_vec());
    stdin.write_vec(scalar_to_bytes(e).to_vec());
    stdin
}

/// Recompute expected public values from canonical state and assert that
/// the guest's commitment matches. Both demo binaries call this on
/// `--execute` and `--prove` paths so a transcript drift surfaces here.
pub fn assert_public_matches_transcript(
    public: &Public,
    sigma: &Scalar,
    x_pt: &ProjectivePoint,
    r_pt: &ProjectivePoint,
    e: &Scalar,
) {
    assert_eq!(public.r, lock_value(sigma), "guest-committed r != host SHA256(σ)");
    assert_eq!(public.x_compressed, point_to_compressed(x_pt), "X mismatch");
    assert_eq!(public.r_commit_compressed, point_to_compressed(r_pt), "R mismatch");
    assert_eq!(public.e, scalar_to_bytes(e), "e mismatch");
}
