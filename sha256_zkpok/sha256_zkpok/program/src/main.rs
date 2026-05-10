//! dPay-style ZKPoK guest.
//!
//! Statement (signer-side ZKPoK from the dPay setup phase):
//!
//!     { σ : r = SHA256(σ)  ∧  σ·G = R + e·X }
//!
//! All of (X, R, e) are public inputs — the blind-signing transcript that
//! the payer and signer agreed on. σ is the only private witness; it is
//! the signer's response that will be revealed during routed release.
//!
//! Public outputs (committed in order, total 130 bytes):
//!     r              [u8; 32]   SHA256(σ); the routed-lock value
//!     X compressed   [u8; 33]   signer pubkey, SEC1
//!     R compressed   [u8; 33]   signer nonce commit, SEC1
//!     e              [u8; 32]   blinded challenge, big-endian scalar mod n

#![no_main]
sp1_zkvm::entrypoint!(main);

use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

pub fn main() {
    // serde's Deserialize for [u8; N] only covers N ≤ 32, so we use read_vec
    // and convert. write order on the host: σ, X, R, e.
    let sigma_bytes: [u8; 32] = sp1_zkvm::io::read_vec().try_into().expect("σ must be 32 bytes");
    let x_compressed: [u8; 33] =
        sp1_zkvm::io::read_vec().try_into().expect("X must be 33 bytes (compressed SEC1)");
    let r_compressed: [u8; 33] =
        sp1_zkvm::io::read_vec().try_into().expect("R must be 33 bytes (compressed SEC1)");
    let e_bytes: [u8; 32] = sp1_zkvm::io::read_vec().try_into().expect("e must be 32 bytes");

    // r = SHA256(σ).
    let r: [u8; 32] = Sha256::digest(sigma_bytes).into();

    // Decode scalars; reject anything outside [0, n).
    let sigma: Scalar =
        Option::from(Scalar::from_repr(sigma_bytes.into())).expect("σ out of range mod n");
    assert!(!bool::from(sigma.is_zero()), "σ must be nonzero");
    let e: Scalar =
        Option::from(Scalar::from_repr(e_bytes.into())).expect("e out of range mod n");

    // Decode SEC1-compressed input points.
    let x_ep = EncodedPoint::from_bytes(x_compressed).expect("bad X encoding");
    let x_aff: AffinePoint =
        Option::from(AffinePoint::from_encoded_point(&x_ep)).expect("X is not on curve");
    let r_ep = EncodedPoint::from_bytes(r_compressed).expect("bad R encoding");
    let r_aff: AffinePoint =
        Option::from(AffinePoint::from_encoded_point(&r_ep)).expect("R is not on curve");
    let x_point = ProjectivePoint::from(x_aff);
    let r_point = ProjectivePoint::from(r_aff);

    // ValidResp(σ, tr): σ·G == R + e·X. SP1's secp256k1 precompile returns
    // points already in affine form, so equality on affine is the precompile-
    // friendly check; switching to projective subtract + is_identity actually
    // *increased* cycle count under this stack.
    let lhs = ProjectivePoint::generator() * sigma;
    let rhs = r_point + x_point * e;
    assert_eq!(lhs.to_affine(), rhs.to_affine(), "ValidResp failed: σ·G != R + e·X");

    // One ecall: r || X || R || e = 130 bytes.
    let mut output = [0u8; 130];
    output[0..32].copy_from_slice(&r);
    output[32..65].copy_from_slice(&x_compressed);
    output[65..98].copy_from_slice(&r_compressed);
    output[98..130].copy_from_slice(&e_bytes);
    sp1_zkvm::io::commit_slice(&output);
}
