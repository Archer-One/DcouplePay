//! Blind Schnorr signature over secp256k1.
//!
//! Standard variant used by the dPay-style construction:
//!
//! ```text
//! Signer keypair             (x, X = x·G)
//! Per-signing signer nonce   (k, R = k·G)            sent to payer
//! Per-signing payer blinding (α, β)                   payer-local
//!
//! Blinded nonce              R' = R + α·G + β·X       payer
//! Blinded challenge          e  = e' + β  (mod n)
//!     where e' = H(R' || X || m)  (mod n)
//! Signer response            σ  = k + e·x  (mod n)    sent at release
//! Unblinded response         s' = σ + α   (mod n)
//!
//! Final signature  (R', s')  verifies as  s'·G == R' + e'·X.
//! ```
//!
//! The hash `r = SHA256(σ)` is the routed-lock value used by the PCN; SP1
//! proves both `r = SHA256(σ)` and the validity of σ as a Schnorr response
//! against the public transcript `(X, R, e)`.

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct SignerSecret {
    pub x: Scalar,
}

#[derive(Clone, Debug)]
pub struct SignerNonce {
    pub k: Scalar,
}

/// Payer-side blinding state stored from the request until cash-out.
/// Only the data the unblind / final-verify path consumes is retained;
/// β is folded into `e` at blind time and not kept.
#[derive(Clone, Debug)]
pub struct PayerBlind {
    alpha: Scalar,
    /// Blinded nonce point R' that the final signature commits to.
    pub r_prime: ProjectivePoint,
    /// Unblinded challenge e' = H(R' || X || m) mod n.
    pub e_prime: Scalar,
    /// Blinded challenge e = e' + β mod n that the signer sees.
    pub e: Scalar,
}

pub fn pubkey(sec: &SignerSecret) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * sec.x
}

pub fn nonce_commit(nonce: &SignerNonce) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * nonce.k
}

/// Payer step: blind the per-signing nonce R against pubkey X for message m.
/// Returns the blinded challenge `e` to send to the signer plus the local
/// state needed to unblind later.
pub fn blind(
    r_point: ProjectivePoint,
    x_point: ProjectivePoint,
    m: &[u8],
    alpha: Scalar,
    beta: Scalar,
) -> PayerBlind {
    let r_prime = r_point + ProjectivePoint::GENERATOR * alpha + x_point * beta;
    let e_prime = challenge_hash(&r_prime, &x_point, m);
    let e = e_prime + beta;
    PayerBlind { alpha, r_prime, e_prime, e }
}

/// Signer step: produce the response σ = k + e·x mod n on the blinded
/// challenge e supplied by the payer.
pub fn respond(secret: &SignerSecret, nonce: &SignerNonce, e: &Scalar) -> Scalar {
    nonce.k + (*e) * secret.x
}

/// Routed-lock value committed during setup.
pub fn lock_value(sigma: &Scalar) -> [u8; 32] {
    let bytes: [u8; 32] = sigma.to_repr().into();
    Sha256::digest(bytes).into()
}

/// Payer step: unblind the response σ into a final-signature scalar s'.
pub fn unblind(sigma: &Scalar, blind: &PayerBlind) -> Scalar {
    *sigma + blind.alpha
}

/// Verify a final unblinded Schnorr signature.
pub fn verify_final(
    r_prime: &ProjectivePoint,
    s_prime: &Scalar,
    e_prime: &Scalar,
    x_point: &ProjectivePoint,
) -> bool {
    let lhs = ProjectivePoint::GENERATOR * (*s_prime);
    let rhs = *r_prime + (*x_point) * (*e_prime);
    lhs.to_affine() == rhs.to_affine()
}

/// e' = H(R'_compressed || X_compressed || m) mod n.
pub fn challenge_hash(r_prime: &ProjectivePoint, x_point: &ProjectivePoint, m: &[u8]) -> Scalar {
    let mut h = Sha256::new();
    h.update(r_prime.to_affine().to_encoded_point(true).as_bytes());
    h.update(x_point.to_affine().to_encoded_point(true).as_bytes());
    h.update(m);
    hash_to_scalar(h)
}

/// Finalize a SHA-256 hash and reduce its 256-bit output mod n into a
/// scalar. Used by both `challenge_hash` and the wormhole secret
/// derivation to keep the digest→scalar conversion in one place.
pub fn hash_to_scalar(h: Sha256) -> Scalar {
    let digest: [u8; 32] = h.finalize().into();
    let fb: FieldBytes = digest.into();
    <Scalar as Reduce<U256>>::reduce_bytes(&fb)
}

/// Convert a 32-byte big-endian scalar repr into a Scalar, rejecting
/// values >= n.
pub fn scalar_from_bytes(bytes: [u8; 32]) -> Result<Scalar, String> {
    Option::from(Scalar::from_repr(bytes.into()))
        .ok_or_else(|| "scalar out of range mod n".to_string())
}

pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_repr().into()
}

/// Decode a SEC1-compressed (33-byte) secp256k1 point.
pub fn point_from_compressed(bytes: &[u8; 33]) -> Result<ProjectivePoint, String> {
    let ep = EncodedPoint::from_bytes(bytes).map_err(|e| format!("bad point: {e}"))?;
    let aff: AffinePoint =
        Option::from(AffinePoint::from_encoded_point(&ep)).ok_or("point off curve")?;
    Ok(ProjectivePoint::from(aff))
}

/// SEC1 compressed (33 bytes) encoding of a projective point.
pub fn point_to_compressed(p: &ProjectivePoint) -> [u8; 33] {
    let ep = p.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(ep.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s_from_u64(v: u64) -> Scalar {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&v.to_be_bytes());
        scalar_from_bytes(b).unwrap()
    }

    #[test]
    fn full_blind_protocol_round_trips() {
        let secret = SignerSecret { x: s_from_u64(0xdeadbeef) };
        let nonce = SignerNonce { k: s_from_u64(0xcafe) };
        let alpha = s_from_u64(0x1111);
        let beta = s_from_u64(0x2222);
        let m = b"cash-out tx digest placeholder";

        let x_pt = pubkey(&secret);
        let r_pt = nonce_commit(&nonce);

        let pb = blind(r_pt, x_pt, m, alpha, beta);
        let sigma = respond(&secret, &nonce, &pb.e);

        // ValidResp: σ·G = R + e·X
        let lhs = ProjectivePoint::GENERATOR * sigma;
        let rhs = r_pt + x_pt * pb.e;
        assert_eq!(lhs.to_affine(), rhs.to_affine(), "ValidResp");

        let s_prime = unblind(&sigma, &pb);
        assert!(
            verify_final(&pb.r_prime, &s_prime, &pb.e_prime, &x_pt),
            "final unblinded signature should verify"
        );
    }

    #[test]
    fn point_round_trip_compressed() {
        let secret = SignerSecret { x: s_from_u64(0xabcd) };
        let pt = pubkey(&secret);
        let c = point_to_compressed(&pt);
        assert_eq!(c.len(), 33);
        assert_eq!(point_from_compressed(&c).unwrap().to_affine(), pt.to_affine());
    }
}
