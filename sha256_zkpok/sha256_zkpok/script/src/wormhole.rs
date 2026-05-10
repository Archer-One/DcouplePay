//! Wormhole-resistant lock mechanism Π_wr (AMHL-style).
//!
//! Anonymous Multi-Hop Locks (Malavolta et al., NDSS 2019) attached to
//! each routed edge so that one edge's release evidence cannot be
//! repurposed against another. Composes with dPay's hash-locked
//! routed payment: each lock is `(K_i, r, listid, sid)`, and release
//! requires both σ (the SHA-256 preimage of r) and the matching AMHL
//! scalar k_i with k_i · G = K_i.
//!
//! Indexing in this module is 0-based throughout — `ys[i]` and the
//! lock at channel `i` correspond to the i-th routed edge (the
//! (U_i, U_{i+1}) lock), for i ∈ [0, L-1] where L = number of routed
//! edges.
//!
//! Construction:
//!
//! ```text
//! payer picks y_0, y_1, ..., y_{L-1}
//! k_i = y_0 + y_1 + ... + y_i        (mod n)
//! K_i = k_i · G                       (lock at channel i)
//! final release seed = k_{L-1}        (held by U_L = U_{n-1}, the
//!                                      final intermediary, to
//!                                      bootstrap the backward cascade)
//! ```
//!
//! Per-intermediary step secret:
//! U_i (for i ∈ [1, L-1]) holds y_i. After receiving k_i from U_{i+1},
//! U_i computes k_{i-1} = k_i - y_i and forwards it to U_{i-1}.
//! U_0 (the payer) verifies k_0 · G == K_0 and the cascade ends.
//!
//! Wormhole defense:
//! If U_j is bypassed by a colluding pair (U_{j+1} ↔ U_{j-1}),
//! U_{j-1} receives k_j (the wrong scalar — it should have been k_{j-1}).
//! Their incoming lock has commitment K_{j-1}, so verifying
//! k_j · G == K_{j-1} fails (off by y_j · G that nobody can subtract).

use crate::blind_schnorr::hash_to_scalar;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// Payer-side AMHL state. The payer holds all `ys` and distributes them:
/// each intermediary U_i (i ∈ [1, L-1]) gets `ys[i]` as their step secret;
/// the final intermediary U_L also receives the bootstrap release seed
/// returned by `final_release`.
#[derive(Clone, Debug)]
pub struct WrSecrets {
    ys: Vec<Scalar>,
}

impl WrSecrets {
    /// Derive `n_routed_edges` independent scalars deterministically from a
    /// seed. Uses domain-separated SHA-256 reduced mod n. A real prover
    /// would draw these from a CSPRNG; the seed is hashed (not used as a
    /// scalar directly) so any 32-byte input is valid.
    pub fn from_seed(seed: [u8; 32], n_routed_edges: usize) -> Self {
        let ys = (0..n_routed_edges)
            .map(|i| {
                let mut h = Sha256::new();
                h.update(b"dpay-amhl-y-v1");
                h.update(seed);
                h.update((i as u32).to_be_bytes());
                hash_to_scalar(h)
            })
            .collect();
        WrSecrets { ys }
    }

    /// Cumulative scalar k_i = ys[0] + ys[1] + ... + ys[i].
    pub fn cumulative(&self, channel_idx: usize) -> Scalar {
        self.ys[..=channel_idx].iter().copied().sum()
    }

    /// Lock commitment at channel i: K_i = k_i · G.
    pub fn lock_at(&self, channel_idx: usize) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * self.cumulative(channel_idx)
    }

    /// Bootstrap release seed for the final intermediary; equals k_{L-1}.
    pub fn final_release(&self) -> Scalar {
        self.cumulative(self.ys.len() - 1)
    }

    /// Step secret y_i, given to U_i during setup.
    pub fn y(&self, channel_idx: usize) -> Scalar {
        self.ys[channel_idx]
    }

    pub fn n_edges(&self) -> usize {
        self.ys.len()
    }
}

/// One step backward in the cascade: k_{i-1} = k_i - y_i.
pub fn step(release: Scalar, y: Scalar) -> Scalar {
    release - y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cascade_reaches_payer_with_correct_scalars() {
        let secrets = WrSecrets::from_seed([0x33u8; 32], 3);
        let mut release = secrets.final_release();
        for ch in (0..secrets.n_edges()).rev() {
            let expected = ProjectivePoint::GENERATOR * release;
            assert_eq!(expected.to_affine(), secrets.lock_at(ch).to_affine());
            if ch > 0 {
                release = step(release, secrets.y(ch));
            }
        }
    }

    #[test]
    fn wormhole_skip_breaks_next_verification() {
        let secrets = WrSecrets::from_seed([0x44u8; 32], 4);
        // Skip U_2: U_3 sends k_2 directly to U_1 instead of U_2 stepping.
        let mut release = secrets.final_release();
        // Honest release at channel 3.
        assert_eq!(
            (ProjectivePoint::GENERATOR * release).to_affine(),
            secrets.lock_at(3).to_affine()
        );
        // U_3 steps honestly.
        release = step(release, secrets.y(3));
        // Honest release at channel 2.
        assert_eq!(
            (ProjectivePoint::GENERATOR * release).to_affine(),
            secrets.lock_at(2).to_affine()
        );
        // Wormhole: U_2 is skipped; release does NOT step.
        // Channel 1 verification must fail.
        let bogus = release; // not stepped
        assert_ne!(
            (ProjectivePoint::GENERATOR * bogus).to_affine(),
            secrets.lock_at(1).to_affine()
        );
    }
}
