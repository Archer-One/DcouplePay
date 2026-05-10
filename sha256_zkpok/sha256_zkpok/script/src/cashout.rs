//! Minimal cash-out transaction model for the dPay payee-side redeem.
//!
//! In a real PCN this would be an actual on-chain spending transaction
//! whose sighash is what the blind signature authorizes. For the demo
//! we keep the structure but use a simple SHA-256 commitment to the
//! relevant fields rather than a Bitcoin-format sighash.

use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct CashoutTx {
    /// Identifier of the U_{n-1} <-> U_n channel that will settle this tx.
    pub channel_id: [u8; 32],
    /// Payee public key in SEC1 compressed form.
    pub payee_pk: [u8; 33],
    /// Amount to be paid out to the payee, in atomic units (e.g. sats).
    pub amount: u64,
    /// Tx version field, mirroring real-PCN structure.
    pub version: u32,
}

impl CashoutTx {
    /// Domain-separated SHA-256 commitment over the spending fields.
    /// This is the message `m` that gets blind-signed during dPay setup.
    pub fn sighash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"sha256-zkpok-cashout-v1");
        h.update(self.version.to_be_bytes());
        h.update(self.channel_id);
        h.update(self.payee_pk);
        h.update(self.amount.to_be_bytes());
        h.finalize().into()
    }
}
