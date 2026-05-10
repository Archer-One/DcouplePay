#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    let response: [u8; 32] =
        sp1_zkvm::io::read_vec().try_into().expect("response must be 32 bytes");
    let r: [u8; 32] = Sha256::digest(response).into();
    sp1_zkvm::io::commit_slice(&r);
}
