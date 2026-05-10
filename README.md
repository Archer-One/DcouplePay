# DecouplePay Artifact

This directory is a clean runnable artifact for DecouplePay (dPay), a payment-channel-network protocol that separates payer-side routed payment from payee-side redemption. The artifact keeps only implementation code needed to build and execute the core protocol flow.

## What Is Included

- Dependency-free Python implementation of secp256k1/Schnorr-style operations used by the dPay model.
- Blind-Schnorr-style redemption authorization.
- Schnorr-AMHL/HTLC-style routed lock and release logic for the payer-to-final-intermediary path.
- Final-intermediary redemption and final-hop channel-state template logic.
- Off-chain verification checks required before routed locks, releases, and final-hop states are accepted.
- Optional Rust/SP1 component for the SHA-256/blind-response ZK proof relation.

## Directory Structure

```text
dPay-artifact/
  README.md
  VALIDATION.md
  .gitignore
  decouplepay_eval/
    crypto.py              secp256k1 and Schnorr-style primitives
    blind_sig.py           blind-signature redemption authorization
    amhl_htlc.py           routed AMHL/HTLC-style lock and release logic
    final_hop.py           final-hop redemption/channel-state templates
    zkp_wrapper.py         Python wrapper for the optional Rust/SP1 ZKP binary
    util.py                small runtime helpers
    example.py             minimal core-flow entry point
  sha256_zkpok/sha256_zkpok/
    Cargo.toml
    Cargo.lock
    rust-toolchain
    LICENSE-MIT
    program/               SP1 guest programs
    script/                host driver and dPay ZKP support library
```

## Required Software

- Python 3.10 or newer.
- Rust/Cargo matching `sha256_zkpok/sha256_zkpok/rust-toolchain` for the optional SP1 component.
- SP1 toolchain for building or proving the Rust ZKP component. The original code expects `cargo-prove` and related SP1 tools on `PATH`, commonly under `~/.sp1/bin`.

## Dependencies

The Python core uses only the Python standard library. No `requirements.txt` is needed.

The optional Rust/SP1 component uses the crates pinned by `Cargo.lock`, including `sp1-sdk`, `sp1-zkvm`, `k256`, `sha2`, `clap`, and `hex`.

## Install Dependencies

For the Python-only core flow, no dependency installation is required:

```bash
cd dPay-artifact
python3 --version
```

For the optional ZKP component, install Rust and SP1, then let Cargo fetch the pinned crates:

```bash
cd dPay-artifact/sha256_zkpok/sha256_zkpok
cargo fetch
```

## Build

Python files can be byte-compiled with:

```bash
cd dPay-artifact
python3 -m compileall decouplepay_eval
```

Build the optional Rust/SP1 host binary with:

```bash
cd dPay-artifact/sha256_zkpok/sha256_zkpok/script
cargo build --release
```

## Run The Core Implementation

Run the Python core-flow example:

```bash
cd dPay-artifact
python3 -m decouplepay_eval.example
```

Run the optional Rust/SP1 execution path, which checks the blind-response relation without producing a proof:

```bash
cd dPay-artifact/sha256_zkpok/sha256_zkpok/script
cargo run --release -- --execute --relation validresp
```

Generate a real SP1 proof only when the SP1 proving environment is installed:

```bash
cd dPay-artifact/sha256_zkpok/sha256_zkpok/script
cargo run --release -- --prove --relation validresp
```

## Cryptographic Notes

The Python secp256k1/Schnorr-style code is intentionally small and dependency-free for artifact readability and reproducibility. It is suitable for protocol execution and research inspection, but it is not constant-time production cryptography.

The blind-signature module models the final-intermediary authorization flow used for payee redemption. The routed-lock module binds the revealed response to a hash value and AMHL-style release scalar so off-chain participants can verify state before installing or releasing channel states.

The Rust/SP1 component proves the setup-phase relation around the hidden blind-signature response. The richer relation checks `r = SHA256(sigma)` together with the public secp256k1 transcript consistency `sigma * G = R + e * X`. The Python wrapper can invoke this component when the Rust binary or Cargo build is available.

## Intentionally Excluded

This clean artifact intentionally excludes actual test code, unit-test directories, benchmark activation scripts, performance launch scripts, plotting scripts, generated CSV files, raw experiment outputs, generated figures, logs, build caches, IDE metadata, paper PDFs, LaTeX files, and unrelated drafts.

The omitted directories and files include the original `benchmark/`, `decouplepay_eval/benchmark/`, `decouplepay_eval/results/`, `evaluation/`, `paper/`, Rust `target/`, Python cache directories, `.idea/`, `.vscode/`, and ad hoc top-level demo/test scripts from the source tree.
