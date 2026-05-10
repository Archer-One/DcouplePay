# Validation

Validation commands are recorded here so failed environment-dependent steps are explicit.

Date: 2026-05-10

## Python Core

Command:

```bash
cd dPay-artifact
python3 -m compileall decouplepay_eval
```

Result: succeeded.

Command:

```bash
cd dPay-artifact
python3 -m decouplepay_eval.example
```

Result: succeeded. The example completed the blind authorization, routed lock/release, and final-hop state update flow.

## Optional Rust/SP1 Component

Command:

```bash
cd dPay-artifact/sha256_zkpok/sha256_zkpok/script
cargo build --release
```

Result: succeeded after allowing Cargo/SP1 to write required internal build artifacts outside the workspace. An initial sandboxed attempt failed because `sp1-core-executor-runner` tried to create an internal `.cargo-lock` under the local Cargo registry, which was read-only in the sandbox.

Command:

```bash
cd dPay-artifact/sha256_zkpok/sha256_zkpok/script
cargo run --release -- --execute --relation validresp
```

Result: succeeded. The SP1 execute path reported that public values matched the expected transcript and that the final unblinded signature verified.

Generated validation outputs such as Python `__pycache__/` directories and Rust `target/` build products were removed from the artifact after validation.
