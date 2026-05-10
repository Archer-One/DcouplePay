from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .util import elapsed_ms, ns


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUST_DIR = ROOT / "sha256_zkpok" / "sha256_zkpok" / "script"
DEFAULT_BIN = ROOT / "sha256_zkpok" / "sha256_zkpok" / "target" / "release" / "sha256-zkpok"


@dataclass(frozen=True)
class ZkpRunResult:
    mode: str
    prove_time_ms: float
    verify_time_ms: float
    total_time_ms: float
    proof_size_bytes: int
    public_input_bytes: int
    wrapper_io_bytes: int
    ok: bool
    stdout: str


def _extract_ms(output: str, label: str) -> float:
    m = re.search(rf"^{re.escape(label)}\s*:\s*([0-9]+)\s*ms", output, re.MULTILINE)
    return float(m.group(1)) if m else 0.0


def _extract_int(output: str, label: str) -> int:
    m = re.search(rf"^{re.escape(label)}\s*:\s*([0-9]+)", output, re.MULTILINE)
    return int(m.group(1)) if m else 0


def _cargo() -> str:
    return shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")


def _binary_is_current(binary: Path, rust_dir: Path) -> bool:
    if not binary.exists():
        return False
    source = rust_dir / "src" / "bin" / "main.rs"
    return not source.exists() or binary.stat().st_mtime >= source.stat().st_mtime


def run_zkp(
    message: str = "decouplepay-zkp-message",
    mode: str = "execute",
    relation: str = "validresp",
    rust_dir: Path = DEFAULT_RUST_DIR,
    binary: Path = DEFAULT_BIN,
) -> ZkpRunResult:
    env = os.environ.copy()
    env["PATH"] = f"{Path.home() / '.cargo' / 'bin'}:{Path.home() / '.sp1' / 'bin'}:{env.get('PATH', '')}"
    cmd: list[str]
    if _binary_is_current(binary, rust_dir):
        cmd = [str(binary), f"--{mode}", "--m", message, "--relation", relation]
        cwd = binary.parent
    else:
        cmd = [_cargo(), "run", "--release", "--", f"--{mode}", "--m", message, "--relation", relation]
        cwd = rust_dir

    start = ns()
    cp = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    total = elapsed_ms(start)
    out = cp.stdout
    ok = "Public values match expected transcript." in out and "Final sig (R',s') verifies under (X, e'): OK" in out
    prove_ms = _extract_ms(out, "prove (STARK)")
    verify_ms = _extract_ms(out, "verify (SP1)")
    proof_size = _extract_int(out, "proof size bytes")
    if mode == "execute":
        # The existing CLI executes the guest and verifies public consistency,
        # but does not serialize a proof. We report elapsed execute time in
        # prove_time_ms for CSV comparability and set proof size to zero.
        prove_ms = total
        proof_size = 0
    return ZkpRunResult(
        mode=mode,
        prove_time_ms=prove_ms,
        verify_time_ms=verify_ms,
        total_time_ms=total,
        proof_size_bytes=proof_size,
        public_input_bytes=32 if relation == "sha256" else 130,
        wrapper_io_bytes=sum(len(x.encode()) for x in cmd) + len(out.encode()),
        ok=ok,
        stdout=out,
    )
