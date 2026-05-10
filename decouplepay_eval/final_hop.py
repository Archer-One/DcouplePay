from __future__ import annotations

import random
from dataclasses import dataclass

from .crypto import SCHNORR_SIG_BYTES, Point, SchnorrKeypair, keygen, sha256, schnorr_sign, schnorr_verify


SAT_PER_BTC = 100_000_000


@dataclass(frozen=True)
class TxTemplate:
    name: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    required_keys: tuple[str, ...]
    nseq: int | None = None
    locktime: int | None = None
    branch: str = ""

    def signing_message(self) -> bytes:
        return self.serialize()

    def serialize(self) -> bytes:
        return (
            f"{self.name}|in={','.join(self.inputs)}|out={','.join(self.outputs)}|"
            f"keys={','.join(self.required_keys)}|nseq={self.nseq}|lock={self.locktime}|{self.branch}"
        ).encode()

    @property
    def size_bytes(self) -> int:
        return len(self.serialize())

    @property
    def witness_bytes(self) -> int:
        return len(self.required_keys) * (1 + SCHNORR_SIG_BYTES) + len(self.branch.encode())


@dataclass
class FinalHopState:
    version: int
    f_balance_sat: int
    p_balance_sat: int
    pk_bs: Point
    f_revocation: SchnorrKeypair
    p_revocation: SchnorrKeypair


@dataclass(frozen=True)
class FinalHopBundle:
    templates: list[TxTemplate]
    state_before: FinalHopState
    state_after: FinalHopState
    revoked_keys: tuple[int, int]

    @property
    def serialized_size(self) -> int:
        return sum(t.size_bytes for t in self.templates)

    @property
    def witness_size(self) -> int:
        return sum(t.witness_bytes for t in self.templates)


def initial_state(pk_bs: Point, rng: random.Random) -> FinalHopState:
    half = SAT_PER_BTC // 2
    return FinalHopState(1, half, half, pk_bs, keygen(rng), keygen(rng))


def build_templates(state: FinalHopState, amount_sat: int) -> list[TxTemplate]:
    f_next = state.f_balance_sat - amount_sat
    p_next = state.p_balance_sat + amount_sat
    return [
        TxTemplate("C1a", ("fund:F-P",), (f"P:{state.p_balance_sat}", f"F:{f_next}:nSeq1000", f"x:{amount_sat}"), ("F1", "P0"), branch="obsolete-state-a"),
        TxTemplate("C1b", ("fund:F-P",), (f"F:{state.f_balance_sat}", f"P:{state.p_balance_sat}", f"x:{amount_sat}:if-bs-else-timeout"), ("F1", "P1"), branch="blind-auth-or-timeout"),
        TxTemplate("C2a", ("fund:F-P",), (f"F:{f_next}", f"P:{p_next}"), ("F2", "P2"), branch="new-state"),
        TxTemplate("RD1a", ("C1a:1",), (f"F:{f_next}",), ("F1", "P0"), nseq=1000, branch="delayed-F-redeem"),
        TxTemplate("RD1b", ("C1b:1",), (f"F:{state.f_balance_sat}",), ("F1", "P1"), nseq=1000, branch="delayed-F-redeem"),
        TxTemplate("RD2b", ("C1b:2",), (f"F:{amount_sat}",), ("F1", "P1"), nseq=1000, branch="corrected-nseq-1000"),
        TxTemplate("BR1a", ("C1a:1",), (f"P:{f_next}",), ("revF1", "revP1"), branch="punish-obsolete"),
        TxTemplate("HS1a", ("C1a:2",), (f"P:{amount_sat}",), ("PK_BS", "P0"), branch="hash-success-a"),
        TxTemplate("HS1b", ("C1b:2",), (f"P:{amount_sat}",), ("PK_BS", "P1"), branch="blind-auth-success-b"),
        TxTemplate("HT1a", ("C1a:2",), (f"F:{amount_sat}",), ("F1", "P0"), nseq=1000, branch="timeout-refund-a"),
        TxTemplate("HT1b", ("C1b:2",), (f"F:{amount_sat}",), ("F1", "P1"), nseq=1000, branch="timeout-refund-b"),
    ]


def sign_and_verify_templates(templates: list[TxTemplate], rng: random.Random) -> tuple[int, int, bool]:
    generated = 0
    verified = 0
    ok = True
    key_cache: dict[str, SchnorrKeypair] = {}
    for template in templates:
        msg = sha256(template.signing_message())
        for key_name in template.required_keys:
            kp = key_cache.setdefault(key_name, keygen(rng))
            sig = schnorr_sign(kp.sk, msg, rng)
            generated += 1
            ok = ok and schnorr_verify(kp.pk, msg, sig)
            verified += 1
    return generated, verified, ok


def simulate_state_update(state: FinalHopState, amount_sat: int, rng: random.Random) -> FinalHopBundle:
    templates = build_templates(state, amount_sat)
    next_state = FinalHopState(
        state.version + 1,
        state.f_balance_sat - amount_sat,
        state.p_balance_sat + amount_sat,
        state.pk_bs,
        keygen(rng),
        keygen(rng),
    )
    revoked = (state.f_revocation.sk, state.p_revocation.sk)
    return FinalHopBundle(templates, state, next_state, revoked)
