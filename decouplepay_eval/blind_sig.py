from __future__ import annotations

import random
from dataclasses import dataclass

from .crypto import (
    POINT_BYTES,
    SCHNORR_SIG_BYTES,
    SCALAR_BYTES,
    Q,
    Point,
    SchnorrSignature,
    challenge,
    keygen,
    mod,
    point_add,
    point_bytes,
    point_mul,
    scalar_bytes,
    schnorr_verify,
)


@dataclass(frozen=True)
class BlindSignerKeypair:
    sk: int
    pk: Point


@dataclass(frozen=True)
class BlindedMessage:
    message: bytes
    signer_nonce: int
    signer_nonce_point: Point
    blinded_nonce_point: Point
    blinded_challenge: int
    signer_pk: Point

    def serialize(self) -> bytes:
        return b"".join(
            [
                len(self.message).to_bytes(4, "big"),
                self.message,
                point_bytes(self.signer_nonce_point),
                point_bytes(self.blinded_nonce_point),
                scalar_bytes(self.blinded_challenge),
                point_bytes(self.signer_pk),
            ]
        )


@dataclass(frozen=True)
class BlindingState:
    alpha: int
    beta: int
    message: bytes
    signer_pk: Point
    blinded_nonce_point: Point
    unblinded_challenge: int


@dataclass(frozen=True)
class BlindResponse:
    sigma: int

    def serialize(self) -> bytes:
        return scalar_bytes(self.sigma)


def bs_keygen(rng: random.Random) -> BlindSignerKeypair:
    kp = keygen(rng)
    return BlindSignerKeypair(kp.sk, kp.pk)


def bs_blind(message: bytes, pk_bs: Point, rng: random.Random) -> tuple[BlindedMessage, BlindingState]:
    # Benchmark abstraction of blind Schnorr. The signer nonce is sampled here
    # to keep a single-call interface; production protocols commit to nonce in
    # a separate signer round.
    signer_nonce = rng.randrange(1, Q)
    signer_nonce_point = point_mul(signer_nonce)
    alpha = rng.randrange(1, Q)
    beta = rng.randrange(1, Q)
    blinded_nonce_point = point_add(signer_nonce_point, point_mul(alpha), point_mul(beta, pk_bs))
    e_prime = challenge(pk_bs, blinded_nonce_point, message)
    e = mod(e_prime + beta)
    blinded = BlindedMessage(message, signer_nonce, signer_nonce_point, blinded_nonce_point, e, pk_bs)
    state = BlindingState(alpha, beta, message, pk_bs, blinded_nonce_point, e_prime)
    return blinded, state


def bs_sign(sk_bs: int, blinded_message: BlindedMessage) -> BlindResponse:
    sigma = mod(blinded_message.signer_nonce + blinded_message.blinded_challenge * sk_bs)
    return BlindResponse(sigma)


def bs_unblind(blind_response: BlindResponse, blinding_state: BlindingState) -> SchnorrSignature:
    return SchnorrSignature(
        blinding_state.blinded_nonce_point,
        mod(blind_response.sigma + blinding_state.alpha),
    )


def bs_verify(pk_bs: Point, message: bytes, signature: SchnorrSignature) -> bool:
    return schnorr_verify(pk_bs, message, signature)


BLINDED_MESSAGE_BASE_BYTES = 4 + 32 + POINT_BYTES * 3 + SCALAR_BYTES
BLIND_RESPONSE_BYTES = SCALAR_BYTES
FINAL_SIGNATURE_BYTES = SCHNORR_SIG_BYTES
