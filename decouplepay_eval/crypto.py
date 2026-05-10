from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import TypeAlias


# secp256k1 parameters.  These Python routines are intentionally small and
# dependency-free for benchmark reproducibility; they are not constant-time.
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240
GENERATOR_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
Point: TypeAlias = tuple[int, int] | None
G: Point = (GENERATOR_X, GENERATOR_Y)

SCALAR_BYTES = 32
# Off-chain transcripts use SEC1 compressed secp256k1 points. Schnorr
# signatures still serialize the nonce point as x-only plus a scalar.
POINT_BYTES = 33
XONLY_POINT_BYTES = 32
SCHNORR_SIG_BYTES = 64


def mod(x: int) -> int:
    return x % Q


def field_mod(x: int) -> int:
    return x % FIELD_PRIME


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def scalar_bytes(x: int) -> bytes:
    return mod(x).to_bytes(SCALAR_BYTES, "big")


def _require_point(p: Point) -> tuple[int, int]:
    if p is None:
        raise ValueError("point at infinity cannot be serialized")
    return p


def point_xonly_bytes(p: Point) -> bytes:
    x, _ = _require_point(p)
    return x.to_bytes(XONLY_POINT_BYTES, "big")


def point_bytes(p: Point) -> bytes:
    x, y = _require_point(p)
    prefix = 0x02 | (y & 1)
    return bytes([prefix]) + x.to_bytes(32, "big")


def scalar_from_hash(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return int.from_bytes(h.digest(), "big") % Q or 1


def rand_scalar(rng: random.Random) -> int:
    return rng.randrange(1, Q)


def _point_double(p: Point) -> Point:
    if p is None:
        return None
    x, y = p
    if y == 0:
        return None
    lam = field_mod((3 * x * x) * pow(2 * y, -1, FIELD_PRIME))
    xr = field_mod(lam * lam - 2 * x)
    yr = field_mod(lam * (x - xr) - y)
    return xr, yr


def _point_add2(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    ax, ay = a
    bx, by = b
    if ax == bx and field_mod(ay + by) == 0:
        return None
    if a == b:
        return _point_double(a)
    lam = field_mod((by - ay) * pow(bx - ax, -1, FIELD_PRIME))
    xr = field_mod(lam * lam - ax - bx)
    yr = field_mod(lam * (ax - xr) - ay)
    return xr, yr


def point_mul(s: int, point: Point = G) -> Point:
    scalar = mod(s)
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add2(result, addend)
        addend = _point_double(addend)
        scalar >>= 1
    return result


def point_add(*points: Point) -> Point:
    result: Point = None
    for point in points:
        result = _point_add2(result, point)
    return result


def challenge(pk: Point, r_point: Point, msg: bytes) -> int:
    return scalar_from_hash(point_bytes(pk), point_bytes(r_point), msg)


@dataclass(frozen=True)
class SchnorrKeypair:
    sk: int
    pk: Point


@dataclass(frozen=True)
class SchnorrSignature:
    r_point: Point
    s: int

    def serialize(self) -> bytes:
        return point_xonly_bytes(self.r_point) + scalar_bytes(self.s)


def keygen(rng: random.Random) -> SchnorrKeypair:
    sk = rand_scalar(rng)
    return SchnorrKeypair(sk, point_mul(sk))


def schnorr_sign(sk: int, msg: bytes, rng: random.Random) -> SchnorrSignature:
    k = rand_scalar(rng)
    r = point_mul(k)
    e = challenge(point_mul(sk), r, msg)
    return SchnorrSignature(r, mod(k + e * sk))


def schnorr_verify(pk: Point, msg: bytes, sig: SchnorrSignature) -> bool:
    e = challenge(pk, sig.r_point, msg)
    return point_mul(sig.s) == point_add(sig.r_point, point_mul(e, pk))
