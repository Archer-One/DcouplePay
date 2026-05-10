from __future__ import annotations

import random
from dataclasses import dataclass

from .crypto import (
    POINT_BYTES,
    SCHNORR_SIG_BYTES,
    SCALAR_BYTES,
    Point,
    SchnorrSignature,
    challenge,
    keygen,
    mod,
    point_add,
    point_bytes,
    point_mul,
    rand_scalar,
    scalar_bytes,
    sha256,
    schnorr_verify,
)


@dataclass(frozen=True)
class RouteSetupState:
    node: str
    y_prev_point: Point
    y_point: Point
    hop_secret: int


@dataclass(frozen=True)
class RoutedLock:
    sid: str
    pid: tuple[str, ...]
    left: str
    right: str
    hash_r: bytes
    pk: Point
    r_point: Point
    partial_s: int
    y_point: Point
    amount_sat: int
    timeout: int

    def serialize(self) -> bytes:
        return b"".join(
            [
                self.sid.encode(),
                b"|".join(x.encode() for x in self.pid),
                self.left.encode(),
                self.right.encode(),
                self.hash_r,
                point_bytes(self.pk),
                point_bytes(self.r_point),
                scalar_bytes(self.partial_s),
                point_bytes(self.y_point),
                self.amount_sat.to_bytes(8, "big"),
                self.timeout.to_bytes(4, "big"),
            ]
        )


@dataclass(frozen=True)
class RoutedRelease:
    response: bytes
    amhl_sig: SchnorrSignature
    partial_s: int

    def serialize(self) -> bytes:
        return self.response + self.amhl_sig.serialize() + scalar_bytes(self.partial_s)


@dataclass(frozen=True)
class RouteContext:
    path: list[str]
    states: dict[str, RouteSetupState]
    receiver_secret: int
    locks: list[RoutedLock]


def setup_route(path_len: int, rng: random.Random) -> tuple[list[str], dict[str, RouteSetupState], int]:
    path = [f"U{i}" for i in range(path_len)]
    if path:
        path[-1] = "F"
    if path_len < 1:
        raise ValueError("path_len must be >= 1")
    if path_len == 1:
        return path, {"F": RouteSetupState("F", None, None, 0)}, 0

    y0 = rand_scalar(rng)
    y_point = point_mul(y0)
    states = {path[0]: RouteSetupState(path[0], None, y_point, y0)}
    receiver_secret = y0
    for i in range(1, path_len - 1):
        yi = rand_scalar(rng)
        y_next = point_add(y_point, point_mul(yi))
        states[path[i]] = RouteSetupState(path[i], y_point, y_next, yi)
        y_point = y_next
        receiver_secret = mod(receiver_secret + yi)
    states[path[-1]] = RouteSetupState(path[-1], y_point, y_point, 0)
    return path, states, receiver_secret


def lock_route(
    sid: str,
    path: list[str],
    states: dict[str, RouteSetupState],
    hash_r: bytes,
    amount_sat: int,
    rng: random.Random,
) -> list[RoutedLock]:
    locks: list[RoutedLock] = []
    for i, (left, right) in enumerate(zip(path, path[1:])):
        left_key = keygen(rng)
        right_key = keygen(rng)
        pk = point_mul(left_key.sk + right_key.sk)
        msg = f"{sid}:{left}->{right}:{amount_sat}:{hash_r.hex()}".encode()
        r0 = rand_scalar(rng)
        r1 = rand_scalar(rng)
        r_no_amhl = point_add(point_mul(r0), point_mul(r1))
        r_point = point_add(r_no_amhl, states[left].y_point)
        e = challenge(pk, r_point, msg)
        partial_s = mod(r0 + r1 + e * (left_key.sk + right_key.sk))
        locks.append(
            RoutedLock(
                sid=sid,
                pid=tuple(path),
                left=left,
                right=right,
                hash_r=hash_r,
                pk=pk,
                r_point=r_point,
                partial_s=partial_s,
                y_point=states[left].y_point,
                amount_sat=amount_sat,
                timeout=1000 + i,
            )
        )
    return locks


def lock_message(lock: RoutedLock) -> bytes:
    return f"{lock.sid}:{lock.left}->{lock.right}:{lock.amount_sat}:{lock.hash_r.hex()}".encode()


def verify_lock(lock: RoutedLock) -> bool:
    partial = SchnorrSignature(lock.r_point, lock.partial_s)
    # Incomplete AMHL signatures should not verify before release.
    return not schnorr_verify(lock.pk, lock_message(lock), partial) and len(lock.hash_r) == 32


def generate_releases(ctx: RouteContext, response: bytes) -> list[RoutedRelease]:
    if not ctx.locks:
        return []
    if sha256(response) != ctx.locks[-1].hash_r:
        raise ValueError("response does not match routed hash")

    opening = SchnorrSignature(ctx.locks[-1].r_point, mod(ctx.locks[-1].partial_s + ctx.receiver_secret))
    releases = [RoutedRelease(response, opening, ctx.locks[-1].partial_s)]
    for i in range(len(ctx.locks) - 2, -1, -1):
        intermediary = ctx.path[i + 1]
        right = releases[-1]
        state = ctx.states[intermediary]
        predecessor_secret = mod(right.amhl_sig.s - right.partial_s - state.hop_secret)
        sig = SchnorrSignature(ctx.locks[i].r_point, mod(ctx.locks[i].partial_s + predecessor_secret))
        releases.append(RoutedRelease(response, sig, ctx.locks[i].partial_s))
    return list(reversed(releases))


def verify_release(lock: RoutedLock, release: RoutedRelease) -> bool:
    return (
        sha256(release.response) == lock.hash_r
        and schnorr_verify(lock.pk, lock_message(lock), release.amhl_sig)
    )


LOCK_BASE_BYTES = 32 + POINT_BYTES * 3 + SCALAR_BYTES + 16
RELEASE_BASE_BYTES = 32 + SCHNORR_SIG_BYTES + SCALAR_BYTES
