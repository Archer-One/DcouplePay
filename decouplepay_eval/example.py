from __future__ import annotations

from .amhl_htlc import RouteContext, generate_releases, lock_route, setup_route, verify_lock, verify_release
from .blind_sig import bs_blind, bs_keygen, bs_sign, bs_unblind, bs_verify
from .crypto import sha256
from .final_hop import build_templates, initial_state, simulate_state_update
from .util import rng_from_seed


def main() -> None:
    rng = rng_from_seed(20260510)
    amount_sat = 100_000

    signer = bs_keygen(rng)
    cashout_message = b"dpay-final-hop-redemption"
    blinded, blinding_state = bs_blind(cashout_message, signer.pk, rng)
    blind_response = bs_sign(signer.sk, blinded)
    final_signature = bs_unblind(blind_response, blinding_state)
    assert bs_verify(signer.pk, cashout_message, final_signature)

    response = blind_response.serialize()
    path, states, receiver_secret = setup_route(path_len=4, rng=rng)
    locks = lock_route(
        sid="example-session",
        path=path,
        states=states,
        hash_r=sha256(response),
        amount_sat=amount_sat,
        rng=rng,
    )
    assert all(verify_lock(lock) for lock in locks)

    ctx = RouteContext(path=path, states=states, receiver_secret=receiver_secret, locks=locks)
    releases = generate_releases(ctx, response)
    assert all(verify_release(lock, release) for lock, release in zip(locks, releases))

    channel_state = initial_state(signer.pk, rng)
    bundle = simulate_state_update(channel_state, amount_sat, rng)
    templates = build_templates(channel_state, amount_sat)

    print("dPay core example completed")
    print(f"route: {' -> '.join(path)}")
    print(f"locks installed/released: {len(locks)}")
    print(f"final-hop templates: {len(templates)}")
    print(f"next state version: {bundle.state_after.version}")


if __name__ == "__main__":
    main()
