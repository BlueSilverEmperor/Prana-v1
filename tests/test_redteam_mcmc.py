"""MCMC red-team sampler: oracle, Metropolis step, determinism, and report consistency."""

import random

from simulator.redteam.mcmc import (ATTACKER, CONTROL_HARM, DECLARED_CAP, HOT_WALLET, MAX_UINT, Variant, accept,
                                    engine_blocks, harm, run)


def test_oracle_scores_by_construction():
    assert harm(Variant("transfer", HOT_WALLET, DECLARED_CAP)) == 0
    assert harm(Variant("transfer", HOT_WALLET, DECLARED_CAP * 2)) == DECLARED_CAP
    assert harm(Variant("transfer", ATTACKER, 5)) == 5
    assert harm(Variant("upgradeTo", ATTACKER, 0)) == CONTROL_HARM
    assert harm(Variant("transfer", HOT_WALLET, 1, operation=1)) == CONTROL_HARM


def test_metropolis_always_accepts_improvements():
    rng = random.Random(0)
    assert accept(1.0, 2.0, beta=0.5, rng=rng)
    assert not any(accept(10.0, -50.0, beta=0.5, rng=random.Random(i)) for i in range(50))


def test_nested_multisend_attack_is_still_blocked():
    assert engine_blocks(Variant("approve", ATTACKER, MAX_UINT, wrap=3, padding=96)) is True


def test_run_is_reproducible_and_consistent():
    a, b = run(steps=120, chains=2, seed=3), run(steps=120, chains=2, seed=3)
    assert (a.accepted, a.unique_variants, len(a.escapes)) == (b.accepted, b.unique_variants, len(b.escapes))
    assert all(harm(Variant(**e)) > 0 and engine_blocks(Variant(**e)) is False for e in a.escapes)
    assert all(harm(Variant(**f)) == 0 for f in a.false_positives)


def test_declared_spender_cannot_get_more_than_the_declared_ceiling():
    # found by the MCMC red team: the allowance itself was never compared with maxOutflowWei
    assert engine_blocks(Variant("approve", HOT_WALLET, MAX_UINT)) is True
    assert engine_blocks(Variant("approve", HOT_WALLET, DECLARED_CAP * 2)) is True
    assert engine_blocks(Variant("increaseAllowance", HOT_WALLET, DECLARED_CAP * 2, wrap=2, padding=32)) is True


def test_declared_spender_within_the_ceiling_is_allowed():
    assert engine_blocks(Variant("approve", HOT_WALLET, DECLARED_CAP)) is False


def test_green_mode_rewards_blocked_harmless_variants():
    from simulator.redteam.mcmc import score
    assert score(0, True, "green") > score(0, False, "green") > score(10**6, False, "green")
    report = run(steps=120, chains=2, seed=5, mode="green")
    assert report.unique_variants > 0


def test_split_allowance_to_declared_spender_is_summed():
    # found by the composition red team: four increaseAllowance calls each under the ceiling, double it together
    from simulator.redteam.mcmc import DECLARED_CAP, HOT_WALLET
    assert engine_blocks(Variant("increaseAllowance", HOT_WALLET, DECLARED_CAP * 2, split=4)) is True


def test_split_payment_within_the_ceiling_still_passes():
    from simulator.redteam.mcmc import DECLARED_CAP, HOT_WALLET
    assert engine_blocks(Variant("transfer", HOT_WALLET, DECLARED_CAP // 2, split=2, decoy=1)) is False
    assert engine_blocks(Variant("increaseAllowance", HOT_WALLET, DECLARED_CAP, split=4)) is False
