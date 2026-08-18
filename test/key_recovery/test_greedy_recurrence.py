"""
The greedy's cost model, tested without a solver.

`estimate_dynamic_autoguess_greedy` is where every reported figure is actually
produced: the per-step work, the surviving-pair count, the key-bit accounting and
the order the S-boxes are peeled in. It normally reaches AutoGuess through
`_run_candidate`, which it calls unqualified, so a test can substitute that call
and hand the greedy canned per-S-box answers. Nothing here builds a cipher, writes
a model or runs a SAT solve; the whole file is milliseconds.

The arithmetic under test:

    work_i        = pairs_left_{i-1} + dK_i
    pairs_left_i  = with_right_pair(work_i - filter_i)
    T             = log2 sum of 2^work_i
    dK_i          = bits of key this S-box adds that are not already known

and the selection rule: commit the S-box with the lowest `dK - filter`, ties
broken by position.
"""
import math
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest

import attacks.key_recovery_modules.dynamic_greedy as dg
from attacks.key_recovery_modules.dynamic_greedy import (
    estimate_dynamic_autoguess_greedy, with_right_pair)
from attacks.key_recovery_modules.propagation import make_unit_id


# --- fakes -------------------------------------------------------------------

class FakeKeyVar:
    """Stands in for an OCP key Variable: the greedy only reads ID and bitsize."""

    def __init__(self, ID, bitsize=1):
        self.ID = ID
        self.bitsize = bitsize

    def __repr__(self):
        return f"FakeKeyVar({self.ID!r}, {self.bitsize})"


def record(name, *, filter_bits, guessed=(), determined=(), width=1, side="backward"):
    """One canned S-box: what it costs to solve and what it filters.

    `guessed` are key variable IDs the solve returns, each `width` bits wide;
    `determined` are key variables the key schedule then yields for free.
    """
    return {
        "side": side,
        "round": 1,
        "input_positions": [name],          # make_unit_id only formats these
        "_filter": float(filter_bits),
        "_guessed": [FakeKeyVar(v, width) for v in guessed],
        "_determined": list(determined),
    }


def install(monkeypatch, *, calls=None):
    """Route the greedy's solver call and filter lookup to the canned data.

    `calls`, if given, collects the `extra_known` set the greedy passes at each
    candidate solve, so a test can check what it considers already known.
    """
    def fake_run_candidate(cipher, rec, extra_known, *args, **kwargs):
        if calls is not None:
            calls.append(set(extra_known))
        return {
            "unit": make_unit_id(rec),
            "label": f"{make_unit_id(rec)}:out",
            "guessed_variables": list(rec["_guessed"]),
            "determined_key_var_ids": list(rec["_determined"]),
        }

    monkeypatch.setattr(dg, "_run_candidate", fake_run_candidate)
    monkeypatch.setattr(dg, "conditional_target_side_filter_for_record",
                        lambda rec: rec["_filter"])


def run(records, N0_log2, **kwargs):
    """Drive the greedy over canned records; returns its 7-tuple."""
    return estimate_dynamic_autoguess_greedy(
        cipher=None, sbox_records=records,
        distinguisher_start=2, distinguisher_end=5,
        N0_log2=N0_log2, verbose=False, **kwargs)


# --- the work / survivor recurrence ------------------------------------------

def test_single_step_work_and_survivors(monkeypatch):
    install(monkeypatch)
    recs = [record("A", filter_bits=3.0, guessed=["k0", "k1", "k2", "k3"])]

    ordering, stages, _, T_log2, survivors, total_K, _ = run(recs, N0_log2=10.0)

    # 2^10 pairs alive, 2^4 key guesses each -> 2^14 work; the 3-bit filter then
    # leaves 2^11 of them.
    assert stages[0]["delta_K_bits"] == 4
    assert stages[0]["work_log2"] == pytest.approx(14.0)
    assert stages[0]["survivors_log2"] == pytest.approx(with_right_pair(11.0))
    assert T_log2 == pytest.approx(14.0)          # one step, so T is that step
    assert survivors == pytest.approx(stages[0]["survivors_log2"])
    assert ordering == [make_unit_id(recs[0])]
    assert total_K == 4


def test_work_chains_through_the_survivor_count(monkeypatch):
    install(monkeypatch)
    # Three identical S-boxes, disjoint key material: dK = 4, filter = 3 each.
    recs = [record(n, filter_bits=3.0, guessed=[f"k{n}{i}" for i in range(4)])
            for n in "ABC"]

    _, stages, _, T_log2, _, total_K, _ = run(recs, N0_log2=50.0)

    # 50 -> work 54, left 51 -> work 55, left 52 -> work 56, left 53
    assert [s["work_log2"] for s in stages] == pytest.approx([54.0, 55.0, 56.0])
    assert [s["survivors_log2"] for s in stages] == pytest.approx([51.0, 52.0, 53.0])
    # T is the SUM of the three step works, not the largest of them.
    assert T_log2 == pytest.approx(math.log2(2.0**54 + 2.0**55 + 2.0**56))
    assert T_log2 > 56.0
    assert total_K == 12


def test_each_step_starts_from_the_previous_survivor_count(monkeypatch):
    install(monkeypatch)
    recs = [record(n, filter_bits=2.0, guessed=[f"k{n}"], width=4) for n in "ABCD"]

    _, stages, _, _, _, _, _ = run(recs, N0_log2=30.0)

    for prev, cur in zip(stages, stages[1:]):
        assert cur["work_log2"] == pytest.approx(
            prev["survivors_log2"] + cur["delta_K_bits"])


def test_a_strong_filter_cannot_empty_the_pair_set(monkeypatch):
    install(monkeypatch)
    # Filter far larger than the work: the wrong pairs are all gone, but the right
    # pair passes every sieve by construction, so the count floors at 2^0.
    recs = [record("A", filter_bits=40.0, guessed=["k0"])]

    _, stages, _, _, survivors, _, _ = run(recs, N0_log2=0.0)

    assert stages[0]["work_log2"] == pytest.approx(1.0)
    assert survivors >= 0.0
    assert survivors == pytest.approx(0.0, abs=1e-9)


def test_t_never_falls_below_the_first_step(monkeypatch):
    install(monkeypatch)
    recs = [record(n, filter_bits=30.0, guessed=[f"k{n}"]) for n in "AB"]

    _, stages, _, T_log2, _, _, _ = run(recs, N0_log2=5.0)

    # Even with filters that annihilate the pair set, the work already done counts.
    assert T_log2 >= stages[0]["work_log2"]


# --- which S-box gets committed ----------------------------------------------

def test_commits_the_lowest_delta_k_minus_filter(monkeypatch):
    install(monkeypatch)
    recs = [
        record("A", filter_bits=3.0, guessed=["a0", "a1", "a2", "a3"]),   # 4-3 = +1
        record("B", filter_bits=3.0, guessed=["b0", "b1"]),               # 2-3 = -1
        record("C", filter_bits=4.0, guessed=["c0", "c1", "c2", "c3"]),   # 4-4 =  0
    ]

    ordering, stages, _, _, _, _, _ = run(recs, N0_log2=20.0)

    assert ordering == [make_unit_id(recs[1]),      # -1 first
                        make_unit_id(recs[2]),      #  0 next
                        make_unit_id(recs[0])]      # +1 last
    assert [s["delta_K_bits"] for s in stages] == [2, 4, 4]


def test_ties_break_on_position(monkeypatch):
    install(monkeypatch)
    # Same dK - filter for both; the earlier record must win.
    recs = [record("A", filter_bits=3.0, guessed=["a0", "a1", "a2"]),
            record("B", filter_bits=3.0, guessed=["b0", "b1", "b2"])]

    ordering, _, _, _, _, _, _ = run(recs, N0_log2=20.0)

    assert ordering == [make_unit_id(recs[0]), make_unit_id(recs[1])]


def test_every_sbox_is_committed_exactly_once(monkeypatch):
    install(monkeypatch)
    recs = [record(n, filter_bits=2.0 + i, guessed=[f"k{n}"])
            for i, n in enumerate("ABCDE")]

    ordering, stages, key_id_sets, _, _, _, selected = run(recs, N0_log2=40.0)

    assert len(ordering) == len(recs) == len(stages) == len(selected)
    assert sorted(ordering) == sorted(make_unit_id(r) for r in recs)
    assert set(key_id_sets) == set(ordering)


# --- key-bit accounting ------------------------------------------------------

def test_a_key_variable_is_charged_once(monkeypatch):
    install(monkeypatch)
    shared = ["k0", "k1", "k2", "k3"]
    recs = [record("A", filter_bits=3.0, guessed=shared),
            record("B", filter_bits=3.0, guessed=shared)]

    _, stages, _, _, _, total_K, _ = run(recs, N0_log2=20.0)

    assert stages[0]["delta_K_bits"] == 4
    assert stages[1]["delta_K_bits"] == 0      # already known, so free
    assert total_K == 4                        # not 8


def test_key_schedule_derived_variables_are_free(monkeypatch):
    install(monkeypatch)
    # Solving A guesses k0 and, through the key schedule, determines k9.
    # B needs k9, which it must not be charged for.
    recs = [record("A", filter_bits=9.0, guessed=["k0"], determined=["k9"]),
            record("B", filter_bits=1.0, guessed=["k9"])]

    ordering, stages, _, _, _, total_K, _ = run(recs, N0_log2=20.0)

    assert ordering[0] == make_unit_id(recs[0])
    assert stages[1]["delta_K_bits"] == 0
    assert total_K == 1                        # only k0 was ever paid for


def test_a_key_word_costs_its_full_width(monkeypatch):
    install(monkeypatch)
    # One nibble-wide key variable is 4 bits of guessing, not 1.
    recs = [record("A", filter_bits=0.0, guessed=["k0"], width=4)]

    _, stages, _, _, _, total_K, _ = run(recs, N0_log2=10.0)

    assert stages[0]["delta_K_bits"] == 4
    assert stages[0]["work_log2"] == pytest.approx(14.0)
    assert total_K == 4


def test_widths_are_summed_across_variables(monkeypatch):
    install(monkeypatch)
    recs = [record("A", filter_bits=0.0, guessed=["k0", "k1", "k2"], width=4)]

    _, stages, _, _, _, total_K, _ = run(recs, N0_log2=10.0)

    assert stages[0]["delta_K_bits"] == 12
    assert total_K == 12


def test_committed_keys_are_offered_to_the_next_solve(monkeypatch):
    calls = []
    install(monkeypatch, calls=calls)
    recs = [record("A", filter_bits=9.0, guessed=["k0"], determined=["k9"]),
            record("B", filter_bits=1.0, guessed=["k1"])]

    run(recs, N0_log2=20.0)

    # Step 1 evaluates both candidates knowing nothing; step 2 knows what step 1
    # guessed AND what its key schedule determined.
    assert calls[0] == set() and calls[1] == set()
    assert calls[2] == {"k0", "k9"}


# --- failure paths -----------------------------------------------------------

def test_empty_records_is_rejected():
    with pytest.raises(ValueError, match="empty sbox_records"):
        run([], N0_log2=10.0)


def test_a_failed_solve_stops_the_run(monkeypatch):
    install(monkeypatch)
    monkeypatch.setattr(dg, "_run_candidate", lambda *a, **k: {
        "solver_failed": True, "label": "sb_b_r1_[A]:out",
        "autoguess_message": "no guess basis found"})
    recs = [record("A", filter_bits=3.0, guessed=["k0"])]

    # Never a silent skip: a partial peel would report a cost for an attack that
    # was never completed.
    with pytest.raises(RuntimeError, match="could not solve S-box"):
        run(recs, N0_log2=10.0, config_model={"maxsteps": 40})


def test_a_missing_package_is_named_as_such(monkeypatch):
    install(monkeypatch)
    monkeypatch.setattr(dg, "_run_candidate", lambda *a, **k: {
        "solver_failed": True, "label": "sb_b_r1_[A]:out",
        "solver_error": "ModuleNotFoundError: No module named 'pysat'"})
    recs = [record("A", filter_bits=3.0, guessed=["k0"])]

    # An absent dependency must not be reported as a solver limit -- raising
    # maxsteps would not help and sends the user after the wrong thing.
    with pytest.raises(RuntimeError, match="pysat.*not installed"):
        run(recs, N0_log2=10.0)


def test_an_impossible_transition_stops_the_run(monkeypatch):
    install(monkeypatch)
    recs = [record("A", filter_bits=3.0, guessed=["k0"]),
            record("B", filter_bits=math.inf, guessed=["k1"])]

    # Left alone this sorts first and wipes the pair set, reporting a cost for an
    # attack that cannot exist.
    with pytest.raises(RuntimeError, match="Impossible S-box transition"):
        run(recs, N0_log2=20.0)


# --- what the report layer is handed -----------------------------------------

def test_callbacks_fire_once_per_step(monkeypatch):
    install(monkeypatch)
    recs = [record(n, filter_bits=2.0, guessed=[f"k{n}"]) for n in "ABC"]
    steps, progress = [], []

    run(recs, N0_log2=20.0,
        step_callback=lambda step, unit, stage, ids: steps.append((step, unit, ids)),
        progress_callback=lambda step, n: progress.append((step, n)))

    assert [s for s, _, _ in steps] == [1, 2, 3]
    assert progress == [(1, 3), (2, 2), (3, 1)]       # the pool shrinks each step
    assert [ids for _, _, ids in steps] == [["kA"], ["kB"], ["kC"]]


def test_stage_dicts_carry_what_the_report_prints(monkeypatch):
    install(monkeypatch)
    recs = [record("A", filter_bits=3.0, guessed=["k0", "k1"])]

    _, stages, _, _, _, _, _ = run(recs, N0_log2=12.0)

    assert set(stages[0]) == {"delta_K_bits", "filter_bits", "filter_model",
                              "work_log2", "survivors_log2"}
    assert stages[0]["filter_bits"] == pytest.approx(3.0)
    assert stages[0]["filter_model"] == "conditional_target_side"


def test_filters_are_looked_up_per_sbox_not_shared(monkeypatch):
    install(monkeypatch)
    # Distinct filters; each stage must carry the filter of the S-box it committed.
    recs = [record("A", filter_bits=1.0, guessed=["a"]),
            record("B", filter_bits=5.0, guessed=["b"]),
            record("C", filter_bits=3.0, guessed=["c"])]

    ordering, stages, _, _, _, _, _ = run(recs, N0_log2=20.0)

    filter_by_unit = {make_unit_id(r): r["_filter"] for r in recs}
    for unit, stage in zip(ordering, stages):
        assert stage["filter_bits"] == pytest.approx(filter_by_unit[unit])
