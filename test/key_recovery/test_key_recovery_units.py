"""
Unit tests for the solver-free parts of the key-recovery layer.

Everything here runs without AutoGuess, without a SAT solver and in milliseconds,
so it is collectable by pytest. The end-to-end reproductions of published attacks
live in the `*_attack.py` scripts next to this file: they take minutes each and
are run by hand, which is why they are deliberately not named `test_*`.
"""
import math
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest

from attacks.key_recovery_modules.ddt_filter import (
    _allowed_differences, conditional_target_side_filter_for_record)
from attacks.key_recovery_modules.dynamic_greedy import (
    _log2_sum_exp2, with_right_pair)
from attacks.key_recovery_modules.propagation import (
    _rev, _set_to_val_mask, _xor_val_masks, boundary_pattern_bits)
from attacks.key_recovery_modules.report import n_is_upper_bound
from attacks.key_recovery_modules.trail import build_manual_trail
from operators.Sbox import PRESENT_Sbox
from variables.variables import Variable


# --- helpers -----------------------------------------------------------------

# PRESENT's S-box: the filters below are checked against the real operator, so the
# published 2+14+1 attack's per-S-box filters come from the same table the attack
# scripts use.
def _present_sbox():
    ins = [Variable(1, ID=f"i{i}") for i in range(4)]
    outs = [Variable(1, ID=f"o{i}") for i in range(4)]
    return PRESENT_Sbox(ins, outs, ID="SB")


def _record(side, in_fixed, in_active, out_fixed, out_active, round_nb=1):
    """A minimal active-S-box record, as the propagation walk emits them."""
    return {"op": _present_sbox(), "side": side, "round": round_nb, "layer": 1,
            "input_var_ids": [f"i{i}" for i in range(4)],
            "output_var_ids": [f"o{i}" for i in range(4)],
            "input_positions": [0, 1, 2, 3],
            "input_fixed_mask": in_fixed, "input_active_mask": in_active,
            "output_fixed_mask": out_fixed, "output_active_mask": out_active}


# --- with_right_pair ---------------------------------------------------------

def test_with_right_pair_adds_exactly_one_pair():
    # 2^3 wrong pairs + the right one = 9
    assert with_right_pair(3.0) == pytest.approx(math.log2(9.0))


def test_with_right_pair_never_empties_the_set():
    # The sieve removed every wrong pair; the right pair still passes it.
    assert with_right_pair(-30.0) == pytest.approx(0.0, abs=1e-8)


def test_with_right_pair_is_inert_in_the_valid_regime():
    # Above ~2^53 one extra pair is not representable, so it must be a no-op --
    # this is what makes the correction safe for every published attack.
    assert with_right_pair(60.0) == 60.0


# --- log2 sum of step works --------------------------------------------------

def test_log2_sum_exp2_matches_the_direct_sum():
    works = [4.0, 5.58, 6.81, 7.91, 8.95, 9.98]      # the default PRESENT run
    assert _log2_sum_exp2(works) == pytest.approx(
        math.log2(sum(2.0 ** w for w in works)), abs=1e-12)


def test_log2_sum_exp2_survives_beyond_float_range():
    # 2.0 ** 2000 raises OverflowError; the log-space sum must not.
    assert _log2_sum_exp2([2000.0, 2000.0]) == pytest.approx(2001.0)


# --- DDT filters -------------------------------------------------------------

def test_allowed_differences_respects_fixed_and_active():
    # bit 0 forced, bits 0 and 1 active -> {01, 11}
    assert _allowed_differences(0b01, 0b11, 4) == [0b01, 0b11]


def test_rev_is_an_involution():
    for mask in range(16):
        assert _rev(_rev(mask, 4), 4) == mask


def test_fully_active_sbox_filters_nothing_extra():
    # Both sides completely unconstrained: knowing the observed side tells us
    # nothing more, so the filter is 0 bits.
    rec = _record("backward", 0, 0b1111, 0, 0b1111)
    assert conditional_target_side_filter_for_record(rec) == pytest.approx(0.0)


def test_fixed_output_difference_filters_by_the_ddt():
    # PT-side box: input difference free, output pinned to a single value. Of the
    # 16*16 = 256 pairs allowed by the input side, only those reaching that one
    # output difference survive.
    rec = _record("backward", 0, 0b1111, 0b1000, 0b1000)
    ddt = rec["op"].computeDDT()
    dy = _rev(0b1000, 4)
    survive = sum(ddt[dx][dy] for dx in range(16))
    eligible = sum(sum(row) for row in ddt)
    assert conditional_target_side_filter_for_record(rec) == pytest.approx(
        -math.log2(survive / eligible))


def test_impossible_transition_is_infinite():
    # A transition the DDT forbids rejects every pair.
    ddt = _present_sbox().computeDDT()
    dx, dy = next((dx, dy) for dx in range(1, 16) for dy in range(1, 16)
                  if ddt[dx][dy] == 0)
    rec = _record("backward", _rev(dx, 4), _rev(dx, 4), _rev(dy, 4), _rev(dy, 4))
    assert conditional_target_side_filter_for_record(rec) == math.inf


# --- boundary set size (d_in / d_out) ----------------------------------------

def test_boundary_pattern_bits_is_the_log_set_size_at_the_outermost_layer():
    # Two backward boxes at round 1 with 3 free input bits each -> |D_in| = 2^6.
    # The round-2 box is inside the extension and must not be counted.
    recs = [_record("backward", 0, 0b0111, 0, 0b1111, round_nb=1),
            _record("backward", 0, 0b0111, 0, 0b1111, round_nb=1),
            _record("backward", 0, 0b1111, 0, 0b1111, round_nb=2)]
    assert boundary_pattern_bits(recs, "backward") == pytest.approx(6.0)


def test_boundary_pattern_bits_ignores_the_other_side():
    assert boundary_pattern_bits([_record("backward", 0, 0b1111, 0, 0b1111)],
                                 "forward") is None


# --- the structure bound on N ------------------------------------------------

@pytest.mark.parametrize("name, p, d_in, expected", [
    # The three reproductions of published attacks stay silent: each has enough
    # data to fill whole structures, so N counts only pairs that exist.
    ("PRESENT-80 2+14+1", 62, 48, False),
    ("RECTANGLE-80 2+14+2", 62.83, 22, False),
    ("SKINNY-64-64 1+5+1", 24, 20, False),
    # These need fewer than one full structure, so N over-counts.
    ("GIFT-64/128 3+13+2", 62.0634, 64, True),
    ("PRESENT-80 1+4+0", 12, 18, True),
    ("AES-128 1+2+0", 30, 64, True),
    ("LED-64 1+2+0", 10, 46, True),
])
def test_n_is_upper_bound_on_the_shipped_attacks(name, p, d_in, expected):
    assert n_is_upper_bound(p, d_in) is expected, name


def test_n_is_upper_bound_boundary():
    # Exactly one structure (d_in == p + 1) still forms every pair N counts.
    assert n_is_upper_bound(10, 11) is False
    assert n_is_upper_bound(10, 12) is True


# --- word-difference mask algebra --------------------------------------------

def test_xor_val_masks_keeps_forced_bits_through_a_truncated_operand():
    # 0b1010 pinned, XOR-ed with an operand free only on bit 0: bits 1..3 stay
    # pinned to the XOR of the forced parts, bit 0 becomes free.
    assert _xor_val_masks([(0b1010, 0b1010), (0b0000, 0b0001)]) == (0b1010, 0b1011)


def test_xor_val_masks_of_pinned_operands_is_exact():
    assert _xor_val_masks([(0b1100, 0b1100), (0b1010, 0b1010)]) == (0b0110, 0b0110)


def test_set_to_val_mask_bounds_a_value_set():
    assert _set_to_val_mask({0b1010, 0b1011}) == (0b1010, 0b1011)


# --- manual trail ------------------------------------------------------------

def _layer(trail, round_nb, layer_nb):
    block = trail.data["trail_struct"]["functions"]["PERMUTATION"]
    return block[round_nb][layer_nb]


def test_manual_trail_bit_cipher_marks_the_active_bits():
    # PRESENT's published 14-round differential.
    trail = build_manual_trail(nbr_words=64, word_bitsize=1, R_d=14, weight=62,
                               delta_in=0x0700000000000700,
                               delta_out=0x0000000900000009)
    active_in = sorted(i for i, v in _layer(trail, 1, 0).items()
                       if v["bin_values"] == "1")
    active_out = sorted(i for i, v in _layer(trail, 14, 2).items()
                        if v["bin_values"] == "1")
    assert active_in == [8, 9, 10, 56, 57, 58]
    assert active_out == [0, 3, 32, 35]
    assert trail.data["diff_weight"] == 62


def test_manual_trail_word_cipher_keeps_the_word_difference_value():
    # A word cipher's nibble difference must survive as a value, not collapse to a
    # single "active" flag: the extension walk is seeded with it directly.
    trail = build_manual_trail(nbr_words=16, word_bitsize=4, R_d=5, weight=24,
                               delta_in=0x0000000000a00000,
                               delta_out=0x000b000000000000, last_layer=4)
    assert _layer(trail, 1, 0)[5]["bin_values"] == "1010"
    assert _layer(trail, 5, 4)[12]["bin_values"] == "1011"


def test_manual_trail_rejects_a_position_list_for_a_word_cipher():
    # A position carries no word difference value, so it cannot say WHICH nibble
    # difference is meant. Reading it as 1 would be silently wrong.
    with pytest.raises(ValueError, match="word_bitsize"):
        build_manual_trail(nbr_words=16, word_bitsize=4, R_d=5, weight=24,
                           delta_in=[5], delta_out=[12], last_layer=4)


def test_manual_trail_accepts_hex_and_binary_strings():
    from_int = build_manual_trail(nbr_words=8, word_bitsize=1, R_d=2, weight=4,
                                  delta_in=0b0101, delta_out=0b1000)
    from_str = build_manual_trail(nbr_words=8, word_bitsize=1, R_d=2, weight=4,
                                  delta_in="0x5", delta_out="0x8")
    assert _layer(from_int, 1, 0) == _layer(from_str, 1, 0)
    assert _layer(from_int, 2, 2) == _layer(from_str, 2, 2)


def test_manual_trail_boundaries_do_not_collide_for_a_one_round_distinguisher():
    trail = build_manual_trail(nbr_words=8, word_bitsize=1, R_d=1, weight=2,
                               delta_in=0b0001, delta_out=0b1000)
    assert _layer(trail, 1, 0)[0]["bin_values"] == "1"
    assert _layer(trail, 1, 2)[3]["bin_values"] == "1"
