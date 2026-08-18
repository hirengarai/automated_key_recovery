"""Per-S-box differential filters.

A "filter" says how strongly an active S-box rejects WRONG pairs, in bits:
filter = f  means only 1 pair in 2^f survives the S-box's difference check
(the other 2^f - 1 are thrown away).

The whole file is three small ideas:
  1. list the difference values a pattern allows         -> _allowed_differences
  2. count how many value-pairs make a given transition  -> _count_pairs (via the DDT)
  3. filter = -log2( pairs that pass / pairs we started with )
"""

from __future__ import annotations

import math


# --- building blocks ---------------------------------------------------------

def _ddt(op):
    """The S-box Difference Distribution Table.

    ddt[dx][dy] = how many inputs x satisfy  S(x) XOR S(x XOR dx) = dy.
    Computed once, then cached on the operator.
    """
    if getattr(op, "ddt", None) is None:
        op.ddt = op.computeDDT()
    return op.ddt


def _rev(mask, n):
    """Bit-reverse an n-bit mask. Stored S-box masks are in variable order
    (bit i = input_vars[i]), but the DDT is in S-box VALUE order (in_0 is the MSB),
    so variable bit i is value bit n-1-i. Reverse before reading the DDT.
    No-op for fully-active nibbles; only matters for partially active S-boxes."""
    return sum(((mask >> i) & 1) << (n - 1 - i) for i in range(n))


def _allowed_differences(fixed_mask, active_mask, n_bits):
    """Every n-bit difference value that fits a truncated pattern.

      fixed_mask  : bits that are ALWAYS 1
      active_mask : bits that MAY be 1   (active but not fixed = free, 0 or 1)

    Naive on purpose: just try all 2^n values and keep the ones that fit
    (n is usually 4, so this is 16 cheap checks).
    """
    allowed = []
    for d in range(2 ** n_bits):
        has_every_fixed_bit = (d & fixed_mask) == fixed_mask   # all forced-1 bits present?
        stays_within_active = (d & ~active_mask) == 0          # no bit outside the active set?
        if has_every_fixed_bit and stays_within_active:
            allowed.append(d)
    return allowed


def _count_pairs(ddt, in_diffs, out_diffs):
    """How many value-pairs go from one of the allowed input differences to one
    of the allowed output differences -- just add up the DDT entries."""
    pairs = 0
    for dx in in_diffs:
        for dy in out_diffs:
            pairs += ddt[dx][dy]
    return pairs


# --- the live filter (used by the greedy) ------------------------------------

def conditional_target_side_filter_for_record(sbox):
    """Filter, in bits, for one active S-box -- the way the attack peels it.

    One side faces the DATA (plaintext/ciphertext) and we OBSERVE it; the other
    faces the distinguisher and we CHECK it against the trail:

        side == "forward"  (ciphertext side): observe OUTPUT, check INPUT
        side == "backward" (plaintext side):  observe INPUT,  check OUTPUT

        filter = -log2( pairs passing BOTH sides / pairs passing the OBSERVED side )
    """
    op    = sbox["op"]
    side  = sbox["side"]
    ddt   = _ddt(op)
    n_in  = op.input_bitsize
    n_out = op.output_bitsize

    in_diffs  = _allowed_differences(_rev(sbox.get("input_fixed_mask", 0), n_in),
                                     _rev(sbox.get("input_active_mask", 0), n_in), n_in)
    out_diffs = _allowed_differences(_rev(sbox.get("output_fixed_mask", 0), n_out),
                                     _rev(sbox.get("output_active_mask", 0), n_out), n_out)

    # pairs matching BOTH the input and output patterns
    pass_both_side = _count_pairs(ddt, in_diffs, out_diffs)

    # denominator: pairs matching only the side we already KNOW from the data,
    # leaving the other side free. The filter is how much ALSO matching the
    # trail's target side shrinks this.
    if side == "forward":     # CT side: output known -> keep output, let input be ANYTHING
        eligible = _count_pairs(ddt, range(2 ** n_in), out_diffs)
    else:                     # PT side: input known  -> keep input,  let output be ANYTHING
        eligible = _count_pairs(ddt, in_diffs, range(2 ** n_out))

    if eligible == 0:
        return 0.0                        # observed side allows nothing extra -> no filter
    if pass_both_side == 0:
        return math.inf                   # impossible transition -> rejects every pair
    filter_value = pass_both_side / eligible
    return max(-math.log2(filter_value), 0.0)
