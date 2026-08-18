"""
PRESENT-80: sweep the round split, report the best attack (defaults throughout)

The plainest use of `auto_key_recovery`: give it the combinations to try and let
every other choice default. "Best" defaults to the most rounds attacked, breaking
ties on the lowest time complexity, and the targeted security level defaults to the
key size, so no attack costing 2^80 or more is returned.

The published 14-round differential is pinned through `manual_distinguishers`, and
R_d = 4 alongside it is searched, so the sweep does both in one run. Pinning matters
here: searching a 14-round PRESENT trail costs far more than the key recovery built
on it, while a 4-round one takes seconds.

`2+14+1` is the published PRESENT-80 attack, so the sweep should select it and
report the same `T = 2^61.46` that `present_80_attack.py` produces on its own.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from attacks.key_recovery_modules.auto_wrapper import auto_key_recovery
from primitives.present import PRESENT_BLOCKCIPHER, PRESENT_PERMUTATION


def sweep_present_80():
    # PRESENT starts its round with AddRoundKey, so the final key addition has to
    # be appended for a reduced round count: final_whitening=True.
    def cipher_factory(r):
        return PRESENT_BLOCKCIPHER(r=r, version=[64, 80], final_whitening=True)

    def perm_factory(r):
        return PRESENT_PERMUTATION(r=r)

    result = auto_key_recovery(
        cipher_factory, perm_factory,
        key_bits=80,
        # The combinations to try: every (r_b, R_d, r_f) in the cross product.
        r_b_values=(2,),
        r_d_values=(4, 14),
        r_f_values=(0, 1),
        # Wang's 14-round differential, kept for the R_d it covers.
        manual_distinguishers={
            14: {"weight": 62,
                 "delta_in": 0x0700000000000700,
                 "delta_out": 0x0000000900000009},
        },
        independent_round_keys=False,
        full_rounds=31,          # PRESENT-80 is 31 rounds; longer splits are skipped
    )

    best = result["best"]
    if best is None:
        print("[TEST] no attack within the targeted security level")
    else:
        print(f"[TEST] best: {best['total_rounds']} rounds "
              f"(r_b={best['r_b']}, R_d={best['R_d']}, r_f={best['r_f']}), "
              f"T=2^{best['T_log2']}")
    return result


if __name__ == '__main__':

    sweep_present_80()
