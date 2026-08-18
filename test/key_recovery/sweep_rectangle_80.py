"""
RECTANGLE-80: sweep an EXPLICIT list of splits

`r_b_values x r_d_values x r_f_values` is a convenience; the combinations to try
can also be handed over one by one as `splits=[(r_b, R_d, r_f), ...]`. Use this
form when the cross product would waste time on shapes you already know are not
worth trying -- here only the splits that keep the extension balanced are listed,
rather than every pairing of r_b and r_f.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from attacks.key_recovery_modules.auto_wrapper import auto_key_recovery
from primitives.rectangle import RECTANGLE_BLOCKCIPHER, RECTANGLE_PERMUTATION


def sweep_rectangle_80():
    def cipher_factory(r):
        return RECTANGLE_BLOCKCIPHER(r=r, version=[64, 80], final_whitening=True)

    def perm_factory(r):
        return RECTANGLE_PERMUTATION(r=r)

    result = auto_key_recovery(
        cipher_factory, perm_factory,
        key_bits=80,
        # The combinations, given explicitly as (r_b, R_d, r_f).
        splits=[(1, 4, 1),
                (2, 4, 1),
                (1, 5, 1),
                (2, 5, 1)],
        independent_round_keys=True,
        maxsteps=100,            # RECTANGLE needs a larger determination budget
        full_rounds=25,
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

    sweep_rectangle_80()
