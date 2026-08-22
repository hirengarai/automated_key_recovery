"""
TWINE-80: sweep with a CUSTOM definition of "best"

`objective` takes a callable as well as the two names. It receives one result row
and returns a sort key; lowest wins. The row is a plain dict with `r_b`, `R_d`,
`r_f`, `total_rounds`, `T_log2`, `C_KR_log2`, `N0_log2`, `d_in`, `d_out` and
`key_bits`, so any ranking expressible in those is available -- including one on
the key-recovery work alone, `lambda row: row["C_KR_log2"]`.

The one below asks for the best complexity PER ROUND ATTACKED -- an attack reaching
one more round is worth a good deal of extra work, but not unboundedly much. Neither
built-in objective says that: "max_rounds" takes the extra round at any price up to
the security level, and "min_time" refuses to pay for it at all.

TWINE is a Type-II generalised Feistel over 16 nibbles. Its diffusion is slow, so an
extension round activates far fewer S-boxes than an SPN of the same width, and the
sweep is correspondingly cheap.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from attacks.key_recovery_modules.auto_wrapper import auto_key_recovery
from primitives.twine import TWINE_BLOCKCIPHER, TWINE_PERMUTATION


def cost_per_round(row):
    """Lowest time complexity per round attacked; ties go to the longer attack."""
    return (row["T_log2"] / row["total_rounds"], -row["total_rounds"])


def sweep_twine_80():
    def cipher_factory(r):
        return TWINE_BLOCKCIPHER(r=r, version=[64, 80])

    def perm_factory(r):
        return TWINE_PERMUTATION(r=r)

    result = auto_key_recovery(
        cipher_factory, perm_factory,
        key_bits=80,
        r_b_values=(1,),
        r_d_values=(4, 5),
        r_f_values=(0, 1),
        objective=cost_per_round,     # a callable, not one of the two names
        independent_round_keys=False,
        full_rounds=36,
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

    sweep_twine_80()
