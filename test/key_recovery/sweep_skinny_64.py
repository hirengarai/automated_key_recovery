"""
SKINNY-64-64: sweep the DISTINGUISHER LENGTH, choosing by lowest complexity

Two things this one shows.

`R_d` is swept, not just where the distinguisher sits. The question "how long a
distinguisher can this cipher support?" is answered by giving `r_d_values` several
lengths; each is searched once and cached, so a length is never re-searched across
the splits that share it.

`objective="min_time"` replaces the default. The default is "most rounds attacked,
then lowest complexity", which answers "how far can I reach?"; `min_time` answers
"what is the cheapest attack available?" and will happily return a shorter one.
Both are read off the same set of results, so switching costs nothing.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from attacks.key_recovery_modules.auto_wrapper import auto_key_recovery
from primitives.skinny import SKINNY_BLOCKCIPHER, SKINNY_PERMUTATION


def sweep_skinny_64():
    def cipher_factory(r):
        return SKINNY_BLOCKCIPHER(r=r, version=[64, 64])

    def perm_factory(r):
        return SKINNY_PERMUTATION(r=r, version=64)

    result = auto_key_recovery(
        cipher_factory, perm_factory,
        key_bits=64,
        r_b_values=(1,),
        r_d_values=(5, 6),       # sweep the distinguisher LENGTH
        r_f_values=(0, 1),
        objective="min_time",    # cheapest attack, not the longest
        independent_round_keys=False,
        full_rounds=32,
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
    sweep_skinny_64()
