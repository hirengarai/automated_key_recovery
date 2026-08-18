"""
GIFT-64/128: sweep with a targeted security level BELOW the key size

`targeted_security` defaults to the key size, but it is a separate input for a
reason: an attack at 2^127 on a 128-bit key is not interesting, and a sweep that
reports it is answering the wrong question. Here it is set to 120, so the sweep
returns only attacks that beat exhaustive search by at least 8 bits. Rows above the
level are still listed in `results`, flagged `over`; they are just never chosen as
`best` and never appear in `valid_results`.

Nothing in THIS sweep exceeds 120, so the level does not exclude anything here --
`sweep_led_64.py` is where two splits actually land over budget and are dropped.
What GIFT does show is why a failed distinguisher is recorded rather than fatal:
OCP cannot serialise a GIFT trail (`TypeError: Object of type GIFT_Sbox is not JSON
serializable`), so `R_d = 4`, which has no pinned distinguisher, is skipped with
that reason on its row while `R_d = 13`, which has one, is estimated normally. The
failure is cached, so the other splits at R_d = 4 do not re-run a search already
known to fail.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from attacks.key_recovery_modules.auto_wrapper import auto_key_recovery
from primitives.gift import GIFT_BLOCKCIPHER, GIFT_PERMUTATION


def sweep_gift_64():
    def cipher_factory(r):
        return GIFT_BLOCKCIPHER(r=r, version=[64, 128])

    def perm_factory(r):
        return GIFT_PERMUTATION(r=r, version=64)

    result = auto_key_recovery(
        cipher_factory, perm_factory,
        key_bits=128,
        targeted_security=120,   # stricter than the 128-bit key
        r_b_values=(1, 2),
        r_d_values=(4, 13),
        r_f_values=(1, 2),
        # Chen-Zong-Dong 13-round differential (ICICS 2019, Table 8 / 5.2)
        manual_distinguishers={
            13: {"weight": 62.0634,
                 "delta_in": 0x0000000000000202,
                 "delta_out": 0x0000000500000005},
        },
        independent_round_keys=False,
        maxsteps=50,
        full_rounds=28,
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

    sweep_gift_64()
