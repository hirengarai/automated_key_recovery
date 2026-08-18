"""
LED-64: sweep, and read the FULL result rather than only the winner

`auto_key_recovery` returns every split it tried, not just the best one:

    {"cipher", "targeted_security", "best", "results", "valid_results"}

`results` holds one plain dict per split -- over-budget ones flagged `valid=False`,
failed and skipped ones carrying a `skipped` reason string instead of numbers -- so
the sweep can be driven from a script and its output kept, compared or written to
JSON without re-running anything. `best` is only `min(valid_results, key=objective)`,
and re-ranking under a different objective needs no further solving.

This script prints the whole table, then asks the same results a second question
under a different objective, to show that ranking is separate from measuring.

LED adds the key only every 4th round, so `r_b` must reach round 1 for the extension
to carry a subkey at all -- which is why r_b is not swept here.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from attacks.key_recovery_modules.auto_wrapper import _pick_best, auto_key_recovery
from primitives.led import LED_BLOCKCIPHER, LED_PERMUTATION


def sweep_led_64():
    def cipher_factory(r):
        return LED_BLOCKCIPHER(r=r, version=[64, 64])

    def perm_factory(r):
        return LED_PERMUTATION(r=r)

    result = auto_key_recovery(
        cipher_factory, perm_factory,
        key_bits=64,
        r_b_values=(1,),
        r_d_values=(2, 3),
        r_f_values=(0, 1),
        independent_round_keys=False,
        full_rounds=32,
    )

    print("\nEvery split tried:")
    for row in result["results"]:
        tag = f"{row['r_b']}+{row['R_d']}+{row['r_f']}"
        if "skipped" in row:
            print(f"  {tag:<10} skipped: {row['skipped']}")
        else:
            print(f"  {tag:<10} T=2^{row['T_log2']:<9} d_in={row['d_in']:g} "
                  f"d_out={row['d_out']:g}  {'valid' if row['valid'] else 'over budget'}")

    # The same measurements, ranked a second way -- no solving involved.
    if result["valid_results"]:
        cheapest = _pick_best(result["valid_results"], "min_time")
        print(f"\n  max_rounds picks {result['best']['total_rounds']} rounds "
              f"at T=2^{result['best']['T_log2']}")
        print(f"  min_time   picks {cheapest['total_rounds']} rounds "
              f"at T=2^{cheapest['T_log2']}")

    best = result["best"]
    if best is None:
        print("[TEST] no attack within the targeted security level")
    else:
        print(f"[TEST] best: {best['total_rounds']} rounds "
              f"(r_b={best['r_b']}, R_d={best['R_d']}, r_f={best['r_f']}), "
              f"T=2^{best['T_log2']}")
    return result


if __name__ == '__main__':

    sweep_led_64()
