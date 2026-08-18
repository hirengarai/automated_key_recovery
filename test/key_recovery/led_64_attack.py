"""
LED-64 differential key recovery (searched distinguisher, GF(2^4) MixColumnsSerial)
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


import attacks.attacks as attacks
from primitives.led import LED_BLOCKCIPHER, LED_PERMUTATION


def led_64_attack():
    # LED adds the key only every 4th round, so r_b must reach round 1
    R_d, r_b, r_f = 2, 1, 0

    cipher = LED_BLOCKCIPHER(r=r_b + R_d + r_f, version=[64, 64])

    # No published distinguisher: search one over R_d rounds
    trail = None
    distinguisher = LED_PERMUTATION(r=R_d)

    result = attacks.key_recovery_attack(
        cipher,
        goal="KEYRECOVERY_DIFF",
        R_d=R_d, r_b=r_b, r_f=r_f,
        trail=trail,
        distinguisher=distinguisher,
        config_model={
            "model_type": "sat",
            "sbox_form": "implication",
            "maxsteps": 40,
            "independent_round_keys": False,
        },
        config_solver={"solver": "cadical153"},
    )
    print(f"[TEST] Time complexity: 2^{result['T_log2']:.2f}, valid attack: {result['valid_attack']}")


if __name__ == '__main__':

    led_64_attack()
