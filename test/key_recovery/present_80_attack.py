"""
PRESENT-80 differential key recovery (Wang 14-round distinguisher)
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


import attacks.attacks as attacks
from attacks.key_recovery_modules.trail import build_manual_trail
from primitives.present import PRESENT_BLOCKCIPHER


def present_80_attack():
    # Round split: 17 attacked rounds
    R_d, r_b, r_f = 14, 2, 1

    cipher = PRESENT_BLOCKCIPHER(r=r_b + R_d + r_f, version=[64, 80], final_whitening=True)
    perm = cipher.functions["PERMUTATION"]

    # Published distinguisher; the trail's shape is read off the cipher
    trail = build_manual_trail(nbr_words=perm.nbr_words, word_bitsize=perm.word_bitsize,
                               last_layer=perm.nbr_layers - 1, R_d=R_d,
                               weight=62, delta_in=0x0700000000000700, delta_out=0x0000000900000009)
    distinguisher = None

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
    present_80_attack()
