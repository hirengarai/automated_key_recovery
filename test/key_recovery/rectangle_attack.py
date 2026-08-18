"""
RECTANGLE-80 differential key recovery (design paper Appendix E distinguisher)
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


import attacks.attacks as attacks
from attacks.key_recovery_modules.trail import build_manual_trail
from primitives.rectangle import RECTANGLE_BLOCKCIPHER


def rectangle_attack():
    # Round split: 18 attacked rounds (Boura et al. Table 3 row 1)
    R_d, r_b, r_f = 14, 2, 2

    cipher = RECTANGLE_BLOCKCIPHER(r=r_b + R_d + r_f, version=[64, 80], final_whitening=True)
    perm = cipher.functions["PERMUTATION"]

    # Published distinguisher; the trail's shape is read off the cipher
    trail = build_manual_trail(nbr_words=perm.nbr_words, word_bitsize=perm.word_bitsize,
                               last_layer=perm.nbr_layers - 1, R_d=R_d,
                               weight=62.83, delta_in=0x0000010021000000, delta_out=0x0000100000020000)
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
            "maxsteps": 100,
            "independent_round_keys": True,
        },
        config_solver={"solver": "cadical153"},
    )
    print(f"[TEST] Time complexity: 2^{result['T_log2']:.2f}, valid attack: {result['valid_attack']}")


if __name__ == '__main__':

    rectangle_attack()
