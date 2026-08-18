"""
SKINNY-64-64 differential key recovery (searched distinguisher)
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


import attacks.attacks as attacks
from primitives.skinny import SKINNY_BLOCKCIPHER, SKINNY_PERMUTATION


def skinny_64_attack():
    R_d, r_b, r_f = 5, 1, 1

    cipher = SKINNY_BLOCKCIPHER(r=r_b + R_d + r_f, version=[64, 64])

    # No published distinguisher: search one over R_d rounds
    trail = None
    distinguisher = SKINNY_PERMUTATION(r=R_d, version=64)

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

    skinny_64_attack()
