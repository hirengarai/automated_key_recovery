"""
AES-128 differential key recovery (searched distinguisher, GF(2^8) MixColumns)
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


import attacks.attacks as attacks
from primitives.aes import AES_BLOCKCIPHER, AES_PERMUTATION


def aes_128_attack():
    # 1+3+1 is the meaningful 5-round shape but takes ~8 min; 1+2+0 runs in ~2
    R_d, r_b, r_f = 2, 1, 0

    cipher = AES_BLOCKCIPHER(r=r_b + R_d + r_f, version=[128, 128])

    # No published distinguisher: search one over R_d rounds
    trail = None
    distinguisher = AES_PERMUTATION(r=R_d)

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

    aes_128_attack()
