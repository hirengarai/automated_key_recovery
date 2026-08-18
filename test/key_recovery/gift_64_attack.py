"""
GIFT-64/128 differential key recovery (Chen-Zong-Dong 13-round distinguisher)

A searched distinguisher would be preferable here, but OCP's trail persistence
cannot serialise a GIFT trail -- `attack_trace.save_json` raises
"Object of type GIFT_Sbox is not JSON serializable". The same failure occurs in
upstream OCP, so the published trail is injected instead.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


import attacks.attacks as attacks
from attacks.key_recovery_modules.trail import build_manual_trail
from primitives.gift import GIFT_BLOCKCIPHER


def gift_64_attack():
    # Round split: 18 attacked rounds
    R_d, r_b, r_f = 13, 3, 2

    cipher = GIFT_BLOCKCIPHER(r=r_b + R_d + r_f, version=[64, 128])
    perm = cipher.functions["PERMUTATION"]

    # Published distinguisher; the trail's shape is read off the cipher
    trail = build_manual_trail(nbr_words=perm.nbr_words, word_bitsize=perm.word_bitsize,
                               last_layer=perm.nbr_layers - 1, R_d=R_d,
                               weight=62.0634, delta_in=0x0000000000000202,
                               delta_out=0x0000000500000005)
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
            "maxsteps": 50,
            "independent_round_keys": False,
        },
        config_solver={"solver": "cadical153"},
    )
    print(f"[TEST] Time complexity: 2^{result['T_log2']:.2f}, valid attack: {result['valid_attack']}")


if __name__ == '__main__':

    gift_64_attack()
