"""
Differential key recovery: edit the parameters below and run this file
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


import attacks.attacks as attacks
from attacks.key_recovery_modules.auto_wrapper import auto_key_recovery
from attacks.key_recovery_modules.trail import build_manual_trail

# The cipher to attack. Any OCP block cipher with an S-box layer works; import its
# BLOCKCIPHER and PERMUTATION and set the two factories below.
from primitives.present import PRESENT_BLOCKCIPHER, PRESENT_PERMUTATION


def _as_tuple(value):
    """A split value, whether written as a single round count or a list."""
    return tuple(value) if isinstance(value, (list, tuple)) else (value,)


def run_attack():
    # PRESENT and RECTANGLE start their round with AddRoundKey, so the final key
    # addition has to be appended for a reduced round count: final_whitening=True.
    def cipher_factory(r):
        return PRESENT_BLOCKCIPHER(r=r, version=[64, 80], final_whitening=True)

    def perm_factory(r):
        return PRESENT_PERMUTATION(r=r)

    key_bits = 80

    # Round split: R_d rounds of distinguisher, r_b rounds before, r_f rounds after.
    # ANY of the three may be a list -- R_d = [4, 5, 6], r_f = [0, 1], ... -- and
    # every combination is then tried and the best attack reported.
    R_d = 4
    r_b = 1
    r_f = 0

    # Distinguisher: searched by default. To pin published ones, map R_d -> trail:
    #   published = {14: {"weight": 62, "delta_in": 0x0700000000000700,
    #                     "delta_out": 0x0000000900000009}}
    # Any R_d not listed is searched.
    published = None

    # Modelling and solver options
    independent_round_keys = False   # True: treat subkeys as independent
    maxsteps = 40                    # raise if AutoGuess runs out of steps

    # Used when a split value is a list: drop attacks costing more than
    # targeted_security bits (None = key_bits), and what "best" means.
    targeted_security = None
    objective = "max_rounds"         # "max_rounds" (then lowest time) | "min_time"
    full_rounds = None               # skip splits longer than the real cipher

    # Try every combination and report the best one
    if any(isinstance(v, (list, tuple)) for v in (R_d, r_b, r_f)):
        auto_key_recovery(cipher_factory, perm_factory, key_bits=key_bits,
                          targeted_security=targeted_security, objective=objective,
                          r_b_values=_as_tuple(r_b), r_f_values=_as_tuple(r_f),
                          r_d_values=_as_tuple(R_d),
                          manual_distinguishers=published,
                          independent_round_keys=independent_round_keys,
                          maxsteps=maxsteps, full_rounds=full_rounds)
        return

    # Build the cipher over all r_b + R_d + r_f rounds
    cipher = cipher_factory(r_b + R_d + r_f)
    perm = cipher.functions["PERMUTATION"]

    # Distinguisher: injected from a published trail, or searched. The trail's shape
    # is read off the cipher rather than declared.
    trail, distinguisher = None, None
    pinned = (published or {}).get(R_d)
    if pinned:
        trail = build_manual_trail(nbr_words=perm.nbr_words, word_bitsize=perm.word_bitsize,
                                   last_layer=perm.nbr_layers - 1, R_d=R_d,
                                   weight=pinned["weight"],
                                   delta_in=pinned["delta_in"],
                                   delta_out=pinned["delta_out"])
    else:
        distinguisher = perm_factory(R_d)

    # Run attack
    result = attacks.key_recovery_attack(
        cipher,
        goal="KEYRECOVERY_DIFF",
        R_d=R_d, r_b=r_b, r_f=r_f,
        trail=trail,
        distinguisher=distinguisher,
        config_model={
            "model_type": "sat",
            "sbox_form": "implication",
            "maxsteps": maxsteps,
            "independent_round_keys": independent_round_keys,
        },
        config_solver={"solver": "cadical153"},
    )
    print(f"[TEST] Time complexity: 2^{result['T_log2']:.2f}, valid attack: {result['valid_attack']}")


if __name__ == '__main__':

    run_attack()
