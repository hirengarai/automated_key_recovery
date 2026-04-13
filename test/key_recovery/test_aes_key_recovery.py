"""
Test: Differential trail --> automatic key recovery pipeline on AES-128.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from primitives.aes import AES_PERMUTATION, AES_BLOCKCIPHER
from attacks import attacks


perm = AES_PERMUTATION(r=1)

trails = attacks.diff_attacks(
    perm,
    goal="DIFFERENTIALPATH_PROB",
    config_model={"model_type": "sat"}
)

trail = trails[0]
# trail.print_trail(show_mode=2)

cipher = AES_BLOCKCIPHER(r=2, version=[128, 128])

result = attacks.trail_to_key_recovery(
    trail,
    cipher,
    protect_all_targets=True,
    distinguisher_start=1,
    distinguisher_end=1,
    findmin=True,
    solver="sat",
    maxguess=16,
    maxsteps=25,
)

# guessed = result.get("guessed_variables", [])
# print(f"Guesses: {len(guessed)}")
# for v in guessed:
#     print(f"  {v.ID}")
