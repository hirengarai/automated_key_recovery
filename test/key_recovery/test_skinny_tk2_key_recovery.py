"""
Test: Differential trail --> automatic key recovery pipeline on SKINNY-64/64.

SKINNY is an SPN tweakable block cipher with 4-bit S-boxes,
ShiftRows, MixColumns, and a lightweight key schedule (permutation only).
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from primitives.skinny import SKINNY_PERMUTATION, SKINNY_BLOCKCIPHER
from attacks import attacks


# --- Configuration ---
TRAIL_ROUNDS = 4  # rounds for the differential trail (distinguisher)
EXTENSION_BEFORE = 2  # extension rounds prepended
EXTENSION_AFTER = 3  # extension rounds appended
TOTAL_ROUNDS = EXTENSION_BEFORE + TRAIL_ROUNDS + EXTENSION_AFTER

# Distinguisher position within the full cipher (1-indexed)
DIST_START = EXTENSION_BEFORE + 1
DIST_END = EXTENSION_BEFORE + TRAIL_ROUNDS

print(f"  Trail rounds:    {TRAIL_ROUNDS}")
print(f"  Cipher rounds:   {TOTAL_ROUNDS}")
print(f"  Distinguisher:   rounds {DIST_START}–{DIST_END}")
print(f"  Extension:       {EXTENSION_BEFORE} before, {EXTENSION_AFTER} after")
print()

# Step 1: Find a differential trail on the permutation
perm = SKINNY_PERMUTATION(r=TRAIL_ROUNDS, version=64)

print(f"Searching for {TRAIL_ROUNDS}-round SKINNY-64 differential trail (SAT)...")
trails = attacks.diff_attacks(
    perm,
    goal="DIFFERENTIALPATH_PROB",
    config_model={"model_type": "sat"},
)

trail = trails[0] # take the best trail
print(f"  Found trail with weight: {trail.data.get('diff_weight')}")
print()

# Step 2: Build full block cipher and run key recovery
cipher = SKINNY_BLOCKCIPHER(r=TOTAL_ROUNDS, version=[64, 128])


print(f"Running key recovery on {TOTAL_ROUNDS}-round SKINNY-64/128...")
result = attacks.trail_to_key_recovery(
    trail,
    cipher,
    distinguisher_start=DIST_START,
    distinguisher_end=DIST_END,
    protect_all_targets=True,
    algebraic_layers=["MatrixLayer"],
    solver="sat",
    satsolver="cadical153",
    findmin=True,
    maxguess=50,
    maxsteps=50,
)

# # Step 3: Report number of guesses
# guessed = result.get("guessed_variables", [])
# print(f"Guesses: {len(guessed)}")
# for v in guessed:
#     print(f"  {v.ID}", end=",")
