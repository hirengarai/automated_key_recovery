"""
Test Autoguess on TWINE-80 Key Schedule (Key Bridging)

Reproduces the experiment from autoguess-without-sage:
  ciphers/T-TWINE/TWINE-80/tktwine80kb.py

25-round TWINE-80 key schedule: 21 subkey nibbles involved,
can be deduced from 19 nibbles (matching autoguess-without-sage result).
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import primitives.twine as twine
from attacks import attacks


# Build TWINE-80 cipher with 25 rounds
nbr_rounds = 25
cipher = twine.TWINE_BLOCKCIPHER(nbr_rounds, version=[64, 80])

KS = cipher.functions["KEY_SCHEDULE"]

# Subkey extraction indices for TWINE-80: [1, 3, 4, 6, 13, 14, 15, 16]
# RK[r][j] = KS.vars[r+1][0][rk_idx[j]]  (r+1 because OCP is 1-indexed)

rk_idx = [1, 3, 4, 6, 13, 14, 15, 16]

def rk_var(r_autoguess, j):
    """Get variable ID for subkey nibble j at autoguess round r."""
    ocp_round = r_autoguess + 1  # autoguess round 0 = OCP round 1
    return KS.vars[ocp_round][0][rk_idx[j]].ID

# Target subkeys (from tktwine80kb.py, R=25)
target_vars = []
# RK[0]: indices 0,1,2,3,5,6,7
target_vars += [rk_var(0, i) for i in [0, 1, 2, 3, 5, 6, 7]]
# RK[1]: indices 2,4,5,6
target_vars += [rk_var(1, i) for i in [2, 4, 5, 6]]
# RK[2]: indices 3,5
target_vars += [rk_var(2, i) for i in [3, 5]]
# RK[3]: index 1
target_vars += [rk_var(3, i) for i in [1]]
# RK[22]: index 7
target_vars += [rk_var(22, i) for i in [7]]
# RK[23]: indices 5,7
target_vars += [rk_var(23, i) for i in [5, 7]]
# RK[24]: indices 0,4,5,7
target_vars += [rk_var(24, i) for i in [0, 4, 5, 7]]

print(f"Number of target subkey nibbles: {len(target_vars)}")
print(f"Target variables: {target_vars[:5]}... (showing first 5)")

# Run guess-and-determine attack on the key schedule
result = attacks.guess_and_determine_attack(
    KS,
    name_prefix="TWINE80",
    target_vars=target_vars,
    solver='sat',
    preprocess=1,
    maxguess=19,
    maxsteps=2,
    timelimit=-1,
)
