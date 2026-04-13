"""
Validate: 10-round AES-256 related-key attack (Biryukov et al., EUROCRYPT 2010, Section 5).

Paper's 10-round attack:
  - 8-round related-key differential distinguisher (paper rounds 2-9)
  - 1 extension round at the TOP (paper round 1)
  - 1 extension round at the BOTTOM (paper round 10, no MC + final ARK)
  - Paper Section 5.2 (chosen-ciphertext): recovers 5 key bytes (35 subkey bits)
    Guessed: K^9_12, K^10_{0,4,8,12}

OCP round mapping for r=10 (AES_BLOCKCIPHER):
  OCP round 1:  ARK + SB + SR + MC   = paper round 1   (TOP extension)
  OCP round 2:  ARK + SB + SR + MC   = paper round 2   (distinguisher start)
  ...
  OCP round 9:  ARK + SB + SR + MC   = paper round 9   (distinguisher end)
  OCP round 10: ARK + SB + SR + ID   = paper round 10  (BOTTOM extension, no MC)
  OCP round 11: ARK + ID + ID + ID   = final key add

  Distinguisher = OCP rounds 2-9 (paper rounds 2-9)
  Top extension = OCP round 1    (paper round 1)
  Bot extension = OCP rounds 10-11 (paper round 10 + final ARK)

  K^9  (paper) = vsk_10_0_*  (subkey in OCP round 10)
  K^10 (paper) = vsk_11_0_*  (subkey in OCP round 11, final ARK)
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from primitives.aes import AES_BLOCKCIPHER
from attacks import attacks


# --- Paper's expected answer (Section 5.2) ---
# K^9_12 + K^10_{0,4,8,12} = 5 key bytes
PAPER_GUESSED_COUNT = 5

# Active bytes at distinguisher boundaries:
# TOP boundary (input to distinguisher, paper's I^2):
#   The paper's differential has zero difference entering round 2,
#   so the top boundary has specific active bytes from extension round 1.
#   Paper Section 5: plaintext difference specified in 8 bytes (main diagonal).
#
# BOTTOM boundary (output of distinguisher, paper's I^9):
#   Same as 9-round case: Δ(I^8) pattern from the 8-round differential.
#   Basic: bytes 3,7,11,15. Truncated: bytes 3 + columns 1,2,3.

# For the bottom, use the basic active bytes
ACTIVE_BOTTOM = [3, 7, 11, 15]

# For the top, the paper's differential inserts differences on the main diagonal
# after round 1 (bytes 0,5,10,15 after ShiftRows). But the distinguisher
# input I^2 expects specific differences. Use all 16 bytes conservatively
# for the top since the top extension also needs partial encryption.
ACTIVE_TOP = list(range(16))

# --- Build 10-round AES-256 ---
print("10-round AES-256 related-key key recovery")
print("Based on Biryukov et al., EUROCRYPT 2010, Section 5")
print()

cipher = AES_BLOCKCIPHER(r=10, version=[128, 256])
perm = cipher.functions["PERMUTATION"]
R = perm.nbr_rounds   # 11
L = perm.nbr_layers   # 4

print(f"  OCP internal rounds: {R}")
print(f"  OCP round 1       = paper round 1  (top extension)")
print(f"  OCP rounds 2-9    = paper rounds 2-9 (distinguisher)")
print(f"  OCP round 10      = paper round 10 (bottom extension, no MC)")
print(f"  OCP round 11      = final ARK")
print()

# --- Known: plaintext + ciphertext ---
# Top extension: attacker knows plaintext (input to round 1)
known_pt = [perm.vars[1][0][i].ID for i in range(16)]
# Bottom extension: attacker knows ciphertext (output of round 11)
known_ct = [perm.vars[R][L][i].ID for i in range(16)]
known_vars = list(dict.fromkeys(known_pt + known_ct))

# --- Targets ---
# The paper's top extension doesn't need key guessing — the attacker
# controls the plaintext difference structure, so the state entering
# the distinguisher is known from the plaintext side.
# Only the BOTTOM boundary needs key guessing (partial decryption from CT).
target_top = []  # Paper handles top via plaintext structure, not key guessing
target_bottom = [perm.vars[10][0][i].ID for i in ACTIVE_BOTTOM]
target_vars = list(dict.fromkeys(target_top + target_bottom))

# --- Not guessed: only key/subkey variables may be guessed ---
known_set = set(known_vars)
target_set = set(target_vars)
not_guessed = [
    v for v in cipher.vars_dictionary
    if not v.startswith("vk_") and not v.startswith("vsk_")
    and v not in known_set and v not in target_set
]

# --- Skip distinguisher + top extension in PERMUTATION ---
# Top extension (round 1) is handled by plaintext structure
# Distinguisher = OCP rounds 2-9
# Only model bottom extension (rounds 10-11)
skip_rounds = {"PERMUTATION": list(range(1, 10))}

print(f"  Known (PT + CT): {len(known_vars)} vars")
print(f"  Targets (top + bottom boundary): {len(target_vars)} vars")
print(f"    Top targets (round 2 input):  {len(target_top)}")
print(f"    Bottom targets (round 10 input): {len(target_bottom)}")
print(f"  Not guessed: {len(not_guessed)} vars")
print(f"  Skipping PERMUTATION rounds 2-9 (distinguisher)")
print()

# --- Run AutoGuess ---
print("Running AutoGuess...")
result = attacks.guess_and_determine_attack(
    cipher,
    known_vars=known_vars,
    target_vars=target_vars,
    not_guessed_vars=not_guessed,
    protect_all_targets=True,
    name_prefix="aes256_rk_10round_check",
    skip_rounds=skip_rounds,
    solver="sat",
    satsolver="cadical153",
    findmin=True,
    maxguess=10,
    maxsteps=30,
)

# --- Analyze results ---
guessed = result.get("guessed_variables", [])
print(f"Guesses: {len(guessed)} (paper: {PAPER_GUESSED_COUNT})")
for v in guessed:
    print(f"  {v.ID}")
