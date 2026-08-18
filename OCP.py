"""
This module provides usage examples for the SPECK primitive and SPECK block cipher, including:

1. Generating software implementations and visualizations
2. Conducting differential cryptanalysis using MILP and SAT methods
3. Conducting guess-and-determine attacks using AutoGuess
4. Conducting integral cryptanalysis using MILP methods
5. Estimating differential key-recovery attacks using AutoGuess

Note:
For examples of other ciphers, refer to the following folders:
- test/implementation
- test/differential_cryptanalysis
- test/autoguess
- test/key_recovery
"""

from pathlib import Path

from kiwisolver import Variable
import implementations.implementations as imp
import visualisations.visualisations as vis
import attacks.attacks as attacks

FILES_DIR = Path("files")
FILES_DIR.mkdir(parents=True, exist_ok=True)

# ********************* IMPLEMENTATIONS ********************* #
def test_python_imp(cipher): # Generate Python implementation and test it with the test vectors
    imp.generate_implementation(cipher, FILES_DIR / f"{cipher.name}.py", "python")
    if cipher.test_vectors==[]:
        print("warning: no test vector defined!")
        return False
    for tv in cipher.test_vectors: imp.test_implementation_python(cipher, cipher.name, tv[0], tv[1])

def test_python_unrolled_imp(cipher): # Generate unrolled Python implementation and test it with the test vectors
    imp.generate_implementation(cipher, FILES_DIR / f"{cipher.name}_unrolled.py", "python", True)
    if cipher.test_vectors==[]:
        print("warning: no test vector defined!")
        return False
    for tv in cipher.test_vectors: imp.test_implementation_python(cipher, cipher.name + "_unrolled", tv[0], tv[1])

def test_c_imp(cipher): # Generate C implementation and test it with the test vectors
    imp.generate_implementation(cipher, FILES_DIR / f"{cipher.name}.c", "c")
    if cipher.test_vectors==[]:
        print("warning: no test vector defined!")
        return False
    for tv in cipher.test_vectors: imp.test_implementation_c(cipher, cipher.name, tv[0], tv[1])

def test_c_unrolled_imp(cipher): # Generate unrolled C implementation and test it with the test vectors
    imp.generate_implementation(cipher, FILES_DIR / f"{cipher.name}_unrolled.c", "c", True)
    if cipher.test_vectors==[]:
        print("warning: no test vector defined!")
        return False
    for tv in cipher.test_vectors: imp.test_implementation_c(cipher, cipher.name + "_unrolled", tv[0], tv[1])

def test_verilog_imp(cipher): # Generate Verilog implementation and test it with the test vectors
    imp.generate_implementation(cipher, FILES_DIR / f"{cipher.name}.sv", "verilog")
    if cipher.test_vectors==[]:
        print("warning: no test vector defined!")
        return False
    for tv in cipher.test_vectors: imp.test_implementation_verilog(cipher, cipher.name, tv[0], tv[1])

def test_verilog_unrolled_imp(cipher): # Generate unrolled Verilog implementation and test it with the test vectors
    imp.generate_implementation(cipher, FILES_DIR / f"{cipher.name}_unrolled.sv", "verilog", True)
    if cipher.test_vectors==[]:
        print("warning: no test vector defined!")
        return False
    for tv in cipher.test_vectors: imp.test_implementation_verilog(cipher, cipher.name + "_unrolled", tv[0], tv[1])

def test_all_implementations(cipher): # Generate all implementations
    #test_python_imp(cipher)
    test_python_unrolled_imp(cipher)
    #test_c_imp(cipher)
    test_c_unrolled_imp(cipher)
    #test_verilog_imp(cipher)
    #test_verilog_unrolled_imp(cipher)


# ********************* VISUALIZATIONS ********************* #
def test_visualisation(cipher): # Generate visualisation figure
    vis.generate_figure(cipher, FILES_DIR / f"{cipher.name}.pdf")

# ********************* Differential Cryptanalysis ********************* #
def test_diff_attack_milp(cipher):
    # Example: default parameters. Refer to test/differential_cryptanalysis/ for more available parameters.
    goal="DIFFERENTIALPATH_PROB"
    constraints=["INPUT_NOT_ZERO"]
    objective_target="OPTIMAL"
    show_mode=0
    config_model=None
    config_solver=None

    # Search for the differential trail
    trails = attacks.diff_attacks(cipher, goal=goal, constraints=constraints, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)

def test_diff_attack_sat(cipher):
    # Example: default parameters. Refer to test/differential_cryptanalysis/ for more available parameters.
    goal="DIFFERENTIALPATH_PROB"
    constraints=["INPUT_NOT_ZERO"]
    objective_target="OPTIMAL"
    show_mode=0
    config_model={"model_type": "sat"}
    config_solver=None

    # Search for the differential trail
    trails = attacks.diff_attacks(cipher, goal=goal, constraints=constraints, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)


# ********************* Linear Cryptanalysis ********************* #
def test_linear_attack_milp(cipher):
    # Example: default parameters. Refer to test/linear_cryptanalysis/ for more available parameters.
    goal="LINEARPATH_CORR"
    constraints=["INPUT_NOT_ZERO"]
    objective_target="OPTIMAL"
    show_mode=0
    config_model=None
    config_solver=None

    # Search for the linear trail
    trails = attacks.linear_attacks(cipher, goal=goal, constraints=constraints, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)

def test_linear_attack_sat(cipher):
    # Example: default parameters. Refer to test/linear_cryptanalysis/ for more available parameters.
    goal="LINEARPATH_CORR"
    constraints=["INPUT_NOT_ZERO"]
    objective_target="OPTIMAL"
    show_mode=0
    config_model={"model_type": "sat"}
    config_solver=None

    # Search for the linear trail
    trails = attacks.linear_attacks(cipher, goal=goal, constraints=constraints, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)


# ********************* Guess-and-Determine ********************* #
def test_gd_attack_sat(cipher, known_vars, objective_target="EXISTENCE", config_model=None, config_solver=None):
    # Example: default parameters. Refer to test/autoguess/ for more available parameters.
    goal="GUESSBASIS"
    show_mode=1
    if config_model is None:
        config_model={}
    else:
        config_model=dict(config_model)
    config_model.setdefault("model_type", "sat")

    # Search for the guess basis
    result = attacks.guess_and_determine_attack(cipher, goal=goal, known_vars=known_vars, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)
    print(f"[TEST] Guess basis ({len(result['guessed_variables'])}): {[v.ID for v in result['guessed_variables']]}")
    return result


# ********************* Integral Cryptanalysis ********************* #
def test_integral_attack_milp(cipher, constant_bits, config_model=None, config_solver=None):
    # Example: two-subset integral distinguisher search using MILP.
    goal="INTEGRAL_TWOSUBSET"
    constraints=["TWO_SUBSET_INIT"]
    objective_target="EXISTENCE"
    show_mode=2
    if config_model is None:
        config_model={}
    else:
        config_model=dict(config_model)
    config_model.setdefault("constant_bits", constant_bits)
    config_model.setdefault("filename", str(FILES_DIR / f"{cipher.name}_INTEGRAL_TWOSUBSET_milp_model.lp"))
    if config_solver is None:
        config_solver={"solver": "DEFAULT", "solution_number": 1, "OutputFlag": 0}

    # Search for the integral distinguisher
    distinguishers = attacks.integral_attacks(cipher, goal=goal, constraints=constraints, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)
    for distinguisher in distinguishers:
        print(f"[TEST] Balanced bits: {distinguisher.data['balanced_bits']}")
    return distinguishers


# ********************* Key Recovery ********************* #
def test_kr_attack(cipher, R_d, r_b, r_f, trail, config_model=None, config_solver=None):
    # Example: default parameters. Refer to test/key_recovery/ for more available parameters.
    goal="KEYRECOVERY_DIFF"
    objective_target="OPTIMAL"
    show_mode=0

    # Estimate the cost of the key-recovery attack built on the distinguisher
    result = attacks.key_recovery_attack(cipher, goal=goal, R_d=R_d, r_b=r_b, r_f=r_f, trail=trail, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)
    print(f"[TEST] Time complexity: 2^{result['T_log2']:.2f}, valid attack: {result['valid_attack']}")
    return result


if __name__ == "__main__":
    # import primitives.aes as aes
    # cipher = aes.AES_BLOCKCIPHER(version=[128,256])

    import primitives.speck as speck
    cipher = speck.SPECK_PERMUTATION(version=32)
    # cipher = speck.SPECK_BLOCKCIPHER(version=[32,64])

    # import primitives.simon as simon
    # cipher = simon.SIMON_BLOCKCIPHER(version=[32,64])

    test_all_implementations(cipher)
    test_visualisation(cipher)

    cipher = speck.SPECK_PERMUTATION(r=2, version=32)
    test_diff_attack_milp(cipher)
    test_diff_attack_sat(cipher)
    test_linear_attack_milp(cipher)
    test_linear_attack_sat(cipher)

    # AES guess-and-determine example: with plaintext and ciphertext known, guessing
    # 6 more words determines the whole 96-word state. "AT MOST 6" is used instead of
    # "OPTIMAL" because the minimisation loop takes ~64s to reach the same answer.
    import primitives.aes as aes
    aes_cipher = aes.AES_BLOCKCIPHER(2, [128, 128])
    aes_func = aes_cipher.functions["PERMUTATION"]
    aes_known = [v.ID for v in aes_func.vars[1][0]] + [v.ID for v in aes_func.vars[aes_func.nbr_rounds][1]]
    test_gd_attack_sat(aes_cipher, aes_known, objective_target="AT MOST 6",
                       config_model={"skip_rounds": [2], "maxsteps": 14})

    # PRESENT integral attack example. This MILP example is slower than the default demos.
    import primitives.present as present
    present_cipher = present.PRESENT_PERMUTATION(r=9)
    present_config_model={
        "model_params": {"PRESENT_Sbox": {"tool_type": "polyhedron"}},
        "filename": str(FILES_DIR / "9round_PRESENT_PERM_INTEGRAL_TWOSUBSET_milp_model.lp"),
    }
    test_integral_attack_milp(present_cipher, [60, 61, 62, 63], config_model=present_config_model)

    # PRESENT-80 key-recovery example: Wang's 14-round differential, extended by one
    # round on the plaintext side only. r_f=0 keeps this to two active S-boxes; the
    # published 2+14+1 attack lives in test/key_recovery/present_80_attack.py.
    from attacks.key_recovery_modules.trail import build_manual_trail
    kr_cipher = present.PRESENT_BLOCKCIPHER(r=15, version=[64, 80])
    kr_trail = build_manual_trail(nbr_words=64, word_bitsize=1, R_d=14, weight=62,
                                  delta_in=0x0700000000000700, delta_out=0x0000000900000009,
                                  last_layer=2)
    test_kr_attack(kr_cipher, R_d=14, r_b=1, r_f=0, trail=kr_trail,
                   config_model={"sbox_form": "implication", "maxsteps": 40,
                                 "independent_round_keys": False},
                   config_solver={"solver": "cadical153"})
