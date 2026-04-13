import time

import attacks.differential_cryptanalysis as diff
import attacks.linear_cryptanalysis as linear
from tools.relation_generator import generate_relations
from tools.autoguess_wrapper import run_autoguess

# **************************************************************************** #
# This module provides a high-level attack interfaces, including:
# 1. differential attacks
# 2. linear attacks
# 3. guess-and-determine attacks (via AutoGuess)
# 4. differential key recovery (trail --> AutoGuess pipeline)
# **************************************************************************** #


# =================== Differential Attacks ===================
def diff_attacks(cipher, goal="DIFFERENTIALPATH_PROB", constraints=["INPUT_NOT_ZERO"], objective_target="OPTIMAL", show_mode=0, config_model=None, config_solver=None):
    time_start = time.time()

    if goal in ["DIFFERENTIAL_SBOXCOUNT", "DIFFERENTIALPATH_PROB", "DIFFERENTIAL_PROB", "TRUNCATEDDIFF_SBOXCOUNT"]:
        trails = diff.search_diff_trail(cipher, goal=goal, constraints=constraints, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)
    else:
        raise ValueError(f"[WARNING] Invalid goal: {goal}.")

    print(f"--- Total Time ---: {time.time() - time_start:.2f} seconds")
    return trails


# =================== Linear Attacks ===================
def linear_attacks(cipher, goal="LINEARPATH_CORRE", constraints=["INPUT_NOT_ZERO"], objective_target="OPTIMAL", show_mode=0, config_model=None, config_solver=None):
    time_start = time.time()

    if goal in ["LINEAR_SBOXCOUNT", "LINEARPATH_CORRE", "LINEARHULL_CORRE", "TRUNCATEDLINEAR_SBOXCOUNT"]:
        trails = linear.search_linear_trail(cipher, goal=goal, constraints=constraints, objective_target=objective_target, show_mode=show_mode, config_model=config_model, config_solver=config_solver)
    else:
        raise ValueError(f"[WARNING] Invalid goal: {goal}.")

    print(f"--- Total Time ---: {time.time() - time_start:.2f} seconds")
    return trails


# =================== Guess-and-Determine Attacks ===================
def guess_and_determine_attack(
    cipher_or_function,
    *,
    # Variable sections
    known_vars=None,
    target_vars=None,
    not_guessed_vars=None,
    protect_all_targets=False,
    # Relation generation options
    name_prefix=None,
    skip_layers=None,
    skip_ops=None,
    skip_rounds=None,
    skip_functions=None,
    flat_sbox=True,
    algebraic_layers=None,
    perm_rename=True,
    rot_rename=True,
    gf2linear_rename=True,
    output_file=None,
    canonical=True,
    cross_round_dir=False,
    bridge_skipped_rounds=True,
    # AutoGuess solver options
    solver="sat",
    findmin=False,
    maxguess=None,
    maxsteps=None,
    reducebasis=False,
    drawgraph=True,
    satsolver="cadical153",
    smtsolver="z3",
    cpsolver="cp-sat",
    milpdirection="min",
    cpoptimization=1,
    timelimit=-1,
    threads=0,
    preprocess=0,
    tikz=0,
    dglayout="dot",
    log=0,
):
    """
    Run a guess-and-determine attack on an OCP cipher or function.

    This combines two steps:
      1. Generate a relation file from the cipher/function (relation_generator)
      2. Solve it with AutoGuess to find a minimal guess basis

    Automatically detects whether the input is a full cipher (has .functions)
    or a single function (has .constraints directly).

    Parameters
    ----------
    cipher_or_function : Cipher or Function object from OCP.
        Pass a full cipher or a single function (e.g. cipher.functions["KEY_SCHEDULE"]).

    --- Variable sections ---

    known_vars : list of str, optional
        Variable IDs that are initially known to the attacker (e.g. plaintext,
        ciphertext bytes). These don't need to be guessed or determined.

    target_vars : list of str, optional
        Variable IDs that must be determined by the end. The solver finds the
        minimum set of guesses needed to determine all targets.

    not_guessed_vars : list of str, optional
        Variable IDs that the solver is forbidden from guessing. Useful for
        key recovery where only key variables (vk_*) should be guessable,
        so all state variables (vs_*) are placed here.

    --- Relation generation options ---

    name_prefix : str, optional
        Prefix for the output relation/result filenames.

    skip_layers : list of str, optional
        Layer class names to skip entirely (e.g. ["AddConstantLayer"]).
        No relations are emitted for these layers.

    skip_ops : list of str, optional
        Operator names to skip (e.g. ["XOR"]). Finer than skip_layers.

    skip_rounds : list of int or dict, optional
        Rounds to skip. If a flat list, applies to all functions.
        If a dict keyed by function name (e.g. {"PERMUTATION": [1, 2]}),
        each function gets its own skip list — functions not in the dict
        skip nothing. Useful for skipping distinguisher rounds while
        keeping key schedule relations.

    skip_functions : list of str, optional
        Function names to skip entirely (e.g. ["SUBKEYS"]).

    flat_sbox : bool, default True
        If True, emit S-box as a flat lookup table (one relation per
        input/output pair). If False, emit the S-box's internal Boolean
        equations.

    algebraic_layers : list of str, optional
        Layer class names to emit algebraically instead of as lookup tables
        (e.g. ["MatrixLayer"] for MixColumns). Produces XOR-based relations
        over GF(2) instead of word-level table relations.

    perm_rename : bool, default True
        If True, collapse permutation layers (ShiftRows) by renaming
        variables instead of emitting identity relations.

    rot_rename : bool, default True
        If True, collapse rotation operators by renaming variables.

    gf2linear_rename : bool, default True
        If True, collapse GF(2)-linear operators by renaming variables.

    output_file : str, optional
        Explicit path for the relation file. If None, auto-generated from
        cipher name and prefix.

    canonical : bool, default True
        If True, sort variables within each relation alphabetically for
        consistent output.

    cross_round_dir : bool, default False
        If True, emit cross-round linking relations (connecting last layer
        of round R to first layer of round R+1).

    --- AutoGuess solver options ---

    solver : str, default "sat"
        Solver backend: 'sat', 'milp', 'smt', 'cp', 'mark', 'elim',
        or 'propagate'. SAT (via CaDiCaL) is fastest for most problems.

    findmin : bool, default False
        If True, iteratively search for the minimum number of guesses
        (binary search on maxguess). Slower but gives optimal result.

    maxguess : int, optional
        Upper bound on number of guessed variables. The solver will find
        a solution with at most this many guesses, or report UNSAT.

    maxsteps : int, optional
        Maximum determination depth (number of propagation steps / state
        copies). Higher values allow longer determination chains but
        increase solver time.

    reducebasis : bool, default False
        If True, try to reduce the guess basis after solving.

    drawgraph : bool, default True
        If True, generate a PDF graph of the determination flow
        (requires Graphviz).

    satsolver : str, default "cadical153"
        PySAT solver name (e.g. "cadical153", "glucose4", "minisat22").

    smtsolver : str, default "z3"
        SMT solver name (only used when solver="smt").

    cpsolver : str, default "cp-sat"
        CP solver name (only used when solver="cp").

    milpdirection : str, default "min"
        Optimization direction for MILP solver: 'min' or 'max'.
        Only used when solver="milp".

    timelimit : int, default -1
        Solver time limit in seconds. -1 means no limit.

    preprocess : int, default 0
        Preprocessing level for the solver (0 = none).

    log : int, default 0
        Logging verbosity for AutoGuess (0 = quiet, higher = more output).

    Returns
    -------
    dict
        Result dictionary containing OCP Variable objects:
        - 'outputfile': path to the AutoGuess output file
        - 'cipher': the cipher/function object passed in
        - 'known_variables': list of Variable objects initially known
        - 'target_variables': list of Variable objects targeted
        - 'guessed_variables': list of Variable objects that were guessed
        - 'determination_steps': list of dicts with 'step' and 'determined_vars'

    Examples
    --------
    # Key schedule attack on SKINNY
    KS = cipher.functions["KEY_SCHEDULE"]
    result = attacks.guess_and_determine_attack(
        KS,
        target_vars=[KS.vars[r][5][i].ID for r, idxs in specs.items() for i in idxs],
        skip_rounds=list(range(1, 17)),
        solver='cp',
        maxguess=25,
        maxsteps=12,
    )

    # Full cipher attack with findmin
    result = attacks.guess_and_determine_attack(
        aes_cipher,
        known_vars=['vs_1_0_0', ...],
        target_vars=['vs_2_4_0', ...],
        solver='sat',
        findmin=True,
    )
    """
    time_start = time.time()

    # Auto-detect function_mode: functions have .constraints directly,
    # ciphers have .functions dict
    function_mode = not hasattr(cipher_or_function, "functions")

    # Prevent trivial solution: ensure at least some targets can't be guessed.
    # protect_all_targets=True: all targets are protected (for key recovery)
    # protect_all_targets=False: only first target is protected (default)
    if target_vars:
        ng = set(not_guessed_vars or [])
        if protect_all_targets:
            ng.update(target_vars)
        elif not ng.intersection(target_vars):
            ng.add(target_vars[0])
        not_guessed_vars = list(ng)

    # Build output filename with name_prefix if provided
    if output_file is None and name_prefix:
        name = getattr(cipher_or_function, "name", "function" if function_mode else "cipher")
        rounds = getattr(cipher_or_function, "nbr_rounds", None)
        fname = f"relations_{name_prefix}_{name}"
        if rounds is not None:
            fname += f"_{rounds}r"
        output_file = fname + ".txt"

    # Step 1: Generate relation file
    generate_relations(
        cipher_or_function,
        function_mode=function_mode,
        known=known_vars,
        target=target_vars,
        not_guessed=not_guessed_vars,
        output_file=output_file,
        skip_layers=skip_layers,
        skip_ops=skip_ops,
        skip_rounds=skip_rounds,
        skip_functions=skip_functions,
        flat_sbox=flat_sbox,
        algebraic_layers=algebraic_layers,
        perm_rename=perm_rename,
        rot_rename=rot_rename,
        gf2linear_rename=gf2linear_rename,
        canonical=canonical,
        cross_round_dir=cross_round_dir,
        bridge_skipped_rounds=bridge_skipped_rounds,
    )

    # Resolve output_file to absolute path (same logic as generate_relations)
    from pathlib import Path
    if output_file is None:
        name = getattr(cipher_or_function, "name", "cipher")
        rounds = getattr(cipher_or_function, "nbr_rounds", None)
        fname = f"relations_{name}"
        if rounds is not None:
            fname += f"_{rounds}r"
        output_file = fname + ".txt"
    if not Path(output_file).is_absolute():
        project_root = Path(__file__).resolve().parents[1]
        output_dir = project_root / "test" / "autoguess" / "files"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = str(output_dir / output_file)

    # Step 2: Run AutoGuess
    # Derive output name from input relation file
    ag_outputfile = str(Path(output_file).parent / Path(output_file).stem.replace("relations_", "output_"))
    result = run_autoguess(
        inputfile=output_file,
        cipher_or_function=cipher_or_function,
        outputfile=ag_outputfile,
        solver=solver,
        findmin=findmin,
        maxguess=maxguess,
        maxsteps=maxsteps,
        reducebasis=reducebasis,
        known=known_vars,
        drawgraph=drawgraph,
        satsolver=satsolver,
        smtsolver=smtsolver,
        cpsolver=cpsolver,
        milpdirection=milpdirection,
        cpoptimization=cpoptimization,
        timelimit=timelimit,
        threads=threads,
        preprocess=preprocess,
        tikz=tikz,
        dglayout=dglayout,
        log=log,
    )

    print(f"--- Total Time ---: {time.time() - time_start:.2f} seconds")
    return result


# =================== Differential Key Recovery ===================
def _extract_active_positions(trail_struct, func_name, round_nb, layer_nb, nbr_words):
    """
    Extract word positions that have non-zero difference from a trail structure.

    Returns a list of integer word indices where bin_values contains '1'.
    """
    active = []
    layer_data = trail_struct["functions"][func_name][round_nb][layer_nb]
    for i in range(nbr_words):
        if '1' in layer_data[i]['bin_values']:
            active.append(i)
    return active


def trail_to_key_recovery(
    trail,
    cipher,
    distinguisher_start=1,
    distinguisher_end=None,
    # Relation generation options
    skip_layers=None,
    algebraic_layers=None,
    flat_sbox=True,
    perm_rename=True,
    rot_rename=True,
    gf2linear_rename=True,
    canonical=True,
    cross_round_dir=False,
    # AutoGuess solver options
    solver="sat",
    findmin=False,
    maxguess=None,
    maxsteps=None,
    drawgraph=True,
    satsolver="cadical153",
    smtsolver="z3",
    cpsolver="cp-sat",
    milpdirection="min",
    cpoptimization=1,
    timelimit=-1,
    threads=0,
    preprocess=0,
    tikz=0,
    dglayout="dot",
    log=0,
    protect_all_targets=True,
):
    """
    Pipeline: differential trail --> automatic key recovery via AutoGuess.

    Given a differential trail (found on a permutation) and a block cipher
    (with key schedule), automatically determines the minimum number of key
    bits to guess for key recovery over the extension rounds.

    The trail covers a subset of the cipher's PERMUTATION rounds (the
    "distinguisher"). Rounds outside the distinguisher are "extension rounds"
    where the attacker partially encrypts/decrypts. AutoGuess finds which
    key bits must be guessed to compute the active state at the distinguisher
    boundary from plaintext/ciphertext.

    Parameters
    ----------
    trail : DifferentialTrail
        Differential trail found by OCP (e.g. via diff_attacks on a Permutation).

    cipher : Block_cipher (Primitive)
        The full block cipher with key schedule. Must have PERMUTATION,
        KEY_SCHEDULE, and SUBKEYS functions. The number of rounds should
        include both the distinguisher and extension rounds.

    distinguisher_start : int
        First round of the distinguisher in the cipher's PERMUTATION (1-indexed).
        Rounds 1 to distinguisher_start-1 are top extension rounds.

    distinguisher_end : int, optional
        Last round of the distinguisher in the cipher's PERMUTATION (1-indexed).
        Rounds distinguisher_end+1 to nbr_rounds are bottom extension rounds.
        Defaults to distinguisher_start + (trail rounds) - 1.

    solver, maxguess, maxsteps, etc.
        Forwarded to guess_and_determine_attack.

    Returns
    -------
    dict
        Contains all guess_and_determine_attack results plus:
        - 'trail': the input DifferentialTrail
        - 'distinguisher_start': int
        - 'distinguisher_end': int
        - 'input_active_positions': list of active word indices at top boundary
        - 'output_active_positions': list of active word indices at bottom boundary
        - 'trail_weight': differential weight (log2 probability)
        - 'key_guessing_complexity': number of guessed key bits (log2)
        - 'data_complexity': trail weight (log2)
        - 'total_complexity_log2': key_guessing + data complexity

    Example
    -------
    # Step 1: Find a differential trail on a permutation
    perm = skinny.SKINNY_PERMUTATION(r=8, version=64)
    trails = attacks.diff_attacks(perm, goal="DIFFERENTIALPATH_PROB")

    # Step 2: Build block cipher with 2 extra rounds for key recovery
    cipher = skinny.SKINNY_BLOCKCIPHER(r=10, version=[64, 64])

    # Step 3: Run key recovery (trail covers rounds 2-9, extensions at top/bottom)
    result = attacks.trail_to_key_recovery(
        trails[0], cipher,
        distinguisher_start=2, distinguisher_end=9,
        solver='sat', maxguess=20, maxsteps=50,
    )
    print(f"Key bits to guess: {result['key_guessing_complexity']}")
    for v in result['guessed_variables']:
        print(f"  Guess: {v.ID}")
    """
    time_start = time.time()

    trail_struct = trail.data['trail_struct']
    trail_functions = trail_struct.get("functions", {})

    # --- Identify the permutation function in the trail ---
    perm_name = None
    for fname in trail_functions:
        if isinstance(trail_functions[fname], dict) and "nbr_words" in trail_functions[fname]:
            perm_name = fname
            break
    assert perm_name is not None, "No permutation function found in trail_struct."

    # --- Determine trail round range ---
    trail_rounds = trail.data["rounds"][perm_name]
    if isinstance(trail_rounds, int):
        trail_rounds = list(range(1, trail_rounds + 1))
    R_trail = len(trail_rounds)

    if distinguisher_end is None:
        distinguisher_end = distinguisher_start + R_trail - 1

    # --- Validate ---
    assert "PERMUTATION" in cipher.functions, "Cipher must have a PERMUTATION function."
    perm_func = cipher.functions["PERMUTATION"]
    R_cipher = perm_func.nbr_rounds
    assert 1 <= distinguisher_start <= distinguisher_end <= R_cipher, \
        f"Invalid distinguisher range [{distinguisher_start}, {distinguisher_end}] for cipher with {R_cipher} rounds."
    assert distinguisher_start > 1 or distinguisher_end < R_cipher, \
        "No extension rounds: distinguisher covers the entire cipher. Nothing to recover."

    nbr_words = trail_functions[perm_name]["nbr_words"]
    cipher_last_layer = perm_func.nbr_layers

    # --- Find the last layer index in the trail ---
    # Look at the last trail round to find the highest layer number
    last_trail_round_data = trail_functions[perm_name][trail_rounds[-1]]
    trail_last_layer = max(k for k in last_trail_round_data if isinstance(k, int))

    # --- Extract active positions at distinguisher boundaries ---
    # Input boundary: first trail round, layer 0
    input_active = _extract_active_positions(
        trail_struct, perm_name, trail_rounds[0], 0, nbr_words
    )
    # Output boundary: last trail round, last layer
    output_active = _extract_active_positions(
        trail_struct, perm_name, trail_rounds[-1], trail_last_layer, nbr_words
    )

    # --- Skip distinguisher rounds (only model extension rounds) ---
    # Only skip PERMUTATION rounds; keep all KEY_SCHEDULE rounds
    # so the key chain stays connected.
    skip_perm_rounds = {"PERMUTATION": list(range(distinguisher_start, distinguisher_end + 1))}

    # --- Build known variable IDs ---
    # Only include plaintext/ciphertext for sides that have extension rounds.
    # Use actual internal PERMUTATION variables, not external interface vars.
    known_vars = []
    if distinguisher_start > 1:
        # Top extension exists → plaintext is known (round 1, layer 0)
        for i in range(perm_func.nbr_words):
            known_vars.append(perm_func.vars[1][0][i].ID)
    if distinguisher_end < R_cipher:
        # Bottom extension exists → ciphertext is known (last round, last layer)
        for i in range(perm_func.nbr_words):
            known_vars.append(perm_func.vars[R_cipher][cipher_last_layer][i].ID)
    # Deduplicate
    known_vars = list(dict.fromkeys(known_vars))

    # --- Build target variable IDs (active boundary positions in cipher) ---
    target_vars = []

    # Top boundary: input of first extension round (= input of distinguisher_start)
    # Since distinguisher rounds are skipped, use the first extension round's
    # last layer going inward. Target = round before distinguisher, last layer.
    if distinguisher_start > 1:
        # Target is at the last layer of the round just before the distinguisher
        # which is the same as the input to the distinguisher (via gap-link)
        for i in input_active:
            target_vars.append(perm_func.vars[distinguisher_start - 1][cipher_last_layer][i].ID)

    # Bottom boundary: input of first bottom extension round
    # Since distinguisher is skipped, target = round distinguisher_end+1, layer 0
    if distinguisher_end < R_cipher:
        for i in output_active:
            target_vars.append(perm_func.vars[distinguisher_end + 1][0][i].ID)

    assert len(target_vars) > 0, "No target variables: no active positions at extension boundaries."

    # --- Build not-guessed list: only key variables (vk_, vsk_) may be guessed ---
    # All state variables (vs_) must not be guessed in key recovery.
    not_guessed = []
    for var_id in cipher.vars_dictionary:
        if not var_id.startswith("vk_") and not var_id.startswith("vsk_"):
            if var_id not in known_vars and var_id not in target_vars:
                not_guessed.append(var_id)

    # --- Run guess-and-determine attack ---
    result = guess_and_determine_attack(
        cipher,
        known_vars=known_vars,
        target_vars=target_vars,
        not_guessed_vars=not_guessed,
        protect_all_targets=protect_all_targets,
        name_prefix="key_recovery",
        skip_rounds=skip_perm_rounds,
        skip_layers=skip_layers,
        algebraic_layers=algebraic_layers,
        flat_sbox=flat_sbox,
        perm_rename=perm_rename,
        rot_rename=rot_rename,
        gf2linear_rename=gf2linear_rename,
        canonical=canonical,
        cross_round_dir=cross_round_dir,
        bridge_skipped_rounds=False,  # don't equate values across distinguisher
        solver=solver,
        findmin=findmin,
        maxguess=maxguess,
        maxsteps=maxsteps,
        drawgraph=drawgraph,
        satsolver=satsolver,
        smtsolver=smtsolver,
        cpsolver=cpsolver,
        milpdirection=milpdirection,
        cpoptimization=cpoptimization,
        timelimit=timelimit,
        threads=threads,
        preprocess=preprocess,
        tikz=tikz,
        dglayout=dglayout,
        log=log,
    )

    # --- Enrich result with key recovery info ---
    result['trail'] = trail
    result['distinguisher_start'] = distinguisher_start
    result['distinguisher_end'] = distinguisher_end
    result['input_active_positions'] = input_active
    result['output_active_positions'] = output_active
    result['trail_weight'] = trail.data.get('diff_weight')

    n_guessed = len(result.get('guessed_variables', []))
    trail_weight = trail.data.get('diff_weight', 0) or 0
    result['key_guessing_complexity'] = n_guessed
    result['data_complexity'] = trail_weight
    result['total_complexity_log2'] = n_guessed + trail_weight

    result['time'] = time.time() - time_start

    return result
