"""Differential key-recovery cost estimation via AutoGuess.

`search_key_recovery` extends a differential distinguisher by `r_b` rounds at the
top and `r_f` rounds at the bottom, and estimates what recovering the involved
key bits costs:

  1. Trail   -- supplied (`build_manual_trail`) or searched on `distinguisher`.
  2. Numbers -- p, d_in, d_out (propagated), N0 = p + d_in + d_out - n.
  3. S-boxes -- the active S-boxes in the r_b / r_f extension rounds.
  4. Greedy  -- peel them with AutoGuess, accumulating dK and the DDT filter.
  5. Time    -- T = C_KR * N0; the attack is valid iff T < 2^|key|.
  6. Report.

The entry point mirrors the other OCP attack engines (`search_diff_trail`,
`search_linear_trail`, `search_guess_basis`, `search_integral_distinguisher`):
a cipher, a `goal`, an `objective_target`, a `show_mode`, and two plain
dictionaries `config_model` / `config_solver`. Everything in `config_model` that
this module does not consume itself is forwarded to `search_guess_basis`, which
validates it.

The user-facing wrapper with timing lives in `attacks.attacks` as
`key_recovery_attack`.
"""

from __future__ import annotations

from attacks.key_recovery_modules.dynamic_greedy import (
    estimate_dynamic_autoguess_greedy, with_right_pair)
from attacks.key_recovery_modules.propagation import (
    find_sbox_layer,
    boundary_pattern_bits,
    extract_extension_active_sboxes,
    propagated_d_in_bits,
    propagated_d_out_bits,
)
from attacks.key_recovery_modules.report import (
    n_is_upper_bound, print_header_and_trail, print_ordering_header,
    print_ordering_row, print_step_progress, print_summary,
)
from attacks.key_recovery_modules.sbox_solver import (
    extract_active_positions, identify_perm_function)

# Accepted values of `goal`, in the style of the other attack modules.
GOALS = ("KEYRECOVERY_DIFF",)

# config_model keys consumed here rather than forwarded to search_guess_basis.
_MODEL_LOCAL_KEYS = ("independent_round_keys", "cipher_name",
                     "distinguisher_goal", "distinguisher_config_model")


def _trail_boundary_positions(trail):
    """Active word positions AND their exact difference values at the trail's input
    and output boundary. Values (per active word, the delta as an int in S-box VALUE
    order) are needed by the word-cipher extension path; bit ciphers ignore them."""
    struct = trail.data["trail_struct"]
    perm_name = identify_perm_function(struct["functions"])
    perm_block = struct["functions"][perm_name]
    nbr_words = perm_block["nbr_words"]
    rounds = perm_block.get("rounds") or trail.data.get("rounds")
    if isinstance(rounds, int):
        rounds = list(range(1, rounds + 1))
    last_layer = max(k for k in perm_block[rounds[-1]] if isinstance(k, int))
    in_act = extract_active_positions(struct, perm_name, rounds[0], 0, nbr_words)
    out_act = extract_active_positions(struct, perm_name, rounds[-1], last_layer, nbr_words)

    def _values(round_nb, layer_nb, positions):
        layer_data = perm_block[round_nb][layer_nb]
        out = {}
        for i in positions:
            bits = layer_data[i]["bin_values"]
            if set(bits) - {"0", "1"}:
                # The trail search writes '-' for a variable the solver left
                # unassigned. Reading it as a difference value is not possible, and
                # int() would raise a bare ValueError from deep in the engine.
                raise RuntimeError(
                    f"Trail word {i} at round {round_nb}, layer {layer_nb} has an "
                    f"undetermined difference ('{bits}'). The trail search returned "
                    f"a partial solution, so the boundary difference the extension "
                    f"is seeded with is unknown. Re-run the search, or pin the "
                    f"distinguisher with build_manual_trail.")
            out[i] = int(bits, 2)
        return out

    in_vals = _values(rounds[0], 0, in_act)
    out_vals = _values(rounds[-1], last_layer, out_act)
    return in_act, out_act, in_vals, out_vals


def _acquire_trail(distinguisher, goal, config_model):
    """Search a differential trail on `distinguisher` and return the best one."""
    from attacks.attacks import diff_attacks  # local import: avoid a cycle
    trails = diff_attacks(distinguisher, goal=goal,
                          config_model=config_model or {"model_type": "sat"})
    if not trails:
        raise RuntimeError("no differential trail found")
    return trails[0]


def _parse_and_set_configs(config_model, config_solver):
    """Split `config_model` into the keys consumed here and the keys forwarded.

    Returns ``(local, config_model, config_solver)``: `local` holds the four
    `_MODEL_LOCAL_KEYS` with defaults filled in, and `config_model` is everything
    else, destined for `search_guess_basis`. Unknown keys are not checked here --
    `search_guess_basis` rejects them, so there is a single list of valid keys.
    """
    config_model = dict(config_model or {})
    config_solver = dict(config_solver or {})

    local = {key: config_model.pop(key, None) for key in _MODEL_LOCAL_KEYS}
    if local["independent_round_keys"] is None:
        local["independent_round_keys"] = True
    if local["distinguisher_goal"] is None:
        local["distinguisher_goal"] = "DIFFERENTIALPATH_PROB"

    # Independent subkeys -> drop the key schedule from the relation system.
    if local["independent_round_keys"]:
        skip = list(config_model.get("skip_functions") or [])
        if "KEY_SCHEDULE" not in skip:
            skip.append("KEY_SCHEDULE")
        config_model["skip_functions"] = skip

    return local, config_model, config_solver


# Engine
def search_key_recovery(cipher, goal="KEYRECOVERY_DIFF", R_d=None, r_b=0, r_f=0,
                        trail=None, distinguisher=None, objective_target="OPTIMAL",
                        show_mode=0, config_model=None, config_solver=None):
    """Estimate the cost of a differential key-recovery attack on `cipher`.

    Args:
        cipher: The cipher object to attack. It must span all `r_b + R_d + r_f`
            rounds, so that the extension rounds carry real subkey variables.
        goal (str): Cryptanalysis goal; only ``"KEYRECOVERY_DIFF"`` is supported.
        R_d (int): Number of rounds covered by the distinguisher.
        r_b (int): Key-recovery rounds prepended above the distinguisher.
        r_f (int): Key-recovery rounds appended below the distinguisher.
        trail: A trail object carrying the distinguisher, e.g. from
            ``key_recovery_modules.trail.build_manual_trail``. Mutually exclusive
            with `distinguisher`.
        distinguisher: An `R_d`-round permutation to search a trail on when
            `trail` is not given. Mutually exclusive with `trail`.
        objective_target (str): Forwarded to `search_guess_basis` for every
            per-S-box solve:
            - 'OPTIMAL': minimise the guess basis. The bound is filled in from the
              cipher's key size -- AutoGuess' own default starts the descent at the
              number of target variables, below the basis size of a single S-box.
            - 'OPTIMAL AT MOST X': minimise, starting the descent at X. X only has
              to be at least the true basis size; the key size is always safe.
            - 'AT MOST X': any basis of size at most X, without minimising.
            - 'EXISTENCE': any basis at all.
        show_mode (int): Result-printing detail level (0-3), forwarded to
            `search_guess_basis`. The key-recovery report itself is always printed.
        config_model (dict, optional): Advanced modeling options. Consumed here:
            - 'independent_round_keys' (bool, default True): treat the subkeys as
              independent, i.e. skip the KEY_SCHEDULE relations. False keeps them,
              so one subkey can be bridged from another and a later S-box can come
              out free.
            - 'cipher_name' (str): name shown in the report. Defaults to the
              cipher's own name plus the round split, e.g. "PRESENT64_80 (2+14+1)".
            - 'distinguisher_goal' (str): goal for the trail search, used when
              `distinguisher` is given.
            - 'distinguisher_config_model' (dict): config_model for that search.
            Every other key is forwarded to `search_guess_basis`, notably
            'model_type' ('sat' by default), 'maxsteps' and 'sbox_form'.
        config_solver (dict, optional): Advanced solver options, forwarded to
            `search_guess_basis`.

    Returns:
        dict: The estimate, with keys 'trail', 'sbox_records', 'ordering',
        'stages', 'key_id_sets', 'per_subset', 'C_KR_filter_model', 'd_in_bits',
        'd_out_bits', 'N0_log2', 'D_log2', 'M_log2', 'C_KR_log2', 'T_log2',
        'total_K_bits', 'total_filter_bits', 'completion_log2', 'key_size_bits',
        'codebook_overflow', 'N_is_upper_bound', 'valid_attack'.
    """
    if goal not in GOALS:
        raise ValueError(f"Invalid goal: {goal}. Expected one of {list(GOALS)}.")
    if not isinstance(R_d, int) or R_d < 1:
        raise ValueError(f"Invalid R_d: {R_d}. Expected the distinguisher round count.")
    if r_b < 0 or r_f < 0 or r_b + r_f == 0:
        raise ValueError(f"Invalid extension (r_b={r_b}, r_f={r_f}). Expected at least one "
                         f"key-recovery round on either side.")
    if (trail is None) == (distinguisher is None):
        raise ValueError("Pass exactly one of `trail` (a built distinguisher) or "
                         "`distinguisher` (a permutation to search a trail on).")
    # Checked here rather than left to the per-S-box solve: an invalid value would
    # otherwise only surface after the trail search and the propagation have run.
    if not (objective_target in ("OPTIMAL", "EXISTENCE")
            or any(objective_target.startswith(prefix + " ") and
                   objective_target[len(prefix):].strip().isdigit()
                   for prefix in ("OPTIMAL AT MOST", "AT MOST"))):
        raise ValueError(f"Invalid objective_target: {objective_target}. Expected one of "
                         f"['OPTIMAL', 'OPTIMAL AT MOST X', 'AT MOST X', 'EXISTENCE'] "
                         f"with integer X.")
    if show_mode not in (0, 1, 2, 3):
        raise ValueError(f"Invalid show_mode: {show_mode}. Expected one of [0, 1, 2, 3].")
    if not (isinstance(config_model, dict) or config_model is None):
        raise ValueError(f"Invalid config_model: {config_model}. Expected a dictionary or None.")
    if not (isinstance(config_solver, dict) or config_solver is None):
        raise ValueError(f"Invalid config_solver: {config_solver}. Expected a dictionary or None.")

    # Step 1. Parse and set model and solver configurations.
    local, config_model, config_solver = _parse_and_set_configs(config_model, config_solver)
    dist_start, dist_end = r_b + 1, r_b + R_d
    perm_func = cipher.functions["PERMUTATION"]
    word_bits = perm_func.word_bitsize
    block_bits = perm_func.nbr_words * word_bits
    ks = cipher.functions.get("KEY_SCHEDULE")
    key_size_bits = ks.nbr_words * ks.word_bitsize if ks is not None else block_bits

    # The cipher must BE the attacked rounds: the ciphertext AutoGuess is given as
    # known is the state at the cipher's last round, so a cipher built over more
    # rounds than r_b + R_d + r_f silently poses a harder problem and returns a
    # cost for it, with no error. One extra round is allowed only when it holds the
    # final key addition alone (`final_whitening=True`), which adds no S-box layer.
    attacked_rounds = r_b + R_d + r_f
    modeled_rounds = perm_func.nbr_rounds
    whitening_only = (modeled_rounds == attacked_rounds + 1
                      and find_sbox_layer(perm_func, modeled_rounds) is None)
    if modeled_rounds != attacked_rounds and not whitening_only:
        raise ValueError(
            f"Cipher has {modeled_rounds} rounds but the split attacks "
            f"{attacked_rounds} (r_b={r_b} + R_d={R_d} + r_f={r_f}). Build it over "
            f"r={attacked_rounds} rounds -- writing `r=r_b + R_d + r_f` keeps the two "
            f"from drifting apart when the split is edited.")

    # Default report label: the cipher's own name plus the round split it was run
    # at, e.g. "PRESENT64_80 (2+14+1)". `cipher_name` overrides it.
    name = local["cipher_name"] or f"{getattr(cipher, 'name', 'cipher')} ({r_b}+{R_d}+{r_f})"

    # A bare 'OPTIMAL' makes AutoGuess start its descent at the number of target
    # variables -- about 4 for a single S-box, below any real guess basis, so no
    # basis is found. The key size is the smallest bound guaranteed to be safe:
    # no attack ever needs to guess more bits than the whole key.
    if objective_target == "OPTIMAL":
        objective_target = f"OPTIMAL AT MOST {key_size_bits}"
        print(f"[INFO] objective_target='OPTIMAL' starts AutoGuess' descent at the number of "
              f"target variables, which is below the guess basis of a single S-box. It is set "
              f"to '{objective_target}' ({key_size_bits}-bit key) instead. Pass "
              f"'OPTIMAL AT MOST X' explicitly to choose your own bound.")

    # Step 2. Acquire the distinguisher trail.
    if trail is None:
        trail = _acquire_trail(distinguisher, local["distinguisher_goal"],
                               local["distinguisher_config_model"])
    p = trail.data.get("diff_weight", 0) or 0

    # Step 3. Trail boundary and the active S-boxes in the extension rounds.
    in_act, out_act, in_vals, out_vals = _trail_boundary_positions(trail)
    if not in_act and not out_act:
        raise RuntimeError("Trail has zero active boundary cells.")
    sbox_records = extract_extension_active_sboxes(
        cipher,
        input_active_positions=in_act if r_b > 0 else [],
        output_active_positions=out_act if r_f > 0 else [],
        input_active_values=in_vals if r_b > 0 else {},
        output_active_values=out_vals if r_f > 0 else {},
        distinguisher_start=dist_start, distinguisher_end=dist_end, r_b=r_b, r_f=r_f,
    )
    if not sbox_records:
        raise RuntimeError(f"No active S-boxes in the extension (r_b={r_b}, r_f={r_f}, "
                           f"in={in_act}, out={out_act}).")

    # Step 4. Trail-derived numbers.
    # d_in / d_out are set SIZES: |D_in| = 2^d_in. Counting active bits equals that
    # only when every combination of the active bits occurs; a bit forced to 1, or a
    # mixing linear layer that makes the bits dependent, both break it. The structure
    # and hash-table footprint is still the active-bit count, so it is kept for M.
    d_in_bits = len(in_act) * word_bits     # default: boundary count (no extension)
    d_out_bits = len(out_act) * word_bits
    d_in_footprint, d_out_footprint = d_in_bits, d_out_bits
    if r_b > 0:
        prop = propagated_d_in_bits(cipher, in_act, distinguisher_start=dist_start, r_b=r_b)
        if prop is not None:
            d_in_footprint = prop
        pattern = boundary_pattern_bits(sbox_records, "backward")
        d_in_bits = d_in_footprint if pattern is None else pattern
    if r_f > 0:
        prop = propagated_d_out_bits(cipher, out_act, distinguisher_end=dist_end, r_f=r_f)
        if prop is not None:
            d_out_footprint = prop
        pattern = boundary_pattern_bits(sbox_records, "forward")
        d_out_bits = d_out_footprint if pattern is None else pattern
    # Wrong pairs surviving the boundary sieve, out of the 2^{p+d_in} pairs formed
    # from the data; then plus the right pair, which passes the sieve by construction.
    N0_log2 = with_right_pair(p + d_in_bits + d_out_bits - block_bits)
    D_log2 = p + 1.0                    # data:   2^{p+1} pairs
    # Memory: the structure held in the hash table. Its dimension is the active-bit
    # footprint, but a structure can never be larger than the data that fills it --
    # with d_in > p + 1 the attack uses a partial structure of 2^{p+1} plaintexts
    # (2^{p-d_in+1} structures is below one), so the footprint alone would report
    # more memory than the attack ever queries.
    M_log2 = float(min(d_in_footprint, D_log2))

    # Step 5. Header + trail numbers, printed BEFORE AutoGuess runs.
    print_header_and_trail(
        cipher_name=name, R_d=R_d, r_b=r_b, r_f=r_f, dist_start=dist_start, dist_end=dist_end,
        p=p, n_active_sboxes=len(sbox_records), d_in=d_in_bits, d_out=d_out_bits,
        N_log2=N0_log2, D_log2=D_log2, M_log2=M_log2, modeled_rounds=perm_func.nbr_rounds,
    )
    print_ordering_header(len(sbox_records))

    # Step 6. Greedy peel; each S-box row streams out as its solve commits.
    ordering, stages, key_id_sets, T_sum_log2, _, total_K_bits, per_subset = \
        estimate_dynamic_autoguess_greedy(
            cipher=cipher, sbox_records=sbox_records,
            distinguisher_start=dist_start, distinguisher_end=dist_end,
            N0_log2=N0_log2, objective_target=objective_target, show_mode=show_mode,
            config_model=config_model, config_solver=config_solver, verbose=True,
            progress_callback=print_step_progress,
            step_callback=print_ordering_row,
        )
    C_KR_log2 = T_sum_log2 - N0_log2
    # Time complexity = C_KR * N (the key-recovery work). Data complexity is
    # deliberately excluded from both the cost and the validity gate.
    T_log2 = T_sum_log2                         # = C_KR_log2 + N0_log2
    codebook_overflow = D_log2 > block_bits     # reported as metadata only
    valid_attack = T_log2 < key_size_bits       # C_KR * N < 2^key_size

    # Step 7. Summary.
    total_filter_bits = sum(s["filter_bits"] for s in stages)
    # The un-guessed key bits are filled in by search over the surviving triplets:
    # N * 2^(|K| - F) triplets, each completed at 2^(key_size - |K|), so |K| cancels
    # and the cost is N * 2^(key_size - F). Both N and F are fixed before the greedy
    # runs, so this is the same whatever order the S-boxes are peeled in -- it is a
    # floor on the attack, not something the ordering can trade against. Reported,
    # never folded into T: T and valid_attack keep the Boura et al. convention.
    completion_log2 = N0_log2 + key_size_bits - total_filter_bits
    if total_K_bits > key_size_bits:
        # The committed variables cannot be independent -- there are only
        # key_size_bits of key. Each is counted once, so a relation AutoGuess did
        # not report inflates the total, and with it C_KR and T. Over-statement
        # only, but worth naming: the remedy is to let AutoGuess find more
        # relations, not to change the model.
        print(f"[WARN] guess basis of {total_K_bits} bits for a {key_size_bits}-bit key: the "
              f"guessed variables cannot be independent, so the true count is at most "
              f"{key_size_bits} and the reported cost is over-stated. AutoGuess only reports "
              f"the relations it finds within config_model['maxsteps'] "
              f"(currently {config_model.get('maxsteps')}); raising it may lower the count. "
              f"With independent_round_keys=True the key schedule is skipped entirely and no "
              f"relation can be found at all.")
    print_summary(
        C_KR_log2=C_KR_log2, N_log2=N0_log2, total_K_bits=total_K_bits, T_log2=T_log2,
        key_size_bits=key_size_bits, valid_attack=valid_attack,
        D_log2=D_log2, block_bits=block_bits,
    )

    return {
        "trail": trail, "sbox_records": sbox_records, "ordering": ordering, "stages": stages,
        "key_id_sets": key_id_sets,
        "per_subset": per_subset, "C_KR_filter_model": "conditional_target_side",
        "d_in_bits": d_in_bits, "d_out_bits": d_out_bits,
        "N0_log2": N0_log2, "D_log2": D_log2, "M_log2": M_log2,
        "C_KR_log2": C_KR_log2, "T_log2": T_log2, "total_K_bits": total_K_bits,
        "total_filter_bits": total_filter_bits, "completion_log2": completion_log2,
        "N_is_upper_bound": n_is_upper_bound(p, d_in_bits),
        "key_size_bits": key_size_bits, "codebook_overflow": codebook_overflow,
        "valid_attack": valid_attack,
    }
