"""One-S-box solve backend via the AutoGuess pipeline.

`solve_sbox_guess_basis` finds the minimum key bits an attacker must guess so that
PT/CT (plus the keys already committed) determine one S-box's distinguisher-facing
difference, over the extension rounds. The greedy calls it once per S-box.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from attacks.guess_and_determine import search_guess_basis

# AutoGuess prints "minimum number of guesses = K"; the greedy parses K from this.
FINDMIN_RE = re.compile(r"minimum number of guesses\s*=\s*(\d+)")


def _is_key_var_id(var_id):
    return var_id.startswith(("vk_", "vsk_"))


def identify_perm_function(trail_functions):
    """Name of the permutation function inside a trail_struct."""
    for fname, fdata in trail_functions.items():
        if isinstance(fdata, dict) and "nbr_words" in fdata:
            return fname
    raise AssertionError("No permutation function found in trail_struct.")


def extract_active_positions(trail_struct, perm_name, round_nb, layer_nb, nbr_words):
    """Active word positions at one (round, layer) of a trail_struct."""
    layer_data = trail_struct["functions"][perm_name][round_nb][layer_nb]
    return [i for i in range(nbr_words) if "1" in layer_data[i]["bin_values"]]


def _build_known_var_ids(perm_func, distinguisher_start, distinguisher_end,
                         R_cipher, cipher_last_layer):
    """Plaintext IDs known iff there's a top extension; ciphertext IDs iff bottom."""
    known = []
    if distinguisher_start > 1:                    # plaintext observable
        known += [perm_func.vars[1][0][i].ID for i in range(perm_func.nbr_words)]
    if distinguisher_end < R_cipher:               # ciphertext observable
        known += [perm_func.vars[R_cipher][cipher_last_layer][i].ID
                  for i in range(perm_func.nbr_words)]
    return list(dict.fromkeys(known))


def _build_not_guessed_var_ids(cipher, known_vars, target_vars):
    """Block every non-key variable from being guessed (keys = vk_/vsk_)."""
    keep_out = set(known_vars) | set(target_vars)
    return [vid for vid in cipher.vars_dictionary
            if not _is_key_var_id(vid) and vid not in keep_out]


def solve_sbox_guess_basis(cipher, *, distinguisher_start, distinguisher_end,
                           target_var_ids, extra_known_var_ids=None,
                           objective_target="OPTIMAL", show_mode=0,
                           config_model=None, config_solver=None, protect_all_targets=True):
    """Min key bits to guess so that PT/CT + extra_known determine `target_var_ids`.

    The distinguisher's own PERMUTATION rounds are skipped; the key schedule is kept.
    `config_model` / `config_solver` / `objective_target` / `show_mode` are the
    guess-and-determine configuration and are forwarded to `search_guess_basis`.

    Returns:
        dict: {K_count, solver_output_exists, guessed_variables, target_var_ids,
        determined_state_var_ids, determined_key_var_ids}.
    """
    config_model = dict(config_model or {})

    perm_func = cipher.functions["PERMUTATION"]
    R_cipher = perm_func.nbr_rounds

    assert 1 <= distinguisher_start <= distinguisher_end <= R_cipher, (
        f"Invalid distinguisher range [{distinguisher_start}, {distinguisher_end}] "
        f"for {R_cipher}-round cipher.")
    assert distinguisher_start > 1 or distinguisher_end < R_cipher, \
        "No extension rounds: distinguisher covers the entire cipher."

    # These two state the sub-problem, not how it is modelled: the distinguisher's
    # rounds must be absent and must not be bridged, or the solve would be allowed
    # to reach through the distinguisher. Overwriting a caller's value silently
    # would make their setting a no-op, so say so instead.
    conflicting = sorted({"skip_rounds", "bridge_skipped_rounds"} & set(config_model))
    if conflicting:
        raise ValueError(
            f"config_model key(s) {conflicting} are set by the key-recovery engine "
            f"itself (the distinguisher's rounds [{distinguisher_start}, "
            f"{distinguisher_end}] are skipped and not bridged) and cannot be "
            f"overridden. Remove them from config_model.")

    # only key bits are guessable; the distinguisher's PERMUTATION rounds are skipped
    config_model["skip_rounds"] = {
        "PERMUTATION": list(range(distinguisher_start, distinguisher_end + 1))}
    config_model["bridge_skipped_rounds"] = False
    known_vars = _build_known_var_ids(perm_func, distinguisher_start, distinguisher_end,
                                      R_cipher, perm_func.nbr_layers)
    if extra_known_var_ids:
        known_vars = list(dict.fromkeys(known_vars + list(extra_known_var_ids)))
    target_vars = list(target_var_ids)
    not_guessed = _build_not_guessed_var_ids(cipher, known_vars, target_vars)

    # The output filename is a hash of the whole sub-problem, so AutoGuess's reused
    # output file never lets a different problem read a stale result.
    spec = repr((sorted(target_vars), sorted(known_vars), sorted(not_guessed), R_cipher,
                 sorted(config_model.get("skip_functions") or []),
                 repr(config_model["skip_rounds"]), config_model["bridge_skipped_rounds"]))
    tag = hashlib.md5(spec.encode()).hexdigest()[:12]
    config_model["name_prefix"] = f"key_recovery_{tag}"

    raw = search_guess_basis(
        cipher, known_vars=known_vars, target_vars=target_vars, not_guessed_vars=not_guessed,
        protect_all_targets=protect_all_targets, objective_target=objective_target,
        show_mode=show_mode, config_model=config_model, config_solver=config_solver)

    guessed_vars = list(raw.get("guessed_variables", []))
    outputfile = raw.get("outputfile")
    determined_ids = {getattr(v, "ID", str(v))
                      for step in raw.get("determination_steps", [])
                      for v in step.get("determined_vars", [])}
    in_cipher = cipher.vars_dictionary
    return {
        "K_count": len(guessed_vars),
        "solver_output_exists": bool(outputfile and Path(outputfile).exists()),
        "guessed_variables": guessed_vars,
        "target_var_ids": target_vars,
        "determined_state_var_ids": sorted(v for v in determined_ids
                                           if v in in_cipher and not _is_key_var_id(v)),
        "determined_key_var_ids": sorted(v for v in determined_ids
                                         if v in in_cipher and _is_key_var_id(v)),
    }
