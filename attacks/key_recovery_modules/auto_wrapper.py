"""Automatic key-recovery driver.

Give it a cipher factory and a permutation factory; the wrapper tries many
(r_b, R_d, r_f) round splits, runs the per-split estimator for each, drops any
attack whose cost is above the targeted security level, and returns the best
surviving attack.

All optional inputs, with defaults:
  * the set of splits to try     -> `splits` (or built from r_b/r_f/r_d values)
  * what "best" means            -> `objective`, default: most rounds attacked,
                                    then lowest time complexity
  * the targeted security level  -> `targeted_security`, default: the key size;
                                    no attack costing more than this is returned

Factories rather than a cipher instance, because a sweep builds the cipher at
every round count it tries:

    auto_key_recovery(
        lambda r: PRESENT_BLOCKCIPHER(r=r, version=[64, 80], final_whitening=True),
        lambda r: PRESENT_PERMUTATION(r=r),
        key_bits=80)

Distinguishers are searched by default. A published one can be injected per R_d
through `manual_distinguishers` -- `{14: {"weight": 62, "delta_in": ..., "delta_out": ...}}`
-- which is much faster for a long distinguisher, and is how `run_attack.py` in
`test/key_recovery/` pins a paper's trail when sweeping splits.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout, redirect_stderr

from attacks.attacks import diff_attacks
from attacks.key_recovery import search_key_recovery
from attacks.key_recovery_modules.trail import build_manual_trail


def _trail_for_rd(cipher_factory, perm_factory, R_d, manual, cache):
    """The distinguisher trail for an R_d-round distinguisher, cached per R_d so a
    split-sweep never re-searches the same length. Uses an injected distinguisher
    when one is given for this R_d, otherwise runs the SAT search. The trail's
    shape is read off the cipher, not declared."""
    if R_d in cache:
        return cache[R_d]
    if manual and R_d in manual:
        d = manual[R_d]
        perm = cipher_factory(R_d + 1).functions["PERMUTATION"]
        trail = build_manual_trail(
            nbr_words=perm.nbr_words, word_bitsize=perm.word_bitsize, R_d=R_d,
            weight=d["weight"], delta_in=d["delta_in"], delta_out=d["delta_out"],
            last_layer=perm.nbr_layers - 1)
    else:
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(buf):
            trails = diff_attacks(perm_factory(R_d), goal="DIFFERENTIALPATH_PROB",
                                  config_model={"model_type": "sat"})
        trail = trails[0] if trails else None
    cache[R_d] = trail
    return trail


def _default_splits(r_b_values, r_f_values, r_d_values):
    """All (r_b, R_d, r_f) from the value lists, dropping the no-extension case."""
    return [(rb, rd, rf)
            for rb in r_b_values for rd in r_d_values for rf in r_f_values
            if rb + rf >= 1]


def _pick_best(valid, objective):
    """The winning attack under `objective`. Lower sort key wins."""
    if callable(objective):
        return min(valid, key=objective)
    if objective == "min_time":                       # cheapest attack
        return min(valid, key=lambda r: (r["T_log2"], -r["total_rounds"]))
    # default "max_rounds": most rounds attacked, tie-break on lowest time
    return min(valid, key=lambda r: (-r["total_rounds"], r["T_log2"]))


def auto_key_recovery(cipher_factory, perm_factory, *, key_bits,
                      targeted_security=None, splits=None,
                      r_b_values=(1, 2), r_f_values=(0, 1), r_d_values=(10,),
                      objective="max_rounds", manual_distinguishers=None,
                      independent_round_keys=True, maxsteps=40,
                      full_rounds=None, cipher_name=None, verbose=True):
    """Try many round splits and return the best valid attack.

    cipher_factory    : cipher_factory(r) -> a fresh r-round block cipher.
    perm_factory      : perm_factory(r)   -> a fresh r-round permutation, used
                        when a distinguisher has to be searched.
    key_bits          : key size, used for the default targeted security and for
                        the per-S-box objective bound.
    targeted_security : bits; attacks with time cost above this are dropped
                        (default: key_bits). "Cost" is the time complexity T only
                        -- data complexity is deliberately excluded, as in Boura
                        et al. and in the estimator's own `valid_attack` gate.
    splits            : explicit [(r_b, R_d, r_f), ...]; if None, built from
                        r_b_values x r_d_values x r_f_values.
    objective         : "max_rounds" (default) | "min_time" | callable(row)->key.
    independent_round_keys : as in `search_key_recovery`, and with the same default
                        (True): treat the subkeys as independent, i.e. skip the
                        KEY_SCHEDULE relations. False keeps them, so one subkey can
                        be bridged from another and a later S-box can come out free.
    full_rounds       : if given, splits totalling more rounds are skipped.

    Returns {cipher, targeted_security, best, results, valid_results}. Every row
    is a plain dict (JSON-serialisable); failed/skipped splits carry a "skipped"
    reason instead of numbers. `results` holds every split tried, over-budget ones
    included and flagged valid=False; `best` and `valid_results` hold only those
    within the targeted security level.
    """
    target = key_bits if targeted_security is None else targeted_security
    if splits is None:
        splits = _default_splits(r_b_values, r_f_values, r_d_values)
    if cipher_name is None:      # the cipher knows its own name; ask it once
        cipher_name = getattr(cipher_factory(splits[0][0] + splits[0][1] + splits[0][2]),
                              "name", "cipher")

    config_model = {"model_type": "sat", "sbox_form": "implication",
                    "maxsteps": maxsteps,
                    "independent_round_keys": independent_round_keys}
    config_solver = {"solver": "cadical153"}
    objective_target = f"OPTIMAL AT MOST {key_bits}"

    trail_cache = {}
    results = []
    for (rb, rd, rf) in splits:
        total = rb + rd + rf
        row = {"r_b": rb, "R_d": rd, "r_f": rf, "total_rounds": total}

        if full_rounds is not None and total > full_rounds:
            row["skipped"] = f"total {total} > full {full_rounds}"
            results.append(row)
            _log(verbose, row)
            continue

        try:
            # The trail search is as fallible as the estimate -- GIFT, for one,
            # cannot serialise its trail at all -- and a sweep that dies on one
            # R_d loses every split, including the ones already computed. Record
            # the reason on the row, exactly as an estimator failure is recorded.
            trail = _trail_for_rd(cipher_factory, perm_factory, rd,
                                  manual_distinguishers, trail_cache)
        except Exception as exc:
            # Cache the failure so the other splits at this R_d do not re-run a
            # search that is already known to fail; this row keeps the reason.
            trail_cache[rd] = None
            row["skipped"] = f"distinguisher: {type(exc).__name__}: {exc}".splitlines()[0][:120]
            results.append(row)
            _log(verbose, row)
            continue
        if trail is None:
            row["skipped"] = "no distinguisher found"
            results.append(row)
            _log(verbose, row)
            continue

        cipher = cipher_factory(total)
        buf = io.StringIO()
        try:
            # A single split failing (weak trail, AutoGuess over its limits, ...)
            # must not abort the sweep -- record why and move on.
            with redirect_stdout(buf), redirect_stderr(buf):
                est = search_key_recovery(
                    cipher, R_d=rd, r_b=rb, r_f=rf, trail=trail,
                    objective_target=objective_target,
                    config_model=config_model, config_solver=config_solver)
        except Exception as exc:
            row["skipped"] = f"{type(exc).__name__}: {exc}".splitlines()[0][:120]
            results.append(row)
            _log(verbose, row)
            continue

        row.update(T_log2=round(est["T_log2"], 2),
                   d_in=est["d_in_bits"], d_out=est["d_out_bits"],
                   key_bits=est["key_size_bits"], valid=est["T_log2"] < target) # strict, as in the estimator
        results.append(row)
        _log(verbose, row)

    valid = [r for r in results if r.get("valid")]
    best = _pick_best(valid, objective) if valid else None
    if verbose:
        _print_summary(cipher_name, target, objective, best, results)
    return {"cipher": cipher_name, "targeted_security": target,
            "best": best, "results": results, "valid_results": valid}


# --- tiny printers ------------------------------------------------------------

def _log(verbose, row):
    if not verbose:
        return
    tag = f"r_b={row['r_b']} R_d={row['R_d']} r_f={row['r_f']} (total {row['total_rounds']})"
    if "skipped" in row:
        print(f"  [skip] {tag:<34} {row['skipped']}")
    else:
        mark = "OK " if row["valid"] else "over"
        print(f"  [{mark}] {tag:<34} T=2^{row['T_log2']}  "
              f"d_in={row['d_in']:g} d_out={row['d_out']:g}")


def _print_summary(cipher_name, target, objective, best, results):
    obj = objective if isinstance(objective, str) else "custom"
    tried = sum(1 for r in results if "skipped" not in r)
    print(f"\n=== {cipher_name}: best attack (objective={obj}, "
          f"targeted security=2^{target}) ===")
    print(f"    {tried}/{len(results)} splits produced an attack.")
    if best is None:
        print("    No attack within the targeted security level.")
        return
    print(f"    rounds attacked : {best['total_rounds']} "
          f"(r_b={best['r_b']}, R_d={best['R_d']}, r_f={best['r_f']})")
    print(f"    time complexity : 2^{best['T_log2']}  (< 2^{target})")
    print(f"    d_in={best['d_in']:g}  d_out={best['d_out']:g}  key={best['key_bits']} bits")
