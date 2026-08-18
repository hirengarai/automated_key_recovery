"""Greedy key recovery: peel the active S-boxes one at a time.

Each step re-solves every remaining S-box with AutoGuess (known = PT/CT +
committed key bits) and commits the one with the best `ΔK - filter`, where
filter is the per-S-box conditional target-side DDT filter. The reported time
is the partial sum of every step's work:  T = Σ_steps (pairs_alive * 2^key_bits).
"""

from __future__ import annotations

import io
import math
import re
from contextlib import redirect_stdout, redirect_stderr

from attacks.key_recovery_modules.ddt_filter import conditional_target_side_filter_for_record
from attacks.key_recovery_modules.propagation import make_unit_id
from attacks.key_recovery_modules.sbox_solver import FINDMIN_RE, solve_sbox_guess_basis


# A missing optional dependency surfaces from deep inside AutoGuess as an ordinary
# solve failure. Raising the "increase maxsteps" hint then sends the user chasing
# the wrong thing, so detect the real cause and say it instead.
_MISSING_DEP_NAME_RE = re.compile(
    r"No module named ['\"]([\w.]+)['\"]|Package ['\"]?([\w.]+)['\"]? is unavailable")
_MISSING_DEP_ANY_RE = re.compile(r"ModuleNotFoundError|ImportError|is unavailable")


def _missing_dependency(text):
    """Name of the absent package if `text` reports one, else None.

    The named patterns are tried over the whole text first: an exception line
    starts with "ModuleNotFoundError", which would otherwise match before the
    package name further along it.
    """
    text = text or ""
    named = _MISSING_DEP_NAME_RE.search(text)
    if named:
        return named.group(1) or named.group(2)
    return "an optional package" if _MISSING_DEP_ANY_RE.search(text) else None


def with_right_pair(log2_wrong_pairs):
    """log2(2^x + 1): surviving wrong pairs plus the right pair.

    The pair counts in this module are expected counts of WRONG pairs: a random
    pair survives a sieve of f bits with probability 2^-f. The right pair is not
    subject to that -- it satisfies the trail, so it passes every boundary sieve
    and every S-box filter by construction, and the data is sized so that one
    exists. At least one pair is therefore always processed.

    Above ~2^53 this returns x unchanged (2^x + 1 == 2^x in float64), so it is a
    no-op for every attack whose sieve leaves many wrong pairs. It only bites when
    the sieve is strong enough to remove them all, where the uncorrected count
    goes below 1 and the work collapses toward zero.
    """
    return log2_wrong_pairs if log2_wrong_pairs > 53 else math.log2(2.0 ** log2_wrong_pairs + 1.0)


def _log2_sum_exp2(values):
    """log2(Σ 2^v) without ever forming 2^v.

    The step works are pair counts that a wide extension on a 128-bit key pushes
    past 2^1024, where `2.0 ** v` raises OverflowError. Factoring out the largest
    term keeps every exponential in [0, 1] and leaves the result bit-identical to
    the direct sum in the ranges where the direct sum is representable.
    """
    top = max(values)
    return top + math.log2(sum(2.0 ** (v - top) for v in values))


def autoguess_target_subset_for_sbox(sbox_record):
    """The variables AutoGuess must determine for one S-box: the side facing the
    distinguisher (output for backward/PT boxes, input for forward/CT boxes)."""
    label = make_unit_id(sbox_record)
    side = sbox_record.get("side")
    if side == "backward":
        return {"var_ids": list(sbox_record["output_var_ids"]),
                "label": f"{label}:out", "target_side": "output"}
    if side == "forward":
        return {"var_ids": list(sbox_record["input_var_ids"]),
                "label": f"{label}:in", "target_side": "input"}
    raise ValueError(f"Unknown S-box side {side!r} for {label}.")


def _key_widths(vars_):
    """ID -> bit width of each guessed key variable.

    A key variable is a whole word, so guessing one costs 2^bitsize, not 2.
    Bit-oriented ciphers (PRESENT, GIFT, RECTANGLE) have bitsize 1 and are
    unaffected; nibble-oriented ones (SKINNY, LED) are 4.
    """
    return {getattr(v, "ID", str(v)): getattr(v, "bitsize", 1) for v in vars_}


def _ids(vars_):
    """OCP variable objects -> their ID strings."""
    return {getattr(v, "ID", str(v)) for v in vars_}


def _run_candidate(cipher, record, extra_known, dist_start, dist_end,
                   objective_target, show_mode, config_model, config_solver):
    """Solve one S-box: minimum key bits to determine its target side, given
    PT/CT + extra_known. Returns the result dict (or {solver_failed: True})."""
    subset = autoguess_target_subset_for_sbox(record)
    buf = io.StringIO()
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            result = solve_sbox_guess_basis(
                cipher,
                distinguisher_start=dist_start, distinguisher_end=dist_end,
                target_var_ids=list(subset["var_ids"]),
                extra_known_var_ids=sorted(extra_known),
                objective_target=objective_target, show_mode=show_mode,
                config_model=config_model, config_solver=config_solver,
                protect_all_targets=True,
            )
    except ImportError:
        # Missing solver backend (e.g. pysat) is an environment error that would
        # recur identically for every S-box -- fail fast instead of looping.
        raise
    except Exception as exc:
        return {"solver_failed": True, "label": subset["label"],
                "solver_error": f"{type(exc).__name__}: {exc}"}

    # AutoGuess prints "minimum number of guesses = K" on a successful solve (any K,
    # including 0). Its ABSENCE means AutoGuess found no guess basis within the
    # maxsteps/maxguess limits -- a hard failure, NOT a free (K=0) solve.
    out = buf.getvalue()
    matches = FINDMIN_RE.findall(out)
    if matches:
        result["K_count"] = int(matches[-1])
        if result["K_count"] == 0:
            result["guessed_variables"] = []
        elif not result.get("solver_output_exists"):
            result["solver_failed"] = True
        elif result["K_count"] != len(result.get("guessed_variables", [])):
            # AutoGuess reported K guesses but fewer resolved back to cipher
            # variables (an unmapped ID, e.g. a dummy standing for a product of
            # variables). The cost model charges 2^len(guessed_variables), so
            # carrying on would UNDER-state the attack -- the one direction that
            # must never happen silently.
            raise RuntimeError(
                f"AutoGuess guessed {result['K_count']} variable(s) for S-box "
                f"{subset['label']} but only "
                f"{len(result.get('guessed_variables', []))} resolved to cipher "
                f"variables, so the key-bit count -- and hence the reported cost -- "
                f"would be too low. Unresolvable IDs are usually AutoGuess dummy "
                f"variables; re-run with config_model['sbox_form'] set to a form "
                f"that introduces none.\n"
                f"---------------- AutoGuess output ----------------\n"
                f"{chr(10).join(out.strip().splitlines()[-15:])}\n"
                f"--------------------------------------------------")
    else:
        result["solver_failed"] = True

    if result.get("solver_failed"):
        # Keep AutoGuess's own message (redirected into buf) so the caller can stop
        # with the exact "increase maxsteps/maxguess" hint instead of skipping it.
        tail = "\n".join(out.strip().splitlines()[-15:])
        result["autoguess_message"] = tail or "(AutoGuess produced no output)"

    result["unit"] = make_unit_id(record)
    result["label"] = subset["label"]
    return result


def estimate_dynamic_autoguess_greedy(
    *,
    cipher,
    sbox_records,
    distinguisher_start,
    distinguisher_end,
    N0_log2,
    objective_target="OPTIMAL",
    show_mode=0,
    config_model=None,
    config_solver=None,
    verbose=True,
    step_callback=None,
    progress_callback=None,
):
    """Run the greedy peel. Returns (ordering, stages, key_id_sets, T_log2,
    survivors_log2, total_key_bits, selected_results) for the report layer.

    If `step_callback` is given it is called as
    step_callback(step, unit, stage_dict, new_key_ids) right after each S-box
    commits, so callers can stream the ordering rows as AutoGuess solves finish.

    If `progress_callback` is given it is called as
    progress_callback(step, n_candidates) at the start of each step, before its
    AutoGuess solves run -- n_candidates is the remaining S-box pool (8, 7, ...).
    """
    if not sbox_records:
        raise ValueError("estimate_dynamic_autoguess_greedy: empty sbox_records")

    # per-S-box filter (bits), precomputed once
    filter_of = {make_unit_id(r): float(conditional_target_side_filter_for_record(r))
                 for r in sbox_records}
    # An infinite filter means the DDT allows NO transition between the record's two
    # patterns: the trail and the propagated extension contradict each other, so
    # there is nothing to estimate. Left alone it would sort first and silently wipe
    # the pair set, reporting a cost for an attack that cannot exist.
    impossible = sorted(u for u, f in filter_of.items() if not math.isfinite(f))
    if impossible:
        raise RuntimeError(
            f"Impossible S-box transition(s): {impossible}. The DDT allows no pair "
            f"between the input and output difference patterns the propagation "
            f"assigned, i.e. the distinguisher's boundary difference cannot be "
            f"extended through these S-boxes. Check delta_in/delta_out and the "
            f"round split against the cipher.")

    remaining = list(sbox_records)
    committed_keys = set()   # key variables actually GUESSED -- these are paid for
    known_keys = set()       # committed, plus the ones the key schedule then derives
    key_bits_of = {}         # guessed key variable ID -> its bit width
    key_id_sets = {}
    ordering = []
    stages = []
    selected = []

    # Two running quantities, both as ABSOLUTE log2 counts (these are exactly the
    # "Work" and "Pairs left" columns printed in the report):
    #   log2_pairs_left -> log2(pairs still alive); starts at the full N0
    #   step_work_log2  -> every step's work (a pair count), kept in log2
    # The final key-recovery time is T = sum of the step works, and C_KR = T / N0.
    # The sum is taken in log space at the end: a 128-bit key over a wide extension
    # reaches step works past 2^1024, where `2.0 ** work` raises OverflowError.
    log2_pairs_left = float(N0_log2)
    step_work_log2 = []

    for step in range(1, len(sbox_records) + 1):
        # known = ONLY the key bits we have committed (PT/CT is added inside
        # search_key_recovery). Never feed determined state or targets: that would
        # let a later S-box assume a boundary value it hasn't paid the keys for.
        extra_known = set(known_keys)

        if progress_callback is not None:
            progress_callback(step, len(remaining))

        best = None  # (sort_key, result, new_key_bits, filter_bits, guessed)
        evaluated = []
        for idx, record in enumerate(remaining):
            result = _run_candidate(cipher, record, extra_known,
                                    distinguisher_start, distinguisher_end,
                                    objective_target, show_mode,
                                    config_model, config_solver)
            evaluated.append(result)
            if result.get("solver_failed"):
                # Fail-fast: AutoGuess could not solve this S-box within the limits.
                # Stop the whole run with its message; the user raises maxsteps/
                # maxguess and re-runs (never skip + carry on with a partial result).
                detail = result.get("solver_error") or result.get("autoguess_message", "")
                missing = _missing_dependency(detail)
                if missing:
                    raise RuntimeError(
                        f"AutoGuess cannot run: the package '{missing}' is not installed. "
                        f"This is an environment problem, not a solver limit -- raising "
                        f"maxsteps will not help.\n"
                        f"Install the dependencies with:  pip install -r requirements.txt\n"
                        f"---------------- AutoGuess output ----------------\n"
                        f"{detail}\n"
                        f"--------------------------------------------------")
                raise RuntimeError(
                    f"AutoGuess could not solve S-box {result.get('label', '?')} within "
                    f"the current limits (config_model['maxsteps']="
                    f"{(config_model or {}).get('maxsteps')}, "
                    f"objective_target={objective_target!r}).\n"
                    f"---------------- AutoGuess output ----------------\n"
                    f"{detail}\n"
                    f"--------------------------------------------------\n"
                    f"Raise config_model['maxsteps'] / the 'OPTIMAL AT MOST X' bound "
                    f"in the driver and re-run.")

            unit = result["unit"]
            guessed = _ids(result.get("guessed_variables", []))
            key_bits_of.update(_key_widths(result.get("guessed_variables", [])))
            filter_bits = filter_of[unit]
            # NEW key BITS this S-box adds -- a key variable is a whole word, so
            # count its width, not the number of variables. Variables the key
            # schedule already derives from committed ones are free.
            new_key_bits = sum(key_bits_of.get(v, 1) for v in guessed - known_keys)
            # pick lowest (new key bits - filter); tie-break by S-box order
            sort_key = (new_key_bits - filter_bits, idx)
            if best is None or sort_key < best[0]:
                best = (sort_key, result, new_key_bits, filter_bits, guessed)

        if best is None:
            labels = ", ".join(r.get("label", "?") for r in evaluated)
            raise RuntimeError(f"No remaining S-box could be solved at step {step}. "
                               f"Remaining: {labels}")

        _, result, new_key_bits, filter_bits, guessed = best
        unit = result["unit"]

        # This step tries 2^new_key_bits key guesses for every pair still alive,
        # so its work = (pairs alive) * 2^new_key_bits.  The S-box's differential
        # filter then discards pairs, shrinking the live set for the next step.
        log2_step_work = log2_pairs_left + new_key_bits
        # the right pair passes this S-box's filter too, so the live set never empties
        log2_pairs_left = with_right_pair(log2_step_work - filter_bits)
        step_work_log2.append(log2_step_work)

        new_key_ids = sorted(guessed - known_keys)       # NEW key vars this step
        committed_keys |= (guessed - known_keys)         # only the ones we pay for
        # Everything the selected solve determines in the key schedule comes for
        # free from here on: later S-boxes must not be charged for it again.
        known_keys |= guessed | set(result.get("determined_key_var_ids", []))
        key_id_sets[unit] = guessed
        ordering.append(unit)
        stages.append({
            "delta_K_bits": new_key_bits,
            "filter_bits": filter_bits,
            "filter_model": "conditional_target_side",
            "work_log2": log2_step_work,
            "survivors_log2": log2_pairs_left,
        })
        selected.append(result)
        remaining = [r for r in remaining if make_unit_id(r) != unit]

        if step_callback is not None:
            step_callback(step, unit, stages[-1], new_key_ids)
        elif verbose:
            print(f"  step {step:>2}: {result['label']:<26} "
                  f"dK={new_key_bits} filter={filter_bits:.2f} "
                  f"committed={sum(key_bits_of.get(v, 1) for v in committed_keys)}")

    total_key_bits = sum(key_bits_of.get(v, 1) for v in committed_keys)
    # T is the SUM of every step's work (not the peak):  T = Σ 2^log2_step_work,
    # summed in log space so a step work beyond 2^1024 cannot overflow.
    T_log2 = _log2_sum_exp2(step_work_log2) if step_work_log2 else float(N0_log2)
    return (ordering, stages, key_id_sets, T_log2,
            log2_pairs_left, total_key_bits, selected)
