"""Console report for the AutoGuess key-recovery estimate."""

from __future__ import annotations


def _print_key_vars(ids, indent="        ", width=100):
    """Print key var IDs, wrapped to `width`, never truncated."""
    if not ids:
        print(f"{indent}key vars: (none)")
        return
    label = "key vars: "
    line = indent + label
    cont = indent + " " * len(label)
    for i, vid in enumerate(ids):
        tok = vid if i == 0 else ", " + vid
        if len(line) + len(tok) > width and line.strip():
            print(line)
            line = cont + vid
        else:
            line += tok
    print(line)


# Shared column layout so the Ordering header and rows stay aligned.
_ORDERING_ROW = "  {:<6}{:<52}{:>6}      {:<14}{:<16}{:<16}"


def n_is_upper_bound(p, d_in):
    """True when `N` counts more pairs than the data can form.

    `N` takes its 2^{p+d_in} pairs from 2^{p-d_in+1} structures of size 2^{d_in}.
    That structure count falls below one exactly when `d_in > p + 1`, and past
    that point the attack builds a single partial structure of 2^{p+1}
    plaintexts, which forms only 2^{2p+1} pairs. Boura et al.'s formula is stated
    without the bound and their own PRESENT-80 rows with `d_in = 64 > p + 1 = 63`
    use it unchanged, so it is kept as printed and flagged instead: the overshoot
    counts pairs that do not exist, which raises `N` and `T` and never lowers
    them.
    """
    return d_in > p + 1


def print_header_and_trail(*, cipher_name, R_d, r_b, r_f, dist_start, dist_end, p,
                           n_active_sboxes, d_in, d_out, N_log2, D_log2, M_log2,
                           modeled_rounds=None):
    """Title line + the Trail block (printed BEFORE any AutoGuess work runs)."""
    total = r_b + R_d + r_f
    modeled = f", modeled {modeled_rounds}" if modeled_rounds not in (None, total) else ""
    print(f"\n{cipher_name}")
    print(f"R_d={R_d}, r_b={r_b}, r_f={r_f}   (attack {total} rounds{modeled}, "
          f"distinguisher = [{dist_start}, {dist_end}])")

    print("\nTrail")
    print(f"  weight p       = {p}")
    print(f"  active S-boxes = {n_active_sboxes}")
    print(f"  d_in           = {d_in:g}")
    print(f"  d_out          = {d_out:g}")
    print(f"  N              = 2^{N_log2:.2f}")
    print(f"  D (data)       = 2^{D_log2:.2f}")
    print(f"  M (memory)     = 2^{M_log2:.2f}")
    if n_is_upper_bound(p, d_in):
        print(f"  [INFO] d_in > p+1: the data forms 2^{2 * p + 1:.2f} pairs, N is counted "
              f"from 2^{p + d_in:.2f}.")
        print(f"         Fewer than one full structure is available, so N -- and hence T "
              f"-- is an upper bound here.")


def print_ordering_header(n_sboxes):
    """Ordering title + column header + rule (printed before the rows stream in)."""
    print(f"\nOrdering ({n_sboxes} S-boxes)  [AutoGuess + conditional target-side filter]")
    hdr = _ORDERING_ROW.format("Step", "S-box", "ΔK", "filter", "Work", "Pairs left")
    print(hdr)
    print("  " + "─" * (len(hdr) - 2) + "\n")


def print_step_progress(step, n_candidates):
    """Live progress line printed before a step's AutoGuess solves run, showing
    how many candidate S-boxes are evaluated this step (8, then 7, ...)."""
    plural = "es" if n_candidates != 1 else ""
    print(f"  step {step}: solving {n_candidates} candidate S-box{plural} ...", flush=True)


def print_ordering_row(step, unit, stage, new_key_ids):
    """One S-box row -- printed the moment its AutoGuess solve commits."""
    print(_ORDERING_ROW.format(step, str(unit), stage["delta_K_bits"],
                               f"{stage['filter_bits']:.2f}",
                               f"2^{stage['work_log2']:.2f}",
                               f"2^{stage['survivors_log2']:.2f}"))
    _print_key_vars(new_key_ids)
    print()


def print_summary(*, C_KR_log2, N_log2, total_K_bits, T_log2, total_filter_bits,
                  key_size_bits, valid_attack, D_log2=None, block_bits=None):
    """Final Summary block. Time = C_KR * N; data complexity is excluded from
    the cost and the validity gate (valid iff C_KR * N < 2^key_size), following
    Boura et al. -- their tables report and gate on exactly this quantity.

    The completion line below is reported, never added to T: after the peel, the
    surviving triplets each fix `total_K_bits` of the key and the rest is filled in
    by search, at a cost of

        N * 2^(|K| - F) * 2^(key_size - |K|)  =  N * 2^(key_size - F)

    in which |K| cancels -- only the total filtering F decides it. F and N are both
    fixed before the greedy starts, so this term is the same whatever order the
    S-boxes are peeled in; the greedy can only move T. It is printed because it is
    a floor on the whole attack, and on a short distinguisher (few active S-boxes,
    hence small F) it is the term that dominates.

    `total_K_bits` is printed as the GUESS BASIS rather than as "key bits
    recovered", because it counts variables, not entropy. AutoGuess may guess key
    material anywhere in the key schedule -- a register bit at round 4 as readily as
    a master-key bit -- and two such variables need not be independent, so the count
    bounds the key entropy fixed rather than equalling it. AES 1+3+1 makes the point
    by reporting 160 for a 128-bit key. The direction is safe: an inflated count
    inflates the per-step work and hence T, never the reverse, and the completion
    term above does not use it at all.
    """
    print("\nSummary")
    print(f"  C_KR (ESTIMATE)      : 2^{C_KR_log2:.2f}")
    print(f"  Guess basis          : {total_K_bits} of {key_size_bits} bits   "
          f"(basis size; an upper bound on the key entropy fixed)")
    print(f"  T = C_KR * N         : 2^{T_log2:.2f}   "
          f"(= 2^{C_KR_log2:.2f} * 2^{N_log2:.2f}; key-recovery work, data cost excluded)")
    print(f"  Total filter F       : {total_filter_bits:.2f} bits")
    completion_log2 = N_log2 + key_size_bits - total_filter_bits
    binds = "DOMINATES T" if completion_log2 > T_log2 else "below T"
    print(f"  Key completion       : 2^{completion_log2:.2f}   "
          f"(= N * 2^({key_size_bits} - F); {binds}, not included in T)")
    if D_log2 is not None and block_bits is not None and D_log2 > block_bits:
        print(f"  [WARN] D = 2^{D_log2:.2f} exceeds the 2^{block_bits} codebook: "
              f"the attack needs more data than the cipher has.")
    why = f"  (T < 2^{key_size_bits})" if valid_attack else f"  (T >= 2^{key_size_bits})"
    print(f"  Valid attack         : {'Yes' if valid_attack else 'No'}{why}")
