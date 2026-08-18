"""Truncated forward/backward propagation of differential activity.

Solver-free, one operator at a time, in one of two representations:

  * bit ciphers (word_bitsize == 1, e.g. PRESENT/GIFT/RECTANGLE) carry two flags
    per state bit -- active ("the difference MAY be 1") and fixed ("the difference
    is ALWAYS 1", a subset of active). A bit that is active but not fixed is
    "truncated" (0 or 1); a bit that is not active is always 0.
  * word ciphers (word_bitsize > 1, e.g. SKINNY/LED/AES) carry a per-word
    (fixed_mask, active_mask) pair instead, because one flag cannot hold a
    multi-bit word difference.

Accuracy is a property of the operator, not of the cipher:
  * exact for bit permutations, and for S-boxes (the DDT is read directly);
  * exact for GF(2^m) MixColumns -- `_gf_matrix_propagate` propagates the actual
    value sets (LED's GF(2^4), AES's GF(2^8));
  * an OVER-APPROXIMATION for binary matrices -- `_xor_val_masks` returns a
    superset of the true difference set (SKINNY's MixColumns);
  * conservative (mark everything active) only when the matrix is missing or the
    operator is unrecognised.

The over-approximation is per-word: a set is stored as a product of per-word sets
(a "box"), so correlation a mixing layer creates BETWEEN words is lost. One
extension round puts no linear layer between two S-box layers, so the box is
entered once and the result is exact; from two rounds on the boxing is lossy and
`boundary_pattern_bits` over-states d_in/d_out (see its docstring). The loss is
always in the safe direction: a superset means a larger d_in/d_out and a larger
reported cost, never a smaller one.
"""

from __future__ import annotations

import math

from operators.Sbox import Sbox


# --- small helpers -----------------------------------------------------------

def _is_sbox(op):
    """True if `op` is an S-box.

    Tested against the operator class, not its name. The name test this replaced
    (`cls.endswith("Sbox")`) missed every cipher whose S-box classes are numbered
    -- LBlock's eight are `LBlock_Sbox0` .. `LBlock_Sbox7` -- and a missed S-box
    does not fail loudly: the layer walk finds no active S-box at all, and the
    propagation falls through to its conservative branch and marks the whole
    output active instead of reading the DDT.
    """
    return isinstance(op, Sbox)


def _ids(vars_list):
    """Flatten a (possibly nested) OCP variable list into ID strings."""
    out = []
    for v in vars_list:
        if isinstance(v, (list, tuple)):
            out.extend(x.ID for x in v)
        else:
            out.append(v.ID)
    return out


def _ids_to_mask(wanted, ids):
    """Bit mask of the positions in `ids` whose ID is in the set `wanted`."""
    return sum(1 << i for i, vid in enumerate(ids) if vid in wanted)


def _mask_to_ids(mask, ids):
    """The IDs in `ids` whose bit is set in `mask`."""
    return {ids[i] for i in range(len(ids)) if mask & (1 << i)}


def _pattern_values(fixed, active, n):
    """Every n-bit difference matching the (fixed, active) pattern.
    Naive: try all 2^n values, keep the ones with all fixed bits and no extra."""
    return [d for d in range(2 ** n)
            if (d & fixed) == fixed and (d & ~active) == 0]


def _rev(mask, n):
    """Bit-reverse an n-bit mask. The (fixed, active) masks index S-box variables
    in order (bit i = input_vars[i]), but the DDT is in S-box VALUE order
    (value = in_0<<(n-1) | ... | in_{n-1}, i.e. in_0 is the MSB). So variable bit
    i corresponds to value bit n-1-i: convert with this reversal before/after DDT.
    A no-op for fully-active nibbles, which is why it only matters for partially
    active S-boxes (e.g. RECTANGLE columns)."""
    return sum(((mask >> i) & 1) << (n - 1 - i) for i in range(n))


def _ensure_ddt(op):
    """Compute and cache the S-box DDT on the operator if missing."""
    ddt = getattr(op, "ddt", None)
    if ddt is None and hasattr(op, "computeDDT"):
        ddt = op.computeDDT()
        op.ddt = ddt
    return ddt


def _gf2_inverse(mat):
    """Invert a square binary matrix over GF(2). None if singular."""
    n = len(mat)
    if any(len(row) != n for row in mat):
        return None
    A = [list(row) + [1 if j == i else 0 for j in range(n)] for i, row in enumerate(mat)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if A[r][col] == 1), None)
        if pivot is None:
            return None
        if pivot != col:
            A[col], A[pivot] = A[pivot], A[col]
        for r in range(n):
            if r != col and A[r][col] == 1:
                A[r] = [A[r][k] ^ A[col][k] for k in range(2 * n)]
    return [row[n:] for row in A]


_MAT_INVERSE_CACHE = {}


def _matrix_inverse(op):
    """mat^{-1} for a Matrix op over GF(2), cached by op identity."""
    key = id(op)
    if key not in _MAT_INVERSE_CACHE:
        mat = getattr(op, "mat", None)
        _MAT_INVERSE_CACHE[key] = _gf2_inverse(mat) if mat is not None else None
    return _MAT_INVERSE_CACHE[key]


def _matrix_propagate(in_ids, out_ids, mat, active_set):
    """out[i] active iff some in[j] with a NONZERO coefficient mat[i][j] is active.
    Over GF(2^m) the coefficients can be any nonzero field element (2, 3, ...), not
    just 1, so the support test is `!= 0`, not `== 1` (== 1 would silently drop the
    activity of every non-binary MDS coefficient, e.g. AES/LED MixColumns)."""
    result = set()
    for i, oi in enumerate(out_ids):
        if i >= len(mat):
            continue
        for j, val in enumerate(mat[i]):
            if j < len(in_ids) and val != 0 and in_ids[j] in active_set:
                result.add(oi)
                break
    return result


# --- one S-box: truncated (fixed, active) on each side -----------------------

def _sbox_forward(op, in_fixed, in_active):
    """Forward through one S-box: over every allowed input difference, collect
    the reachable output differences (active = their OR, fixed = their AND).
    Returns (out_fixed, out_active), or None if DDT missing / no transition."""
    ddt = _ensure_ddt(op)
    if ddt is None:
        return None
    if in_active == 0:
        return 0, 0
    n_in, n_out = len(_ids(op.input_vars)), len(_ids(op.output_vars))
    in_fixed, in_active = _rev(in_fixed, n_in), _rev(in_active, n_in)  # mask -> value order
    out_active, out_fixed, saw_any = 0, (1 << n_out) - 1, False
    for dx in _pattern_values(in_fixed, in_active, n_in):
        if dx < len(ddt):
            for dy, count in enumerate(ddt[dx]):
                if count > 0:
                    out_active |= dy
                    out_fixed &= dy
                    saw_any = True
    if not saw_any:
        return None
    out_fixed &= out_active
    mask = (1 << n_out) - 1
    return _rev(out_fixed & mask, n_out), _rev(out_active & mask, n_out)  # value -> mask order


def _sbox_backward(op, out_fixed, out_active):
    """Backward mirror of _sbox_forward."""
    ddt = _ensure_ddt(op)
    if ddt is None:
        return None
    if out_active == 0:
        return 0, 0
    n_in, n_out = len(_ids(op.input_vars)), len(_ids(op.output_vars))
    out_fixed, out_active = _rev(out_fixed, n_out), _rev(out_active, n_out)  # mask -> value order
    in_active, in_fixed, saw_any = 0, (1 << n_in) - 1, False
    for dy in _pattern_values(out_fixed, out_active, n_out):
        for dx in range(len(ddt)):
            if dy < len(ddt[dx]) and ddt[dx][dy] > 0:
                in_active |= dx
                in_fixed &= dx
                saw_any = True
    if not saw_any:
        return None
    in_fixed &= in_active
    mask = (1 << n_in) - 1
    return _rev(in_fixed & mask, n_in), _rev(in_active & mask, n_in)  # value -> mask order


# --- word-aware VALUE propagation (word_bitsize > 1) -------------------------
#
# The set-based (fixed, active) machinery above tracks one flag PER VARIABLE.
# For a bit cipher (word_bitsize == 1) one S-box variable == one bit, so that is
# exactly bit-granular and correct. For a nibble/byte cipher (SKINNY, AES, ...)
# one S-box variable == one whole word, so a single flag cannot hold the word's
# multi-bit difference and the DDT masks collapse to a single bit (-> filter=inf).
#
# The functions below carry, per state word, an actual (fmask, amask) difference
# in VALUE order (bit j == value bit j, so masks index the DDT directly with no
# _rev). Seeded from the trail's exact boundary delta and pushed through the
# linear layers exactly (XOR of nibble diffs) and the S-boxes via the DDT.

def _is_binary_matrix(mat):
    """True if every matrix entry is 0/1 (GF(2)); then a MixColumns output is a
    plain XOR of its input words and exact difference values survive it."""
    return all(v in (0, 1) for row in mat for v in row)


def _gf_image(coeff, fmask, amask, n, poly):
    """The set of values {coeff * x} for x matching the (fmask, amask) pattern,
    multiplied in GF(2^n). Multiplication by a non-zero constant is a GF(2)-linear
    bijection, so this is exact; n is 4 or 8 in practice, so enumerating is cheap."""
    from operators.matrix import _normalize_mod_poly, gf2_multiply
    mod = _normalize_mod_poly(poly, n)
    return {gf2_multiply(coeff, x, mod, n) for x in _pattern_values(fmask, amask, n)}


def _xor_value_sets(sets):
    """XOR-combine sets of word values. Each set holds n-bit values, so the
    combination never exceeds 2^n elements -- no blow-up."""
    acc = {0}
    for s in sets:
        if not s:
            return set()
        acc = {a ^ b for a in acc for b in s}
    return acc


def _set_to_val_mask(values):
    """Bounding (fmask, amask) of a set of word values: bits set in every value are
    forced, bits set in any value are active."""
    if not values:
        return (0, 0)
    fixed = None
    active = 0
    for v in values:
        fixed = v if fixed is None else (fixed & v)
        active |= v
    return (fixed, active)


_GF_MAT_INVERSE_CACHE = {}


def _gf_matrix_inverse(op):
    """mat^{-1} over GF(2^m), cached. The operator inverts itself using its own
    irreducible polynomial; the GF(2) inverse used elsewhere cannot do this."""
    key = id(op)
    if key not in _GF_MAT_INVERSE_CACHE:
        try:
            _GF_MAT_INVERSE_CACHE[key] = op.inverse_over_gf2m()
        except Exception:
            _GF_MAT_INVERSE_CACHE[key] = None
    return _GF_MAT_INVERSE_CACHE[key]


def _gf_matrix_propagate(mat, in_ids, out_ids, g, n, poly):
    """Push word differences through a GF(2^m) matrix (LED / AES MixColumns).

    Each output word is the GF(2^m) combination of its input words. Working with
    the actual value sets keeps this exact where the binary-matrix path would XOR
    masks; the result is then boxed back into (fmask, amask) for the record.
    """
    res = {}
    for i, oi in enumerate(out_ids):
        if i >= len(mat):
            continue
        sets = []
        for j in range(len(mat[i])):
            if j >= len(in_ids) or mat[i][j] == 0:
                continue
            f, a = g(in_ids[j])
            if a == 0 and f == 0:
                continue                      # inactive word contributes nothing
            sets.append(_gf_image(mat[i][j], f, a, n, poly))
        if not sets:
            continue
        m = _set_to_val_mask(_xor_value_sets(sets))
        if m[1]:
            res[oi] = m
    return res


def _xor_val_masks(masks):
    """XOR-combine a list of (fmask, amask) word diffs (value order).

    Per bit position: an operand either pins it (forced part) or leaves it free.
    The XOR is free at that position iff SOME operand leaves it free; otherwise it
    is pinned to the XOR of the operands' forced bits. So the forced information
    survives a truncated operand -- only the positions that operand actually leaves
    free are lost. Exact (a == f) iff no operand leaves any position free.

    Still an over-approximation: the masks are per word, so two operands whose free
    bits share a source are treated as independent when their XOR is in fact
    determined. The result is always a superset of the true difference set.
    """
    masks = [(f, a) for f, a in masks if a != 0 or f != 0]
    if not masks:
        return (0, 0)
    free = 0    # positions some operand leaves free
    xf = 0      # XOR of the pinned parts
    for f, a in masks:
        free |= a & ~f
        xf ^= f
    if free == 0:
        return (xf, xf)
    return (xf & ~free, xf | free)


def _sbox_fwd_val(op, in_fmask, in_amask):
    """Forward through one S-box in VALUE order: over every input difference in the
    (fmask, amask) pattern, OR/AND the reachable output differences. Masks are the
    S-box's input_bitsize/output_bitsize wide, NOT the variable count."""
    ddt = _ensure_ddt(op)
    if ddt is None:
        return None
    if in_amask == 0:
        return (0, 0)
    n_in, n_out = op.input_bitsize, op.output_bitsize
    out_amask, out_fmask, saw_any = 0, (1 << n_out) - 1, False
    for dx in _pattern_values(in_fmask, in_amask, n_in):
        if dx < len(ddt):
            for dy, count in enumerate(ddt[dx]):
                if count > 0:
                    out_amask |= dy
                    out_fmask &= dy
                    saw_any = True
    if not saw_any:
        return None
    out_fmask &= out_amask
    return (out_fmask, out_amask)


def _sbox_bwd_val(op, out_fmask, out_amask):
    """Backward mirror of _sbox_fwd_val (VALUE order)."""
    ddt = _ensure_ddt(op)
    if ddt is None:
        return None
    if out_amask == 0:
        return (0, 0)
    n_in, n_out = op.input_bitsize, op.output_bitsize
    in_amask, in_fmask, saw_any = 0, (1 << n_in) - 1, False
    for dy in _pattern_values(out_fmask, out_amask, n_out):
        for dx in range(len(ddt)):
            if dy < len(ddt[dx]) and ddt[dx][dy] > 0:
                in_amask |= dx
                in_fmask &= dx
                saw_any = True
    if not saw_any:
        return None
    in_fmask &= in_amask
    return (in_fmask, in_amask)


def _prop_op_val_forward(op, state, wb):
    """One operator forward on a value-mask state {var_id: (fmask, amask)}.
    Returns only the ops' OUTPUT words (mirrors the set-based _apply_layer)."""
    cls = op.__class__.__name__
    if cls == "NoneOperator":
        return {}
    in_ids, out_ids = _ids(op.input_vars), _ids(op.output_vars)
    g = lambda vid: state.get(vid, (0, 0))
    full = (1 << wb) - 1

    if _is_sbox(op):
        f, a = g(in_ids[0])
        if a == 0:
            return {}
        r = _sbox_fwd_val(op, f, a)
        return {out_ids[0]: r if r is not None else (0, full)}

    if cls in ("Equal", "ConstantXOR"):                # Δconst = 0 -> value passes
        return {oi: g(ii) for ii, oi in zip(in_ids, out_ids) if g(ii) != (0, 0)}

    if cls == "XOR":                                   # ARK: out = state ^ subkey, Δsubkey=0
        if len(in_ids) == 2 * len(out_ids):
            return {oi: g(in_ids[2 * k]) for k, oi in enumerate(out_ids)
                    if g(in_ids[2 * k]) != (0, 0)}
        m = _xor_val_masks([g(i) for i in in_ids])
        return {oi: m for oi in out_ids} if m[1] else {}

    if cls == "Matrix":
        mat = getattr(op, "mat", None)
        if mat is not None and _is_binary_matrix(mat):
            res = {}
            for i, oi in enumerate(out_ids):
                if i >= len(mat):
                    continue
                contrib = [g(in_ids[j]) for j in range(len(mat[i]))
                           if j < len(in_ids) and mat[i][j] != 0]
                m = _xor_val_masks(contrib)
                if m[1]:
                    res[oi] = m
            return res
        poly = getattr(op, "polynomial", None)
        if mat is not None and poly:            # GF(2^m) MixColumns (LED, AES)
            return _gf_matrix_propagate(mat, in_ids, out_ids, g, wb, poly)
        # no matrix / no polynomial: conservative -> all active
        return ({oi: (0, full) for oi in out_ids}
                if any(g(i)[1] for i in in_ids) else {})

    # unrecognised: conservative -> mark every output word fully active
    return {oi: (0, full) for oi in out_ids} if any(g(i)[1] for i in in_ids) else {}


def _prop_op_val_backward(op, state, wb):
    """Backward mirror of _prop_op_val_forward."""
    cls = op.__class__.__name__
    if cls == "NoneOperator":
        return {}
    in_ids, out_ids = _ids(op.input_vars), _ids(op.output_vars)
    g = lambda vid: state.get(vid, (0, 0))
    full = (1 << wb) - 1

    if _is_sbox(op):
        f, a = g(out_ids[0])
        if a == 0:
            return {}
        r = _sbox_bwd_val(op, f, a)
        return {in_ids[0]: r if r is not None else (0, full)}

    if cls in ("Equal", "ConstantXOR"):
        return {ii: g(oi) for ii, oi in zip(in_ids, out_ids) if g(oi) != (0, 0)}

    if cls == "XOR":
        if len(in_ids) == 2 * len(out_ids):
            return {in_ids[2 * k]: g(oi) for k, oi in enumerate(out_ids)
                    if g(oi) != (0, 0)}
        m = _xor_val_masks([g(o) for o in out_ids])
        return {ii: m for ii in in_ids} if m[1] else {}

    if cls == "Matrix":
        inv = _matrix_inverse(op)
        if inv is not None and _is_binary_matrix(inv):
            res = {}
            for j, ii in enumerate(in_ids):
                if j >= len(inv):
                    continue
                contrib = [g(out_ids[i]) for i in range(len(inv[j]))
                           if i < len(out_ids) and inv[j][i] != 0]
                m = _xor_val_masks(contrib)
                if m[1]:
                    res[ii] = m
            return res
        poly = getattr(op, "polynomial", None)
        if poly:                                # GF(2^m) MixColumns, inverted
            # _matrix_inverse is GF(2)-only and returns None here; the operator
            # knows how to invert itself over its own field.
            gf_inv = _gf_matrix_inverse(op)
            if gf_inv is not None:
                return _gf_matrix_propagate(gf_inv, out_ids, in_ids, g, wb, poly)
        return ({ii: (0, full) for ii in in_ids}
                if any(g(o)[1] for o in out_ids) else {})

    return {ii: (0, full) for ii in in_ids} if any(g(o)[1] for o in out_ids) else {}


def _apply_layer_val(ops, state, prop, wb):
    """Push a value-mask state through one layer's ops, keeping only outputs."""
    new = {}
    for op in ops or []:
        for vid, (f, a) in prop(op, state, wb).items():
            if a == 0 and f == 0:
                continue
            if vid in new:                              # rare: two ops write one word
                pf, pa = new[vid]
                new[vid] = (pf & f, pa | a)
            else:
                new[vid] = (f, a)
    return new


# --- one operator: dispatch on its type --------------------------------------

def _propagate_op_pair_forward(op, fixed_set, active_set):
    cls = op.__class__.__name__
    if cls == "NoneOperator":
        return set(), set()

    in_ids = _ids(op.input_vars)
    out_ids = _ids(op.output_vars)
    any_active = any(i in active_set for i in in_ids)

    if _is_sbox(op):
        if not any_active:
            return set(), set()
        res = _sbox_forward(op, _ids_to_mask(fixed_set, in_ids),
                            _ids_to_mask(active_set, in_ids))
        if res is None:
            return set(), set(out_ids)              # unknown -> all active
        out_fixed, out_active = res
        return _mask_to_ids(out_fixed, out_ids), _mask_to_ids(out_active, out_ids)

    if cls in ("Equal", "ConstantXOR", "Rot"):       # bit-wise pass-through
        new_fixed, new_active = set(), set()
        for ii, oi in zip(in_ids, out_ids):
            if ii in active_set:
                new_active.add(oi)
            if ii in fixed_set:
                new_fixed.add(oi)
        return new_fixed, new_active

    if cls == "XOR":                                 # ARK: out = state ^ subkey, Δsubkey=0
        if len(in_ids) == 2 * len(out_ids):
            new_fixed, new_active = set(), set()
            for k, oi in enumerate(out_ids):
                state_id = in_ids[2 * k]              # state is the first of each pair
                if state_id in active_set:
                    new_active.add(oi)
                if state_id in fixed_set:
                    new_fixed.add(oi)
            return new_fixed, new_active
        return (set(), set(out_ids)) if any_active else (set(), set())

    if cls == "Matrix":
        mat = getattr(op, "mat", None)
        if mat is None:
            return (set(), set(out_ids)) if any_active else (set(), set())
        return set(), _matrix_propagate(in_ids, out_ids, mat, active_set)  # fixed dropped

    # GF2Linear_Trans and anything unrecognised: conservative -> all outputs active
    return (set(), set(out_ids)) if any_active else (set(), set())


def _propagate_op_pair_backward(op, fixed_set, active_set):
    cls = op.__class__.__name__
    if cls == "NoneOperator":
        return set(), set()

    in_ids = _ids(op.input_vars)
    out_ids = _ids(op.output_vars)
    any_active = any(o in active_set for o in out_ids)

    if _is_sbox(op):
        if not any_active:
            return set(), set()
        res = _sbox_backward(op, _ids_to_mask(fixed_set, out_ids),
                             _ids_to_mask(active_set, out_ids))
        if res is None:
            return set(), set(in_ids)
        in_fixed, in_active = res
        return _mask_to_ids(in_fixed, in_ids), _mask_to_ids(in_active, in_ids)

    if cls in ("Equal", "ConstantXOR", "Rot"):
        new_fixed, new_active = set(), set()
        for ii, oi in zip(in_ids, out_ids):
            if oi in active_set:
                new_active.add(ii)
            if oi in fixed_set:
                new_fixed.add(ii)
        return new_fixed, new_active

    if cls == "XOR":
        if len(in_ids) == 2 * len(out_ids):
            new_fixed, new_active = set(), set()
            for k, oi in enumerate(out_ids):
                state_id = in_ids[2 * k]
                if oi in active_set:
                    new_active.add(state_id)
                if oi in fixed_set:
                    new_fixed.add(state_id)
            return new_fixed, new_active
        return (set(), set(in_ids)) if any_active else (set(), set())

    if cls == "Matrix":
        inv = _matrix_inverse(op)
        if inv is None:
            return (set(), set(in_ids)) if any_active else (set(), set())
        return set(), _matrix_propagate(out_ids, in_ids, inv, active_set)

    return (set(), set(in_ids)) if any_active else (set(), set())


# --- walking layers and rounds -----------------------------------------------

def _layer_ops(perm_func, r, layer):
    """The ops at constraints[r][layer], or None if out of range."""
    try:
        return perm_func.constraints[r][layer]
    except (IndexError, KeyError, TypeError):
        return None


def _apply_layer(ops, fixed, active, propagate_op):
    """Push (fixed, active) through one layer's ops, unioning the results."""
    new_fixed, new_active = set(), set()
    for op in ops or []:
        f, a = propagate_op(op, fixed, active)
        new_fixed |= f
        new_active |= a
    return new_fixed, new_active


def propagate_pair_forward(perm_func, start_fixed, start_active, *, start_round, num_rounds):
    """Forward (fixed, active) propagation through num_rounds."""
    fixed, active = set(start_fixed), set(start_active)
    for r in range(start_round, start_round + num_rounds):
        for layer in range(perm_func.nbr_layers + 1):
            ops = _layer_ops(perm_func, r, layer)
            if ops:
                fixed, active = _apply_layer(ops, fixed, active, _propagate_op_pair_forward)
    return fixed, active


def propagate_pair_backward(perm_func, end_fixed, end_active, *, end_round, num_rounds):
    """Backward (fixed, active) propagation through num_rounds."""
    fixed, active = set(end_fixed), set(end_active)
    for r in range(end_round, end_round - num_rounds, -1):
        for layer in range(perm_func.nbr_layers, -1, -1):
            ops = _layer_ops(perm_func, r, layer)
            if ops:
                fixed, active = _apply_layer(ops, fixed, active, _propagate_op_pair_backward)
    return fixed, active


# --- d_in / d_out: how wide the difference spreads at PT / CT -----------------

def propagated_d_out_bits(cipher, output_active_positions, *, distinguisher_end, r_f):
    """d_out bits at the ciphertext side via r_f-round forward propagation."""
    if r_f <= 0:
        return None
    perm = cipher.functions["PERMUTATION"]
    start = distinguisher_end + 1
    active = {perm.vars[start][0][i].ID for i in output_active_positions}
    _, final = propagate_pair_forward(perm, active, active, start_round=start, num_rounds=r_f)
    return len(final) * perm.word_bitsize


def propagated_d_in_bits(cipher, input_active_positions, *, distinguisher_start, r_b):
    """d_in bits at the plaintext side via r_b-round backward propagation.
    Subkey IDs are stripped -- the ARK XOR returns both state and subkey inputs,
    but only the state bits count at the plaintext."""
    if r_b <= 0:
        return None
    perm = cipher.functions["PERMUTATION"]
    end = distinguisher_start - 1
    active = {perm.vars[distinguisher_start][0][i].ID for i in input_active_positions}
    _, final = propagate_pair_backward(perm, active, active, end_round=end, num_rounds=r_b)
    state_only = {vid for vid in final
                  if not (vid.startswith("vk_") or vid.startswith("vsk_") or vid.startswith("k_"))}
    return len(state_only) * perm.word_bitsize


def boundary_pattern_bits(sbox_records, side):
    """log2 |set of PT (side='backward') / CT (side='forward') differences reachable|.

    This is d_in / d_out as the paper defines them: `|D_in| = 2^d_in`, a set size.
    Counting active bits -- what `propagated_d_*_bits` does -- only equals that size
    when the set is a box, i.e. every combination of the active bits occurs. Two
    things break that: a bit forced to 1 (the box calls it free), and a mixing
    linear layer, which makes the bits dependent -- SKINNY's MixColumns spreads a
    16-dimensional space over 40 active bits.

    Read at the outermost extension S-box layer, because everything between it and
    the PT/CT is a key-independent bijection and so cannot change the set's size.
    """
    rs = [r for r in sbox_records if r["side"] == side]
    if not rs:
        return None
    edge = (max if side == "forward" else min)(r["round"] for r in rs)
    key = "output" if side == "forward" else "input"
    total = 0.0
    for r in rs:
        if r["round"] != edge:
            continue
        op = r["op"]
        n = op.output_bitsize if side == "forward" else op.input_bitsize
        values = _pattern_values(_rev(r[f"{key}_fixed_mask"], n),
                                 _rev(r[f"{key}_active_mask"], n), n)
        total += math.log2(len(values))
    return total


# --- finding the active S-boxes in the extension rounds ----------------------

def find_sbox_layer(perm_func, round_idx):
    """The layer index that holds S-box ops in round_idx, or None."""
    for layer in range(perm_func.nbr_layers + 1):
        for op in _layer_ops(perm_func, round_idx, layer) or []:
            if _is_sbox(op):
                return layer
    return None


def find_active_sboxes_at_layer(perm_func, round_idx, layer_idx,
                                fixed_var_ids, active_var_ids, *, side="forward"):
    """Active S-box records at (round_idx, layer_idx). Each record carries the
    (fixed, active) masks on both sides, the op, its var IDs, and input positions.
    side="forward" keeps boxes with an active input; "backward" an active output."""
    ops = _layer_ops(perm_func, round_idx, layer_idx)
    if not ops:
        return []
    pos_of_var = {v.ID: idx for idx, v in enumerate(perm_func.vars[round_idx][layer_idx])}

    out = []
    for op in ops:
        if not _is_sbox(op):
            continue
        in_ids = _ids(op.input_vars)
        out_ids = _ids(op.output_vars)

        if side == "forward":
            if not any(vid in active_var_ids for vid in in_ids):
                continue
            in_fixed = _ids_to_mask(fixed_var_ids, in_ids)
            in_active = _ids_to_mask(active_var_ids, in_ids)
            res = _sbox_forward(op, in_fixed, in_active)
            out_fixed, out_active = res if res is not None else (0, (1 << len(out_ids)) - 1)
        else:
            if not any(vid in active_var_ids for vid in out_ids):
                continue
            out_fixed = _ids_to_mask(fixed_var_ids, out_ids)
            out_active = _ids_to_mask(active_var_ids, out_ids)
            res = _sbox_backward(op, out_fixed, out_active)
            in_fixed, in_active = res if res is not None else (0, (1 << len(in_ids)) - 1)

        out.append({
            "op": op, "round": round_idx, "layer": layer_idx,
            "input_var_ids": in_ids, "output_var_ids": out_ids,
            "input_positions": [pos_of_var.get(vid, -1) for vid in in_ids],
            "input_fixed_mask": in_fixed, "input_active_mask": in_active,
            "output_fixed_mask": out_fixed, "output_active_mask": out_active,
        })
    return out


def _find_active_sboxes_val(perm_func, round_idx, layer_idx, state, *, side):
    """Word-cipher counterpart of find_active_sboxes_at_layer. `state` is a value-
    mask dict {var_id: (fmask, amask)} in VALUE order. The record masks are stored
    in the convention ddt_filter expects (it applies _rev), so we pre-_rev them."""
    ops = _layer_ops(perm_func, round_idx, layer_idx)
    if not ops:
        return []
    pos_of_var = {v.ID: idx for idx, v in enumerate(perm_func.vars[round_idx][layer_idx])}

    out = []
    for op in ops:
        if not _is_sbox(op):
            continue
        in_ids, out_ids = _ids(op.input_vars), _ids(op.output_vars)
        n_in, n_out = op.input_bitsize, op.output_bitsize

        if side == "forward":
            in_f, in_a = state.get(in_ids[0], (0, 0))
            if in_a == 0:
                continue
            r = _sbox_fwd_val(op, in_f, in_a)
            out_f, out_a = r if r is not None else (0, (1 << n_out) - 1)
        else:
            out_f, out_a = state.get(out_ids[0], (0, 0))
            if out_a == 0:
                continue
            r = _sbox_bwd_val(op, out_f, out_a)
            in_f, in_a = r if r is not None else (0, (1 << n_in) - 1)

        out.append({
            "op": op, "round": round_idx, "layer": layer_idx,
            "input_var_ids": in_ids, "output_var_ids": out_ids,
            "input_positions": [pos_of_var.get(vid, -1) for vid in in_ids],
            "input_fixed_mask": _rev(in_f, n_in), "input_active_mask": _rev(in_a, n_in),
            "output_fixed_mask": _rev(out_f, n_out), "output_active_mask": _rev(out_a, n_out),
        })
    return out


def make_unit_id(rec):
    """Stable label for an active S-box record, e.g. sb_b_r2_[32,33,34,35]."""
    pos = "[" + ",".join(str(p) for p in rec["input_positions"]) + "]"
    return f"sb_{rec['side'][0]}_r{rec['round']}_{pos}"


def _extract_word(cipher, *, input_active_values, output_active_values,
                  distinguisher_start, distinguisher_end, r_b, r_f):
    """Word-cipher (word_bitsize > 1) extraction: seed the extension walk with the
    trail's EXACT boundary difference values and carry them (value-mask state) so
    each S-box record gets a full-width nibble/byte difference, not a 1-bit stub."""
    perm = cipher.functions["PERMUTATION"]
    nlayers, wb = perm.nbr_layers, perm.word_bitsize
    out = []

    def walk(direction, r, layers, state):
        prop = _prop_op_val_forward if direction == "forward" else _prop_op_val_backward
        for layer in layers:
            ops = _layer_ops(perm, r, layer)
            if ops:
                state = _apply_layer_val(ops, state, prop, wb)
        return state

    if r_f > 0 and output_active_values:
        state = {perm.vars[distinguisher_end + 1][0][i].ID: (v, v)   # exact delta
                 for i, v in output_active_values.items()}
        for r in range(distinguisher_end + 1, distinguisher_end + r_f + 1):
            sbox_layer = find_sbox_layer(perm, r)
            if sbox_layer is None:
                continue
            state = walk("forward", r, range(0, sbox_layer), state)
            boxes = _find_active_sboxes_val(perm, r, sbox_layer, state, side="forward")
            for s in boxes:
                s["side"] = "forward"
            out.extend(boxes)
            state = walk("forward", r, range(sbox_layer, nlayers + 1), state)

    if r_b > 0 and input_active_values:
        state = {perm.vars[distinguisher_start][0][i].ID: (v, v)
                 for i, v in input_active_values.items()}
        for r in range(distinguisher_start - 1, distinguisher_start - r_b - 1, -1):
            sbox_layer = find_sbox_layer(perm, r)
            if sbox_layer is None:
                continue
            state = walk("backward", r, range(nlayers, sbox_layer, -1), state)
            boxes = _find_active_sboxes_val(perm, r, sbox_layer, state, side="backward")
            for s in boxes:
                s["side"] = "backward"
            out.extend(boxes)
            state = walk("backward", r, range(sbox_layer, -1, -1), state)

    return out


def extract_extension_active_sboxes(cipher, *, input_active_positions, output_active_positions,
                                    distinguisher_start, distinguisher_end, r_b, r_f,
                                    input_active_values=None, output_active_values=None):
    """Walk the r_b backward and r_f forward extension rounds; return the active
    S-box records, each tagged side="forward"/"backward". At the distinguisher
    boundary the trail fixes a specific delta, so fixed = active there.

    Bit ciphers (word_bitsize == 1) use the set-based path below unchanged. Nibble/
    byte ciphers route to the value-mask path, which needs the boundary delta values
    (a 1-bit-per-variable flag cannot represent a multi-bit word difference)."""
    perm = cipher.functions["PERMUTATION"]
    if perm.word_bitsize > 1:
        return _extract_word(
            cipher, input_active_values=input_active_values or {},
            output_active_values=output_active_values or {},
            distinguisher_start=distinguisher_start, distinguisher_end=distinguisher_end,
            r_b=r_b, r_f=r_f)
    nlayers = perm.nbr_layers
    out = []

    def walk(direction, r, layers, fixed, active):
        propagate_op = (_propagate_op_pair_forward if direction == "forward"
                        else _propagate_op_pair_backward)
        for layer in layers:
            ops = _layer_ops(perm, r, layer)
            if ops:
                fixed, active = _apply_layer(ops, fixed, active, propagate_op)
        return fixed, active

    if r_f > 0:
        ids = {perm.vars[distinguisher_end + 1][0][i].ID for i in output_active_positions}
        fixed, active = set(ids), set(ids)
        for r in range(distinguisher_end + 1, distinguisher_end + r_f + 1):
            sbox_layer = find_sbox_layer(perm, r)
            if sbox_layer is None:
                continue
            fixed, active = walk("forward", r, range(0, sbox_layer), fixed, active)
            boxes = find_active_sboxes_at_layer(perm, r, sbox_layer, fixed, active, side="forward")
            for s in boxes:
                s["side"] = "forward"
            out.extend(boxes)
            fixed, active = walk("forward", r, range(sbox_layer, nlayers + 1), fixed, active)

    if r_b > 0:
        ids = {perm.vars[distinguisher_start][0][i].ID for i in input_active_positions}
        fixed, active = set(ids), set(ids)
        for r in range(distinguisher_start - 1, distinguisher_start - r_b - 1, -1):
            sbox_layer = find_sbox_layer(perm, r)
            if sbox_layer is None:
                continue
            fixed, active = walk("backward", r, range(nlayers, sbox_layer, -1), fixed, active)
            boxes = find_active_sboxes_at_layer(perm, r, sbox_layer, fixed, active, side="backward")
            for s in boxes:
                s["side"] = "backward"
            out.extend(boxes)
            fixed, active = walk("backward", r, range(sbox_layer, -1, -1), fixed, active)

    return out
