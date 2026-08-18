"""Manual trail object for key recovery.

`build_manual_trail(...)` injects a published distinguisher without running a SAT search. The result exposes
`.data` with keys `diff_weight`, `trail_struct`, `rounds`, `cipher`; the
engine only ever reads the two boundary layers.

Convention: bit 0 of an int/hex difference is word 0 (LSB-first); word k
occupies bits [k*word_bitsize, (k+1)*word_bitsize - 1].
"""

from __future__ import annotations


class ManualTrail:
    """Minimal trail object: just holds `.data` for the engine to read."""

    def __init__(self, data):
        self.data = data


def _to_word_values(delta, nbr_words, word_bitsize=1, *, what="delta"):
    """{active word position: its difference VALUE} for a difference.

    `delta` may be an int, a hex/binary string, or -- for a bit cipher only -- a
    list/set of active positions. A position list carries no value, so for
    `word_bitsize > 1` it cannot say WHICH nibble/byte difference is meant and is
    rejected rather than silently read as 1: the extension walk is seeded with
    this exact value, so a wrong value gives wrong filters and a wrong d_in/d_out.
    """
    if isinstance(delta, (list, tuple, set)):
        if word_bitsize > 1:
            raise ValueError(
                f"{what} was given as a list of active positions, but this cipher has "
                f"word_bitsize={word_bitsize}: a position carries no word difference "
                f"value. Pass the difference as an int or hex string, e.g. 0x00a0...")
        return {int(x): 1 for x in delta}
    if isinstance(delta, int):
        value = delta
    elif isinstance(delta, str):
        s = delta.strip().lower().replace(" ", "").replace("_", "")
        if s.startswith(("0x", "0b")):
            value = int(s, 0)
        elif set(s) <= set("01"):
            value = int(s, 2)
        else:
            value = int(s, 16)
    else:
        raise TypeError(f"{what} must be int, str, or list; got {type(delta).__name__}")

    mask = (1 << word_bitsize) - 1
    words = {k: (value >> (k * word_bitsize)) & mask for k in range(nbr_words)}
    return {k: v for k, v in words.items() if v}


def build_manual_trail(*, perm_name="PERMUTATION", nbr_words, word_bitsize=1,
                       R_d, weight, delta_in, delta_out, last_layer=2):
    """Trail for a hand-given distinguisher. Only the two boundary layers are
    filled (round 1 / layer 0 = input, round R_d / last_layer = output).
    weight = -log2(prob); last_layer is the permutation's last layer index,
    i.e. `perm.nbr_layers - 1` (2 for PRESENT, 4 for SKINNY)."""
    in_vals = _to_word_values(delta_in, nbr_words, word_bitsize, what="delta_in")
    out_vals = _to_word_values(delta_out, nbr_words, word_bitsize, what="delta_out")

    def layer(values):
        # A word's difference VALUE, MSB first -- the same convention a searched
        # trail writes (variable index 0 is the S-box's in_0, i.e. the MSB), so the
        # engine reads both kinds of trail with one `int(bin_values, 2)`. For a bit
        # cipher this is exactly the old "1"/"0".
        return {i: {"bin_values": format(values.get(i, 0), f"0{word_bitsize}b")}
                for i in range(nbr_words)}

    perm_block = {"nbr_words": nbr_words, "rounds": list(range(1, R_d + 1))}
    # set the two boundary rounds separately so they don't collide when R_d == 1
    perm_block[1] = {0: layer(in_vals)}
    perm_block.setdefault(R_d, {})[last_layer] = layer(out_vals)

    return ManualTrail({
        "diff_weight": weight,
        "trail_struct": {"functions": {perm_name: perm_block}},
        "rounds": list(range(1, R_d + 1)),
        "cipher": f"{R_d}_round_{perm_name}",
    })
