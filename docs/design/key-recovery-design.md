# key_reco_2 — design

Date: 2026-08-03

## Purpose

`key-reco` is a differential key-recovery estimator built on an old snapshot of
`OCP-with-autoguess`. That snapshot has since been upstreamed to the current
Open-CP/OCP code base, which changed both the code style and the
guess-and-determine API. `key_reco_2` re-establishes the key-recovery layer on
top of the current `OCP-with-autoguess`, written in that repository's
conventions rather than in `key-reco`'s.

## Scope

In scope:

- A fresh, local, non-git directory `/Users/hiren/sourcecodes/key_reco_2`,
  seeded from the current `OCP-with-autoguess` working tree.
- The nine `key-reco` key-recovery modules, ported to OCP conventions.
- The key-recovery test scripts, ported; `present_80_attack.py` verified to run.
- One additive change to `attacks/guess_and_determine.py` (see
  [Objective-target extension](#objective-target-extension)).

Out of scope:

- Any change to `primitives/`. Upstream versions are used verbatim.
- Carrying over `key-reco`'s local edits to `present.py`, `rectangle.py` and
  `tools/autoguess_wrapper.py`.
- `speedy.py`, `chaskey_half.py`, `articles/`, `slides/`.
- Git initialisation, remotes, or history.

## Baseline facts

Established by inspection of both trees on 2026-08-03.

`key-reco` = old OCP + `attacks/key_recovery/` (9 modules, ~90 KB) +
`test/key_recovery/` (6 scripts) + local edits to `present.py`, `rectangle.py`,
`tools/autoguess_wrapper.py`, plus `speedy.py`, `chaskey_half.py`, `articles/`
and `slides/`.

Current `OCP-with-autoguess` conventions:

- Module-level docstring on every module; Google-style docstrings on public
  functions.
- `__init__.py` in every package (`attacks`, `primitives`, `operators`, `tools`,
  `tools/relation_generator_modules`, `variables`, `visualisations`,
  `implementations`, `solving`).
- One module per attack under `attacks/`, each exposing a `search_*` engine.
- `attacks/attacks.py` holds thin timing wrappers over those engines.
- `OCP.py` holds one short demo function per attack family.
- Support code for a large engine lives in a sibling `*_modules/` subpackage
  (precedent: `tools/relation_generator.py` + `tools/relation_generator_modules/`).
- `test/<attack>/` holds runnable scripts.
- `CHANGELOG.md` is maintained.

The blocking incompatibility: `key-reco` calls

```python
search_guess_basis(cipher, target_vars=[...],
                   relgen_cfg=RelGenConfig(...), solver_cfg=SolverConfig(...))
```

Current OCP replaced that with

```python
search_guess_basis(cipher_or_function, goal="GUESSBASIS", known_vars=None,
                   target_vars=None, not_guessed_vars=None,
                   protect_all_targets=False, objective_target="EXISTENCE",
                   show_mode=0, config_model=None, config_solver=None)
```

and documents `RelGenConfig` / `SolverConfig` as internal plumbing that callers
never import. Both config dicts reject unknown keys, so the mapping must be
exact.

`test/key_recovery/toy_attack.py` imports `primitives.toy_cipher`, which does
not exist in `key-reco`. The script is already dead and is dropped.

## Architecture

```
key_reco_2/
  OCP.py                          # + Key Recovery demo section
  CHANGELOG.md                    # + entry for the key-recovery layer
  attacks/
    attacks.py                    # + key_recovery_attack() timing wrapper
    guess_and_determine.py        # + "OPTIMAL AT MOST X" objective target
    key_recovery.py               # engine: search_key_recovery(...)
    key_recovery_modules/
      __init__.py
      propagation.py
      ddt_filter.py
      trail.py
      report.py
      dynamic_greedy.py
      sbox_solver.py
      auto_wrapper.py
  test/key_recovery/
    present_80_attack.py
    rectangle_attack.py
    gift_64_attack.py
    skinny_64_attack.py
    led_64_attack.py
    aes_128_attack.py
    run_attack.py            # the one script the user edits
```

### Unit responsibilities

| Unit | Does | Depends on |
| --- | --- | --- |
| `attacks/key_recovery.py` | Orchestrates the estimate: acquire trail, derive `p`/`d_in`/`d_out`/`N0`, extract extension S-boxes, run the greedy peel, print the report, return the result dict. Owns config parsing and validation. | `key_recovery_modules.*`, `attacks.attacks.diff_attacks` (local import, cycle-avoiding) |
| `attacks/attacks.py::key_recovery_attack` | Timing wrapper; the user-facing entry point. | `attacks.key_recovery` |
| `key_recovery_modules/propagation.py` | Truncated forward/backward propagation of differential activity; `d_in`/`d_out` in bits; extraction of active S-boxes in the extension rounds. Handles both the bit path (`word_bitsize == 1`) and the word-value path. | `operators` |
| `key_recovery_modules/ddt_filter.py` | Per-S-box conditional target-side filter, in bits, from the S-box DDT. | `operators.Sbox.computeDDT` |
| `key_recovery_modules/trail.py` | `build_manual_trail(...)`: wrap a published distinguisher as a trail object with only its two boundary layers filled. | — |
| `key_recovery_modules/report.py` | Console rendering: header, trail block, streaming ordering rows, summary. Pure printing. | — |
| `key_recovery_modules/dynamic_greedy.py` | Greedy peel: repeatedly pick the next S-box to commit by solving each candidate, accumulating key bits, filter bits and work. | `sbox_solver`, `ddt_filter`, `propagation` |
| `key_recovery_modules/sbox_solver.py` | `solve_sbox_guess_basis(...)`: build the known/target/not-guessed variable sets for one S-box and call `search_guess_basis`; parse the minimum guess count from its output. | `attacks.guess_and_determine` |
| `key_recovery_modules/auto_wrapper.py` | `auto_key_recovery(...)`: sweep `(r_b, R_d, r_f)` splits for a cipher given as a factory pair; picks a best attack by objective. | `attacks.key_recovery`, `trail` |

Internals of `propagation.py`, `ddt_filter.py`, `trail.py` and `report.py` are
carried over unchanged apart from import paths and docstring formatting; they do
not touch the guess-and-determine API.

### Public API

```python
# attacks/key_recovery.py
GOALS = ("KEYRECOVERY_DIFF",)

def search_key_recovery(cipher, goal="KEYRECOVERY_DIFF", R_d=None, r_b=0, r_f=0,
                        trail=None, distinguisher=None, objective_target="OPTIMAL",
                        show_mode=0, config_model=None, config_solver=None):
    """Estimate the cost of a differential key-recovery attack on `cipher`."""
```

```python
# attacks/attacks.py
def key_recovery_attack(cipher, goal="KEYRECOVERY_DIFF", R_d=None, r_b=0, r_f=0,
                        trail=None, distinguisher=None, objective_target="OPTIMAL",
                        show_mode=0, config_model=None, config_solver=None):
    time_start = time.time()
    result = kr.search_key_recovery(...)
    print(f"--- Total Time ---: {time.time() - time_start:.2f} seconds")
    return result
```

`R_d`, `r_b`, `r_f`, `trail` and `distinguisher` are named arguments rather than
`config_model` keys because they state the problem, not how it is modelled —
the same distinction that puts `known_vars` / `target_vars` /
`not_guessed_vars` in the signature of `guess_and_determine_attack`.
`distinguisher` is the permutation searched when `trail is None`; exactly one of
`trail` and `distinguisher` must be given.

The return value keeps `key-reco`'s result dict unchanged: `trail`,
`sbox_records`, `ordering`, `stages`, `key_id_sets`, `per_subset`,
`C_KR_filter_model`, `d_in_bits`, `d_out_bits`, `N0_log2`, `D_log2`, `M_log2`,
`C_KR_log2`, `T_log2`, `total_K_bits`, `key_size_bits`, `codebook_overflow`,
`valid_attack`. The 2026-08-18 audit added three keys, all reported rather than
folded into any existing figure: `total_filter_bits`, `completion_log2` (the cost
of filling in the key bits the attack did not determine) and `N_is_upper_bound`
(true when `d_in > p + 1`, i.e. when `N` counts pairs the data cannot form).

### Renames

| `key-reco` | `key_reco_2` | Reason |
| --- | --- | --- |
| `attacks/key_recovery/estimator.py` | `attacks/key_recovery.py` | Engine module sits directly under `attacks/`, like `differential_cryptanalysis.py`. |
| `estimator.estimate_key_recovery` | `key_recovery.search_key_recovery` | Matches `search_diff_trail`, `search_linear_trail`, `search_guess_basis`, `search_integral_distinguisher`. |
| `sbox_solver.search_key_recovery` | `sbox_solver.solve_sbox_guess_basis` | The old name collides with the new engine name, and the function solves one S-box, not the whole recovery. |
| `attacks/key_recovery/` (package) | `attacks/key_recovery_modules/` | Frees `key_recovery.py` for the engine; mirrors `tools/relation_generator_modules/`. |

## Configuration mapping

| `key-reco` | `key_reco_2` |
| --- | --- |
| `RelGenConfig(sbox_form="implication")` | `config_model={"sbox_form": "implication"}` |
| `independent_round_keys=True` | `config_model["independent_round_keys"]=True`; the engine appends `"KEY_SCHEDULE"` to `config_model["skip_functions"]` |
| `SolverConfig(solver="sat")` | `config_model={"model_type": "sat"}` |
| `SolverConfig(satsolver="cadical153")` | `config_solver={"solver": "cadical153"}` |
| `SolverConfig(findmin=True, maxguess=80)` | `objective_target="OPTIMAL AT MOST 80"` |
| `SolverConfig(maxsteps=40)` | `config_model={"maxsteps": 40}` |
| `SolverConfig(drawgraph=False)` | `show_mode=0` |
| `diff_goal=...` | `config_model["distinguisher_goal"]` |
| `diff_config_model=...` | `config_model["distinguisher_config_model"]` |
| `cipher_name="PRESENT-80 (…)"` | `config_model["cipher_name"]` |

`search_key_recovery` splits its own `config_model` into the keys it consumes
(`independent_round_keys`, `cipher_name`, `distinguisher_goal`,
`distinguisher_config_model`) and the keys forwarded verbatim to
`search_guess_basis` per S-box. Unknown keys are not checked twice: whatever is
not consumed here reaches `search_guess_basis`, whose `_reject_unknown_keys` call
raises on it, so a misspelled key fails loudly against a single list of valid
names. Two keys are the exception -- `skip_rounds` and `bridge_skipped_rounds`
state the sub-problem (the distinguisher's rounds are absent and unbridged) rather
than how it is modelled, and the engine sets them itself; passing either raises
instead of being silently overwritten.

### Objective-target extension

`attacks/guess_and_determine.py::_parse_objective_target` gains one branch:

```python
if objective_target.startswith("OPTIMAL AT MOST"):
    bound = objective_target[len("OPTIMAL AT MOST"):].strip()
    if not bound.isdigit():
        raise ValueError(...)
    return True, int(bound)      # findmin=True, maxguess=bound
```

Rationale: `tools/autoguess/core/search.py::_findmin_descent` starts its descent
from `parameters["maxguess"]`. The existing mapping produces
`OPTIMAL -> (findmin=True, maxguess=None)` and
`AT MOST X -> (findmin=False, maxguess=X)`; neither expresses "minimise,
starting the descent at X", which is what `key-reco` used
(`findmin=True, maxguess=80`). With `maxguess=None`, AutoGuess defaults it to
`len(target_variables)` — a handful of variables for a single-S-box subproblem,
potentially below the true basis size.

The branch is placed before the plain `AT MOST` check for readability; the two
prefixes are disjoint, so ordering does not affect behaviour. The three existing
forms (`EXISTENCE`, `OPTIMAL`, `AT MOST X`) keep their current behaviour
exactly. The docstring, the
`objective_target` documentation on `search_guess_basis`, and `CHANGELOG.md` are
updated to list the fourth form.

## Error handling

- `goal` not in `GOALS`, `show_mode` outside `0..3`, non-dict `config_model` /
  `config_solver`: `ValueError`, matching the other engines' validation block.
- Unknown keys in either config dict: `ValueError` listing the offenders and the
  accepted set.
- `R_d` left as `None`, or `r_b == r_f == 0` (nothing to recover): `ValueError`.
- Neither `trail` nor `distinguisher` supplied, or both: `ValueError`.
- No differential trail found by the search: `RuntimeError`.
- Trail has zero active boundary cells: `RuntimeError`.
- No active S-boxes in the extension rounds: `RuntimeError` naming `r_b`, `r_f`
  and the boundary positions.

No silent fallbacks and no exception swallowing anywhere on the estimate path;
every failure that would change a reported complexity raises.

## Accepted behaviour deltas

`primitives/` is upstream verbatim, so the following differences from `key-reco`
are accepted and documented rather than fixed:

1. **PRESENT `r_f` under-count.** Upstream `present.py` appends the final
   whitening `AddRoundKey` as an extra round only when `nbr_rounds` is `None` or
   `31`. `present_80_attack.py` builds `r = r_b + R_d + r_f = 17`, so no
   whitening round exists, the last `SboxLayer` output is exposed key-free at
   the ciphertext, and the `r_f = 1` recovery costs less than it should.
   `key_reco_2`'s PRESENT-80 numbers will therefore differ from `key-reco`'s.
   Both are reported and the gap is explained; no code change.
2. **Silent guess-basis shrink — CLOSED 2026-08-18.** `key-reco`'s
   `tools/autoguess_wrapper.py` raised when AutoGuess reported N guessed variables
   but fewer resolved to cipher variables. Upstream keeps whatever resolved, and
   since the guess count feeds `2^guesses` in the cost, an unresolvable ID
   understated the complexity. Rather than change the shared wrapper, the
   key-recovery layer now makes the check itself: `dynamic_greedy._run_candidate`
   already parsed AutoGuess' `minimum number of guesses = K`, and compares it
   against `len(guessed_variables)`, raising on a mismatch. This was the only
   place the tool could report an attack cheaper than it is.
3. **`rectangle_attack.py`** — the concern that upstream's different RECTANGLE
   implementation would need the manual trail's `last_layer` and delta
   bit-ordering re-derived proved unfounded; see the RECTANGLE outcome below.
   The two implementations encode the same cipher. Only delta 1 applies.
4. **`gift_64_attack.py`, `skinny_64_attack.py`** are ported
   and import-checked, not run.
5. **`toy_attack.py` dropped** — dead import (`primitives.toy_cipher`).

## Verification

1. **Capture the baseline first.** Run `key-reco`'s
   `test/key_recovery/present_80_attack.py` and save its full output before
   writing any `key_reco_2` code.
2. **Primary check.** `python test/key_recovery/present_80_attack.py` in
   `key_reco_2` runs end to end and prints the Trail, Ordering and Summary
   blocks.
3. **Diff against the baseline.** Every difference is attributed to a specific
   cause from [Accepted behaviour deltas](#accepted-behaviour-deltas) or
   investigated as a port defect.
4. **Import smoke test.** `attacks.attacks`, `attacks.key_recovery` and every
   `attacks.key_recovery_modules.*` submodule import cleanly.
5. **Regression guard on the upstream edit.**
   `test/autoguess/test_gd_present_zc.py` and `python OCP.py` behave as they do
   in `OCP-with-autoguess`, proving `_parse_objective_target` stayed
   backward-compatible.

Success criterion: steps 2–5 pass and every difference in step 3 is explained.

## Outcome (measured 2026-08-05)

`test/key_recovery/present_80_attack.py` runs end to end in 175 s.

| | `key-reco` baseline | `key_reco_2` |
| --- | --- | --- |
| rounds modelled | 18 (whitening ARK appended) | 17 |
| active S-boxes | 17 | 17 (same set) |
| d_in / d_out | 48 / 6 | 48 / 6 |
| N | 2^52.00 | 2^52.00 |
| per-S-box filters | 3.00 / 4.00 | 3.00 / 4.00 (identical) |
| Total filter F | 54.00 ✓ | 54.00 ✓ |
| key bits committed | 53 | 48 |
| C_KR | 2^9.46 | 2^3.89 |
| T = C_KR · N | 2^61.46 | 2^55.89 |

Every difference traces to accepted delta 1. Upstream `present.py` does not append
the whitening `AddRoundKey` at `r = 17`, so round 17's `SboxLayer` output *is* the
ciphertext. The two ciphertext-side S-boxes `sb_f_r17_[0,1,2,3]` and
`sb_f_r17_[32,33,34,35]` therefore cost `dK = 0` instead of 4: no whitening subkey
has to be guessed to reach them. Because the greedy orders by `dK - filter`, those
two now sort first, which reshuffles the whole ordering and hence the per-row `dK`
of the backward S-boxes (they are only comparable in total, not row by row). The
net effect is 5 fewer committed key bits and a 5.57-bit cheaper attack.

The structural quantities — which S-boxes are active, their filters, `d_in`,
`d_out`, `N`, and the `F = d_in + d_out` consistency check — are unchanged, which
is what confirms the port itself is faithful.

The regression guard passed: `test/autoguess/test_gd_present_zc.py` produces output
identical to `OCP-with-autoguess` apart from timestamps and file paths.
`python OCP.py` likewise reproduces upstream's output exactly; the only addition is
the new key-recovery demo.

### RECTANGLE-80 (measured 2026-08-05)

`test/key_recovery/rectangle_attack.py` runs end to end in 397 s (2 + 14 + 2 = 18
rounds).

The two RECTANGLE implementations were first checked for equivalence rather than
assumed different. The ShiftRow permutation, the SubColumn S-box column indices,
the 5-bit LFSR round constants and the official test vectors all match exactly,
and upstream's per-bit `XOR`/`Equal` key-schedule wiring rebuilds to precisely
`key-reco`'s 80x80 GF(2) Feistel matrix. `last_layer=2` remains correct: both
model the round as ARK(0) → SubColumn(1) → ShiftRow(2). The key-schedule encoding
difference (`MatrixLayer` vs explicit constraints) is moot here because the script
sets `independent_round_keys=True`, which skips `KEY_SCHEDULE` entirely.

| | `key-reco` baseline | `key_reco_2` |
| --- | --- | --- |
| rounds modelled | 19 (whitening ARK appended) | 18 |
| active S-boxes | 17 | 17 (same set, same greedy order) |
| per-row filters | — | identical, all 17 rows |
| d_in / d_out | 24 / 28 | 24 / 28 |
| N | 2^50.83 | 2^50.83 |
| Total filter F | 49.00 ✗ (expected 52) | 49.00 ✗ (expected 52) |
| key bits committed | 72 | 44 |
| C_KR | 2^26.03 | 2^0.48 |
| T = C_KR · N | 2^76.86 | 2^51.31 |

Again a single cause, accepted delta 1. Without the whitening `AddRoundKey` the
round-18 ShiftRow output *is* the ciphertext, so all seven `sb_f_r18_*` S-boxes
cost `dK = 0` instead of 4 — 28 free key bits, and a 25.55-bit understatement of
the attack cost. This is far more distorting than the PRESENT case (5.57 bits),
because `r_f = 2` here exposes seven last-round S-boxes rather than two. The
baseline's `T = 2^76.86` sits just under the 2^80 validity gate; `key_reco_2`'s
`T = 2^51.31` is not a meaningful figure for this cipher.

### Whitening resolved (2026-08-05)

Accepted delta 1 was subsequently fixed rather than lived with, on the user's
instruction. `PRESENT_BLOCKCIPHER` and `RECTANGLE_BLOCKCIPHER` gained an opt-in
`final_whitening` flag (see CHANGELOG); both key-recovery scripts set it. With it
enabled, both attacks reproduce `key-reco` exactly — every ordering row and every
summary figure:

| | PRESENT-80 | RECTANGLE-80 |
| --- | --- | --- |
| modelled rounds | 18 (was 17) | 19 (was 18) |
| key bits | 53 ✓ | 72 ✓ |
| C_KR | 2^9.46 ✓ | 2^26.03 ✓ |
| T | 2^61.46 ✓ | 2^76.86 ✓ |

Default behaviour is unchanged: `r=17` still models 17 rounds, `r=None` and
`r=31`/`r=25` still model 32/26. The `Total filter F ... ✗` on RECTANGLE is
unaffected by the flag, confirming it is a separate, filter-side issue.

Published-table cross-check — three of the four rows reproduce exactly:

| Cipher | Attack | d_in | d_out | N | C_KR | valid |
| --- | --- | --- | --- | --- | --- | --- |
| RECTANGLE-80 | 2+14+2 | 24 | 28 | 2^50.83 | 2^26.03 | yes (< 2^80) |
| GIFT-64/128 | 3+13+2 | 64 | 32 | 2^94.06 | 2^0.19 | yes (< 2^128) |
| GIFT-64/128 | 4+13+4 | 64 | 64 | 2^126.06 | 2^3.00 | no (>= 2^128) |
| SKINNY-64-64 | 1+5+1 | — | — | — | — | not reproducible, see below |

Both GIFT rows satisfy filter conservation (`96.00 = 96`, `128.00 = 128`), as does
PRESENT (`54.00 = 54`). Only RECTANGLE and SKINNY fail it. GIFT `4+13+4` has 80
active S-boxes and took 6747 s: the greedy re-solves every remaining S-box at each
step, so cost grows quadratically (~3240 AutoGuess solves here).

### SKINNY-64-64 is not reproducible across the port, by construction

`skinny_64_attack.py` is the only key-recovery script that *searches* for its
distinguisher (`USE_MANUAL_TRAIL = False`) rather than injecting a published one.
Probing the 5-round search directly, twice per repository:

```
key_reco_2 : weight=24  in_active=[4, 11, 13, 14]   out_active=[1, 8, 9, 13]
key-reco   : weight=24  in_active=[3, 12]           out_active=[0,1,2,3,4,9,10,12,13,14]
```

Each repository is deterministic — identical on both runs. `primitives/skinny.py`
is byte-identical between them, so both of those are valid weight-24 trails of the
same cipher: **the minimum-weight trail is not unique.** The script never
specified *which* optimum it wanted, so it gets whichever the solver reaches first.

**The deciding variable is the `python-sat` version, not the OCP code.** An earlier
revision of this document blamed upstream's changed CNF encoding in
`operators/Sbox.py` / `operators/matrix.py`; that was wrong. Isolating it:

| environment | Python | python-sat | d_in / d_out | N |
| --- | --- | --- | --- | --- |
| key_reco_2 `env312` | 3.12.13 | 1.9.dev2 | 40 / 40 | 2^40.00 |
| key-reco `env312` | 3.12.13 | 1.9.dev5 | 16 / 60 | 2^36.00 |
| clean venv | 3.12.13 | 1.9.dev13 | 16 / 60 | 2^36.00 |
| clean venv | 3.14.3 | 1.9.dev13 | 16 / 60 | 2^36.00 |

Rows 1 and 3 differ only in the solver library: same code, same interpreter
version, different trail. So `key_reco_2` *does* reproduce the published
`16/60, N = 2^36.00, C_KR = 2^0.10` — its bundled `env312` merely carries an
unusually old `python-sat`.

**Re-measured 2026-08-18: this no longer reproduces.** On the current code,
`skinny_64_attack.py` returns a byte-identical trail under 1.9.dev2 and 1.9.dev15 --
same input difference `0000200000020220`, same `Total Weight: 24`, same
`rounds_diff_weight: [8, 4, 4, 4, 4]` -- and the same `d_in/d_out = 20/8`,
`T = 2^5.26`. Whatever produced the divergence above has gone; the table is kept as
the record of what was seen on 2026-08-05, not as current behaviour. The underlying
point stands and is the reason to pin anything published: the minimum-weight trail is
not unique, so nothing guarantees two solver versions return the same one.

Attacks that inject a published distinguisher are unaffected: PRESENT-80 and
RECTANGLE-80 produce bit-identical reports under 1.9.dev2 and 1.9.dev13, on both
3.12 and 3.14. Only the trail *search* is version-sensitive, because only there
is the answer non-unique.

Recommendation: pin the distinguisher for anything published, either through
`build_manual_trail` (lossy for a word cipher — active positions are recorded as
single bits, discarding the nibble difference values) or by passing `input_diff` /
`output_diff` in the trail search's `config_model`, which reuses the existing
`_gen_fixed_input_output_constraints` machinery and keeps real nibble values.

### End-to-end audit and the right-pair correction (2026-08-14)

The end-to-end path — SAT differential search for the distinguisher, then key
recovery — was audited on the shipped configuration (Python 3.14, the five
`requirements.txt` packages). The pipeline works: search, trail, extension,
greedy, report, no plumbing errors. Two demo-sized end-to-end runs, both fully
searched with no injected trail:

| attack | p | d_in | d_out | N | T | wall |
| --- | --- | --- | --- | --- | --- | --- |
| PRESENT-80 2+8+1 | 32 | 48 | 8 | 2^24 | 2^33.81 | 4 min |
| PRESENT-80 1+10+1 | 41 | 24 | 16 | 2^17 | 2^25.30 | 5 min |

The audit found a defect. `N = 2^(p + d_in + d_out - n)` counts the *wrong* pairs
surviving the ciphertext sieve, since `2^(d_out - n)` is the probability a
*random* pair passes it. The right pair passes by construction and was never
counted. With a weak distinguisher the sieve removes every wrong pair, `N` drops
below 1, and the work collapses: a 1+3+1 run reported `N = 2^-20.00` and
`T = 2^-12.75`, then printed `Valid attack: Yes` because `2^-12.75 < 2^80`.

Fixed by `dynamic_greedy.with_right_pair(x) -> log2(2^x + 1)`, applied to the
initial `N0` and to the surviving count after every S-box (the right pair passes
each S-box filter too). Above ~2^53 it returns `x` unchanged.

Re-verified after the change — all five identical to their pre-fix values, every
ordering row included:

| attack | C_KR | T | min pairs-left |
| --- | --- | --- | --- |
| PRESENT-80 2+14+1 | 2^9.46 | 2^61.46 | 2^51.00 |
| RECTANGLE-80 2+14+2 | 2^26.03 | 2^76.86 | 2^51.83 |
| GIFT-64/128 3+13+2 | 2^0.19 | 2^94.26 | 2^28.06 |
| GIFT-64/128 4+13+4 | 2^3.00 | 2^129.06 | 2^92.06 |
| SKINNY-64-64 1+5+1 | 2^0.42 | 2^40.42 | 2^13.00 |

The 1+3+1 case now reports `N = 2^0.00` and `T = 2^9.71` against `2^9` data.

The last column is why: the smallest surviving count anywhere in these runs is
`2^13`, far above the threshold where adding one pair is visible. The correction
is provably inert in the valid regime, and the re-runs confirm it empirically.

Regime note: the estimate is informative only while key-recovery work dominates,
i.e. while `p + d_in + d_out > n`. Below that the data cost dominates and the
time-only convention (Boura et al.) understates the real cost. Widening the
extension raises `d_in` and reaches the regime far more cheaply than searching a
longer distinguisher — 2+8+1 is in regime while 1+8+1 is not.

### Pre-existing issue surfaced (not introduced by the port) — DIAGNOSED

Both runs report `Total filter F = 49.00 (= d_out + d_in = 52) ✗`. An earlier
revision of this document guessed the leak was in "partially active S-boxes whose
checked side does not span a full nibble". **That was wrong**, and the rows
carrying `filter = 2.00` obey exactly the same formula as every other row.

The filters are correct. `conditional_target_side_filter_for_record` returns
exactly `log2|allowed differences on the observed side| - log2|allowed on the
checked side|`, measured with deviation `0.000e+00` across all 80 records of the
four runs. It is forced: for a bijective S-box every DDT row *and* column sums to
`2^n`, so `pass_both = 2^n·|checked set|` and `eligible = 2^n·|observed set|`.
Summing over a side telescopes to `log2` of the difference-set cardinality at the
outermost extension S-box layer — and everything beyond that layer (ARK,
bit-permutation, MixColumns) is a key-independent bijection, so it cannot change
that cardinality.

The defect is the right-hand side. `propagated_d_in_bits` / `propagated_d_out_bits`
return `len(active_var_set) * word_bitsize`: an *activity footprint*, i.e. how many
state bits are touched. Footprint >= log2|set|, with three separate sources of
slack:

| case | side | Σfilter | shipped d | word-rounding | forced bits | box-vs-set | gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PRESENT | fwd/bwd | 6 / 48 | 6 / 48 | 0 | 0 | 0 | 0 |
| GIFT | fwd/bwd | 32 / 64 | 32 / 64 | 0 | 0 | 0 | 0 |
| RECTANGLE | fwd | 27 | 28 | 0 | 1 | 0 | 1 |
| RECTANGLE | bwd | 22 | 24 | 0 | 2 | 0 | 2 |
| SKINNY | fwd | 8 | 40 | 10 | 0 | 22 | 32 |
| SKINNY | bwd | 20 | 40 | 10 | 10 | 0 | 20 |

RECTANGLE's 3 bits are boundary bits *forced to 1*, which the footprint counts as
free (exact enumeration of 947,970 and 141,120 differences confirms it). SKINNY's
52 are forced bits, per-word rounding (a touched nibble charged 4 bits when 3 are
active), and a structural term: `MixColumns` smears a dimension-8 affine set over
30 active bits, and a per-word box model cannot represent that.

**`sum(filter) == d_in + d_out` is not a theorem.** It holds iff no boundary bit is
forced, and `word_bitsize == 1` or words fill, and the extension's linear layers
are bit permutations. PRESENT and GIFT satisfy all three by coincidence of cipher
structure. The check is a seam check between two implementations of the same
truncated model, and it correctly flagged the seam.

**This is not cosmetic.** `key_recovery.py` feeds the same footprint into
`N0 = p + d_in + d_out - n`, so `N0` is over-stated wherever the seam is open — by
3 bits for RECTANGLE, 52 for SKINNY.

### Resolution (2026-08-15): d_in / d_out are set sizes

Boura et al. define these as sizes — `|D_in| = 2^d_in` — and that definition is
cipher-independent: the formula `N = 2^(p + d_in + d_out - n)` needs only the two
cardinalities. What is cipher-specific is the *shortcut* of counting active bits,
which equals the size only when every combination of the active bits occurs.

Confirmed against the paper (`kyrydi-main/generic_key_recovery.pdf`), which prints
`din = 24`, `dout = 28`, `N = 2^50.83` for the 18-round RECTANGLE attack — exactly
what the pre-fix code produced. The paper's restriction to bit-permutation linear
layers is about its *construction* (structures built by fixing inactive bits), not
about the quantity, which is always well defined.

`propagation.boundary_pattern_bits(sbox_records, side)` now returns `log2 |D|`,
read at the outermost extension S-box layer: everything between it and the PT/CT
is a key-independent bijection and so cannot change the set's size. `M` keeps the
active-bit footprint, since a structure really is built over active bits.

Measured on all five configurations — the check passes on every one, because both
sides now measure the same quantity:

| attack | d_in / d_out | N | T |
| --- | --- | --- | --- |
| PRESENT-80 2+14+1 | 48 / 6 unchanged | 2^52.00 unchanged | 2^61.46 unchanged |
| GIFT-64/128 3+13+2 | 64 / 32 unchanged | 2^94.06 unchanged | 2^94.26 unchanged |
| GIFT-64/128 4+13+4 | 64 / 64 unchanged | 2^126.06 unchanged | 2^129.06 unchanged |
| RECTANGLE-80 2+14+2 | 24/28 -> 22/27 | 2^50.83 -> 2^47.83 | 2^76.86 -> 2^73.86 |
| SKINNY-64-64 1+5+1 | 40/40 -> 20/8 | 2^40.00 -> 2^0.00 | 2^40.42 -> 2^4.29 |

The SKINNY `T` in that table is superseded. Three changes landed the day after it
was taken -- counting guessed key BITS rather than variables, keeping the forced
bits when XOR-ing word differences, and propagating through GF(2^m) MixColumns --
and they move a word cipher. The 2026-08-17 sweep entry in `CHANGELOG.md` records
`1+5+1` at `T = 2^5.26`, `d_in/d_out = 20/8`, and the 2026-08-18 re-run reproduces
exactly that. `d_in`, `d_out` and `N` are unchanged from the row above; only `T`
moved. The four other rows are still current, re-measured on 2026-08-18.
RECTANGLE moves by exactly its 3 forced boundary bits. GIFT 4+13+4 does not move
because `r_b = r_f = 4` spreads the difference over the whole 64-bit state, so
`d = 64` is already the full space and there is nothing to remove — it remains
invalid at `2^129.06`.

RECTANGLE now differs from the paper's printed `24/28`. Not a disagreement: the
paper propagates ignoring the DDT, this code propagates with it and so reaches a
smaller set. The estimate here is tighter.

Two threads from the audit remain open and are *not* addressed by this change:
`_xor_val_masks` widens the pattern where an exact and a truncated word meet at
MixColumns, which affects two-round word extensions; and the boundary set is still
a per-word box, so it bounds rather than equals the true set (exact enumeration
gives GIFT's forward boundary as `2^17.09` against the `32` used). Both make the
estimate conservative, never optimistic.

### The greedy is a total order; the paper searches partitions (2026-08-18)

The largest known gap between this tool and Boura et al. is algorithmic, and it is
not a defect: it is a capability of their algorithm that `dynamic_greedy.py` does
not implement. Written down here because the numbers differ visibly on RECTANGLE
and the repository previously said nothing about why.

**What the paper does.** §2.2 lists three things that determine the key-recovery
complexity:

> First, the order in which each S-box is solved impacts the complexity. [...]
> Second, it is possible to solve several S-boxes at the same time, which can also
> help reduce the overall time complexity. Last but not least, S-boxes and sets of
> S-boxes can be solved in parallel. [...] It comes that finding an efficient key
> recovery procedure consists in choosing an efficient partition of the S-boxes
> with an associated order on each element of the partition.

So their search space is *partitions of the active S-boxes, each part internally
ordered*. Solving a part jointly can beat solving its members one after another,
because the parts' key bits and filters interact; and independent parts can be
solved in parallel, so their costs add rather than multiply.

**What this tool does.** `estimate_dynamic_autoguess_greedy` commits exactly one
S-box per step, choosing the one with the best `ΔK - filter` among those remaining,
and never revisits the choice. That is the first of the paper's three levers and
only the first: the partition is always the trivial one, every part a singleton,
and there is no parallel composition. The greedy is also greedy — it takes the
locally best S-box rather than searching orders.

**How far that is from optimal, measured.** The paper gives a lower bound for the
key-recovery step (§2.2): `N + N * 2^(|K| - d_in - d_out)`, the number of expected
solutions. Applying it to this tool's own measured parameters -- so the comparison
does not depend on the paper's different `d_in`/`d_out` -- gives the headroom a
partition search could in principle recover:

| attack | N | \|K\| | d_in+d_out | lower bound | measured T | gap |
| --- | --- | --- | --- | --- | --- | --- |
| GIFT-64/128 3+13+2 | 2^94.06 | 30 | 96 | 2^94.06 | 2^94.26 | 0.20 |
| GIFT-64/128 4+13+4 | 2^126.06 | 94 | 128 | 2^126.06 | 2^129.06 | 3.00 |
| RECTANGLE-80 2+14+2 | 2^47.83 | 72 | 49 | 2^70.83 | 2^73.86 | 3.03 |
| SKINNY-64-64 1+5+1 | 2^0.00 | 4 | 28 | 2^0.00 | 2^5.26 | 5.26 |
| LED-64 1+2+0 | 2^24.00 | 48 | 78 | 2^24.00 | 2^31.70 | 7.70 |
| PRESENT-80 2+14+1 | 2^52.00 | 53 | 54 | 2^52.58 | 2^61.46 | 8.88 |
| PRESENT-80 1+4+0 | 2^0.00 | 24 | 24 | 2^1.00 | 2^10.91 | 9.91 |
| AES-128 1+2+0 | 2^0.00 | 64 | 88 | 2^0.00 | 2^13.17 | 13.17 |

GIFT `3+13+2` is essentially optimal (`C_KR = 2^0.19`, the ordering cannot matter
when almost nothing is guessed before the sieve has done its work). The gap grows
with the number of S-boxes whose relative order is contested. The bound is a bound,
not a target: the paper says an efficient algorithm gets "as close as possible" to
it, not that it is reached.

**Against the paper's published attacks.** Two are directly comparable:

| attack | paper | this tool | |
| --- | --- | --- | --- |
| PRESENT-80 2+14+1 | d_in/d_out 48/6, N=2^52, C_KR=2^8, T=2^60 | 48/6, N=2^52, C_KR=2^9.46, T=2^61.46 | T +1.46 |
| RECTANGLE-80 2+14+2 | 24/28, N=2^50.83, C_KR=2^19, T=2^69.83 | 22/27, N=2^47.83, C_KR=2^26.03, T=2^73.86 | T +4.03 |

PRESENT is a clean comparison -- identical `d_in`, `d_out` and `N` -- and the whole
1.46-bit difference is the key-recovery procedure. RECTANGLE is not: this tool's
`d_in`/`d_out` are *tighter* (22/27 against 24/28, because it propagates with the
DDT and the paper without), so its `N` is 3 bits smaller. That makes the apparent
`C_KR` gap of 7.03 bits misleading -- 3.00 of it is only the smaller denominator in
`C_KR = T / N`. The real difference is the 4.03 bits on `T`. Note also that the
paper's RECTANGLE-80 `C_KR = 2^19` sits exactly on their lower bound
`N * 2^(71-52)`, i.e. their procedure is optimal there, so the 4.03 bits is the
full cost of the missing partition search on this attack.

**Direction.** Always conservative: a worse ordering does more work, so `T` comes
out too high. No attack is reported cheaper than it is.

**If it is implemented.** The natural shape is to keep the per-S-box AutoGuess
solve as-is and replace the selection step: at each stage consider subsets of the
remaining S-boxes up to some size `k`, solve each subset jointly (one
`search_guess_basis` call with the union of the target variables), and score
`ΔK - filter` over the subset. `k = 1` is exactly today's behaviour. Cost grows as
`C(m, k)` solves per stage against `m` today, so the practical limit is small `k`;
GIFT `4+13+4` already takes 4556 s at `k = 1` with 80 S-boxes.
