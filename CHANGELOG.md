# Changelog

## 2026-08-18 — clean-install check: pytest was missing, and a documented divergence no longer reproduces

Built an empty venv from `requirements.txt` as a new user would, on Python 3.12.13,
and ran the tool from it. Two findings.

**`pytest` was not in `requirements.txt`.** The documented `pytest test/key_recovery`
command failed with `No module named pytest` on a fresh install -- the file listed
only the five packages needed to run an attack. Added, and the surrounding prose
("with exactly these five") corrected.

**The recorded `python-sat` version sensitivity does not reproduce.** The design
notes record `skinny_64_attack.py` giving `d_in/d_out = 40/40` under 1.9.dev2 and
`16/60` from 1.9.dev5 on, measured 2026-08-05. On the current code, dev2 and dev15
return a byte-identical trail -- input difference `0000200000020220`, `Total Weight:
24`, `rounds_diff_weight: [8, 4, 4, 4, 4]` -- and identical figures, `20/8` and
`T = 2^5.26`. The note in the design document is marked accordingly.

The claim that replaces it is weaker but true: the minimum-weight trail is not
unique, so nothing *guarantees* two solver versions agree, and anything published
should pin its distinguisher. What cannot be said is that they are known to disagree.

Also verified on the clean environment: `run_attack.py` gives `T = 2^10.91` and
`present_80_attack.py` gives `T = 2^61.46`, both identical to the bundled `env312`.

The README's Install section now carries the three things that actually bite someone
running this for the first time -- build your own virtualenv, run one script at a
time, and compare against a pinned-trail script -- rather than leaving them in
`requirements.txt` comments where a new user will not look.

## 2026-08-18 — say "guess basis", not "key bits guessed"

The Summary printed

```
  Key bits guessed     : 53 / 80
```

which reads as "53 of the 80 key bits were recovered". It is not that. AutoGuess may
take its basis from anywhere in the key schedule -- a key-register bit at round 4 as
readily as a master-key bit -- and two such variables need not be independent, so
the figure counts VARIABLES and bounds the key entropy fixed rather than equalling
it. AES 1+3+1 makes the point by reporting 160 for a 128-bit key. It now prints

```
  Guess basis          : 53 of 80 bits   (basis size; an upper bound on the key entropy fixed)
```

Nothing computed changes; `total_K_bits` keeps its name and meaning in the result
dict, and the over-count warning is reworded to match.

Worth recording alongside it, because it is the reason the looseness does not
propagate: the completion term does not use `|K|` at all. The surviving triplets are
`N * 2^(|K| - F)` and each is completed at `2^(key_size - |K|)`, so the product is
`N * 2^(key_size - F)` and `|K|` cancels. If the true entropy is `e < |K|`, the
triplet count is over-stated and the per-triplet completion under-stated by exactly
the same factor, and the product is unchanged. So an inflated basis inflates the
per-step work and hence `T` -- the safe direction -- and leaves the completion floor
untouched.

Restricting the basis to master-key bits would not help: a master-key-only basis is
still a basis, so the minimum over those is at least the minimum over all key-schedule
variables. For PRESENT it would be much worse, since the schedule is non-linear and
deriving a round-4 subkey nibble from the master key means inverting three rounds of
it. Boura et al. take the same side -- their `Kin`/`Kout` are round-key bits, not
master-key bits -- but restrict themselves to linear key schedules, where the union
is a linear span with a well-defined dimension. Using the real schedule is what turns
that dimension into a set size.

## 2026-08-18 — the cost model is now tested, without a solver

Every figure the tool reports comes out of `estimate_dynamic_autoguess_greedy`, and
until now nothing verified it. The 28 existing tests cover leaf helpers -- the DDT
filters, `with_right_pair`, the mask algebra, `build_manual_trail` -- and all 28
pass with the `- filter_bits` deleted from the survivor update, or the greedy
inverted to commit the worst S-box at every step. The only thing standing between a
change to the recurrence and a wrong published number was somebody re-running an
attack script and comparing the output to a figure in this file by eye.

`test/key_recovery/test_greedy_recurrence.py` closes that. The greedy calls
`_run_candidate` unqualified, so a test substitutes it and feeds canned per-S-box
answers: no cipher is built, no model is written, no SAT solve runs. 20 tests, 0.07
seconds, and nothing in `attacks/` changed to make them possible.

What they pin down:

- the recurrence itself -- `work_i = pairs_left_{i-1} + dK_i`, then
  `pairs_left_i = with_right_pair(work_i - filter_i)`, checked step by step across a
  chain rather than only at the ends;
- `T` as the SUM of the step works, not the largest of them;
- the right-pair floor: a filter larger than the work leaves `2^0`, never less;
- the selection rule -- lowest `dK - filter` wins, ties break on position -- and
  that every S-box is committed exactly once;
- key accounting: a variable guessed twice is charged once, a variable the key
  schedule determines is free from then on, and a key WORD costs its full width
  (a nibble is 4 bits, not 1);
- that the keys committed at one step are handed to the next step's solves;
- the failure paths: an unsolved S-box stops the run rather than being skipped, a
  missing package is reported as a missing package and not as a solver limit, and an
  impossible S-box transition stops the run instead of silently wiping the pair set;
- the stage dicts the report layer prints, and that each stage carries the filter of
  the S-box it actually committed.

**Checked by breaking the code.** A passing test proves nothing on its own, so the
suite was run against nine deliberate mutations of the cost model. All nine were
caught:

| mutation | tests failed |
| --- | --- |
| `work = pairs_left - dK` instead of `+` | 5 |
| `- filter_bits` dropped from the survivor update | 3 |
| right-pair floor removed | 2 |
| greedy commits the WORST S-box | 3 |
| tie-break inverted | 2 |
| already-known keys charged again | 2 |
| key width ignored, variables counted instead | 2 |
| `T` = peak step work instead of the sum | 1 |
| key-schedule-determined variables not recorded | 2 |

The file was restored afterwards and `run_attack.py` re-run to confirm it:
`d_in = 18`, `d_out = 6`, `T = 2^10.91`, unchanged.

Still not covered, and deliberately left for the pre-PR pass: `search_key_recovery`'s
own validation and plumbing, `sbox_solver`, `auto_key_recovery`, and any end-to-end
run with a real solve. The last of those is worth pinning a distinguisher for rather
than searching one -- a searched trail is not stable across `python-sat` versions
(see the SKINNY note below), so an end-to-end test that asserts exact figures has to
inject its distinguisher or it will fail on a different machine for the wrong reason.

## 2026-08-18 — six sweep scripts; a failed distinguisher no longer kills the sweep

`auto_key_recovery` is the function that answers the question the tool exists for --
try many round splits, return the best one, and never return an attack costing more
than the targeted security level -- and until now nothing exercised it but
`run_attack.py`, and only when one of its three parameters happened to be a list.
Six scripts under `test/key_recovery/` now do, one per option:

| script | shows |
| --- | --- |
| `sweep_present_80.py` | every default: combinations as `r_b_values x r_d_values x r_f_values`, `objective="max_rounds"`, `targeted_security` = key size |
| `sweep_rectangle_80.py` | the combinations given explicitly as `splits=[(r_b, R_d, r_f), ...]` |
| `sweep_skinny_64.py` | sweeping the distinguisher LENGTH, and `objective="min_time"` |
| `sweep_twine_80.py` | `objective` as a callable -- lowest cost per round attacked |
| `sweep_gift_64.py` | `targeted_security` below the key size, and a distinguisher that cannot be built |
| `sweep_led_64.py` | reading `results` / `valid_results`, and re-ranking without re-solving |

Measured:

| sweep | splits | best | T |
| --- | --- | --- | --- |
| `sweep_present_80` | 4/4 | 17 rounds (2+14+1) | 2^61.46 |
| `sweep_rectangle_80` | 4/4 | 8 rounds (2+5+1) | 2^25.28 |
| `sweep_gift_64` | 4/8 | 17 rounds (2+13+2) | 2^46.26 |
| `sweep_skinny_64` | 4/4 | 6 rounds (1+5+0), by min_time | 2^3.70 |
| `sweep_twine_80` | 2/4 | 7 rounds (1+5+1) | 2^5.58 |
| `sweep_led_64` | 4/4, 2 over budget | 4 rounds (1+2+1) | 2^29.10 |

Two of these are checks rather than demonstrations. `sweep_present_80` pins Wang's
14-round differential and searches R_d = 4 alongside it in the same run, and selects
`2+14+1` at `T = 2^61.46` -- the figure `present_80_attack.py` produces standalone,
so the sweep path and the single-attack path agree. `sweep_skinny_64`'s four rows
reproduce the 2026-08-17 sweep entry below, figure for figure.

`sweep_skinny_64` is also where the objective visibly changes the answer:
`min_time` returns the 6-round attack at `2^3.70`, where the default `max_rounds`
would take the 8-round one at `2^38.09`. And `sweep_led_64` is where the security
level bites -- `1+3+0` at `2^86.75` and `1+3+1` at `2^76.09` are both above `2^64`,
so they stay in `results` flagged `over` and are excluded from `best` and
`valid_results`.

**A distinguisher that cannot be built aborted the whole sweep.** `_trail_for_rd`
sat outside the per-split `try`, two lines above a comment promising that "a single
split failing must not abort the sweep". Any R_d whose trail search raised took
every split with it, including the ones already computed. It is now inside the
guard, recorded on the row like any other failure, and the failure is cached so the
remaining splits at that R_d do not re-run a search already known to fail.

GIFT is the case that finds it, because OCP cannot serialise a GIFT trail at all:

```
  [skip] r_b=1 R_d=4 r_f=1   distinguisher: TypeError: Object of type GIFT_Sbox is not JSON serializable
  [skip] r_b=1 R_d=4 r_f=2   no distinguisher found
  [OK ] r_b=1 R_d=13 r_f=1  T=2^12.41  d_in=4 d_out=8
  ...
    4/8 splits produced an attack.
```

Before the change that first row ended the run.


## 2026-08-18 — detect S-boxes by class, not by name

**S-box detection was by class-NAME suffix.** `find_sbox_layer` and the four
propagation dispatchers tested `cls.endswith("Sbox")`, which misses any cipher whose
S-box classes are numbered. LBlock's eight are `LBlock_Sbox0` .. `LBlock_Sbox7`, so
none of them was ever seen as an S-box. The failure is quiet in the worst way: the
layer walk finds no active S-box and the run dies with "No active S-boxes in the
extension", while inside the propagation the operator falls through to the
conservative branch and marks its whole output active instead of reading the DDT.
`propagation._is_sbox(op)` now tests `isinstance(op, operators.Sbox.Sbox)`.

Checked for regressions by comparing both predicates over every operator of
PRESENT, RECTANGLE, GIFT, SKINNY, LED, AES and TWINE at four rounds: identical sets
in all seven. LBlock is the only cipher whose detection changes.

**LBlock is still not usable, for a different reason.** With the detector fixed it
runs, and its 4-round search returns

```
IN_: 000080c078000005  ->  round 4, layer 0: 0000000000800000
Total Weight: 0        rounds_diff_weight: [0, 0, 0, 0]
```

a non-zero trail at probability 1, which cannot exist -- the differential weight is
not being attributed to `LBlock_Sbox*`, so `p = 0` and every number derived from it
is meaningless. `primitives/lblock.py`, `attacks/differential_cryptanalysis.py` and
`operators/Sbox.py` are byte-identical to upstream, so this is an OCP issue and
independent of the detector change. TWINE, the same structure class (Feistel, 4-bit
S-boxes), attributes weight correctly (`Total Weight: 6`,
`rounds_diff_weight: [2, 0, 2, 2]`), which isolates it to LBlock.

**GIFT cannot search a distinguisher at all.** `attack_trace.save_json` raises
`TypeError: Object of type GIFT_Sbox is not JSON serializable` while persisting the
trail, in upstream OCP too. This is the failure `gift_64_attack.py`'s docstring
already records as its reason for injecting a published trail; it is now also what
`sweep_gift_64.py` uses to exercise the sweep's failure path.

**The over-count warning gave the wrong advice.** Added in the audit entry below, it
ended "Try independent_round_keys=False" -- which the AES 1+3+1 run that triggers it
already uses, and `True` skips the key schedule entirely so it can only make the
count worse. It now says what is actually true: the guessed variables cannot be
independent, the true count is at most the key size, and AutoGuess reports only the
relations it finds within `config_model['maxsteps']`, whose current value it prints.

## 2026-08-18 — pre-release audit: close the paths that could under-state a cost

A read-through of the whole key-recovery layer ahead of upstreaming it. Nothing
here changes `T`, `C_KR` or `valid_attack` for any attack that ran before; all
seven reproductions were re-measured and every recorded figure comes back
unchanged (table below).

**The report now says what `T` leaves out.** `T = C_KR * N` is the cost of the
key-recovery step, which is exactly what Boura et al. report and gate on — their
Table 5 caption says an attack is valid iff that quantity is below `2^80`. It is
not the whole attack: the key bits the peel does not determine are filled in by
search over the surviving triplets. That costs

```
N * 2^(|K| - F) triplets  *  2^(key_size - |K|) each  =  N * 2^(key_size - F)
```

in which `|K|` cancels — only the total filtering `F` decides it. Both `N` and `F`
are fixed before the greedy starts (each S-box's filter is precomputed and does
not depend on the order), so no ordering can trade against this term: the greedy
can only move `T`. It is a floor on the attack, and on a short distinguisher --
few active S-boxes, hence small `F` -- it is the term that dominates:

```
  Total filter F       : 18.00 bits
  Key completion       : 2^62.00   (= N * 2^(80 - F); DOMINATES T, not included in T)
```

Checked against the paper's own tables: every valid PRESENT-80 row in their
Table 5 gives `N * 2^(80 - F) = 2^78`, from `T = 2^28` up to `T = 2^77`.
`total_filter_bits` and `completion_log2` join the result dict.

**A guess AutoGuess reports but OCP cannot resolve is now an error.** The wrapper's
`_resolve_vars` drops any variable ID absent from `cipher.vars_dictionary` (an
AutoGuess dummy standing for a product of variables, say), while the cost model
charges `2^len(guessed_variables)`. The greedy already parsed AutoGuess' own
`minimum number of guesses = K`; it now compares the two and stops. This was the
only place the tool could silently report an attack *cheaper* than it is.

**A manual trail no longer discards a word cipher's difference values.**
`build_manual_trail` wrote `"1"` per active word, so `delta_in=0x...a00000` on a
nibble cipher reached the extension walk as the difference `0x1` — wrong filters
and a wrong `d_in`/`d_out`, in no particular direction. It now writes the word's
value as a `word_bitsize`-wide binary string, the same convention a searched trail
uses, and a list of active positions (which carries no value) is rejected for
`word_bitsize > 1` instead of being read as 1. Bit ciphers are unaffected: for
`word_bitsize == 1` the string is the old `"1"`/`"0"`.

**Memory is bounded by the data.** `M` was the active-bit footprint `2^d_in`, but
a structure cannot be larger than the data that fills it: with `d_in > p + 1` the
attack builds one partial structure of `2^(p+1)` plaintexts. The `1+4+0` run
reported `M = 2^24` against `D = 2^13`; it now reports `2^13`. Every published
reproduction has `d_in <= p + 1` and is unchanged.

**An impossible S-box transition stops the run.** A record whose DDT allows no
transition between its two patterns gets `filter = inf`, which sorted first and
silently wiped the pair set — a cost reported for an attack that cannot exist. It
now raises, naming the S-boxes: the trail and the propagated extension contradict
each other.

**Smaller things.**

- The step works are summed in log space (`_log2_sum_exp2`). `2.0 ** work`
  raises `OverflowError` past `2^1024`, reachable on a 128-bit key over a wide
  extension. Bit-identical below that.
- `config_model['skip_rounds']` and `['bridge_skipped_rounds']` were silently
  overwritten per S-box; passing them now raises, since they state the sub-problem
  rather than how it is modelled.
- `objective_target` was validated by bare prefix, so `'OPTIMALLY'` passed here and
  only failed later inside `guess_and_determine`. The four accepted forms are now
  matched exactly, integer bound included.
- A trail word whose difference the solver left undetermined (`'-'`) raised a bare
  `ValueError` from `int()`; it now says which word, and why.
- `auto_key_recovery`'s `independent_round_keys` defaulted to `False` while
  `search_key_recovery`'s defaults to `True` — the same knob with opposite
  defaults. Both are `True` now. Every shipped script passes it explicitly and is
  unaffected.
- Committing more key bits than the key holds prints a warning naming the likely
  cause (key-schedule relations AutoGuess did not find are counted as independent).
- `codebook_overflow` was computed, returned and never shown; the Summary now
  warns when `D` exceeds the codebook.
- `find_sbox_layer`, `extract_active_positions`, `identify_perm_function` and
  `FINDMIN_RE` lost their leading underscore: they are imported across module
  boundaries, so they were never private.
- `print_summary` dropped the commented-out filter-conservation check and the four
  parameters that only existed to keep it restorable.

**Re-measured, all seven runs, 2026-08-18.** Every recorded figure reproduces:

| attack | d_in / d_out | N | T | vs record |
| --- | --- | --- | --- | --- |
| PRESENT-80 2+14+1 | 48 / 6 | 2^52.00 | 2^61.46 | exact, all 17 rows |
| RECTANGLE-80 2+14+2 | 22 / 27 | 2^47.83 | 2^73.86 | exact, all 17 rows |
| GIFT-64/128 3+13+2 | 64 / 32 | 2^94.06 | 2^94.26 | exact |
| GIFT-64/128 4+13+4 | 64 / 64 | 2^126.06 | 2^129.06 | exact, invalid as before |
| SKINNY-64-64 1+5+1 | 20 / 8 | 2^0.00 | 2^5.26 | exact vs the 2026-08-17 sweep |
| PRESENT-80 1+4+0 | 18 / 6 | 2^0.00 | 2^10.91 | exact, all 6 rows |
| LED-64 1+2+0 | 46 / 32 | 2^24.00 | 2^31.70 | first recorded |
| AES-128 1+2+0 | 64 / 24 | 2^0.00 | 2^13.17 | first recorded |

`M` moved only where the structure could not be filled, i.e. where it now reports
the data bound instead of the active-bit footprint: GIFT (both splits) `2^64 ->
2^63.06`, PRESENT 1+4+0 `2^24 -> 2^13`, LED `-> 2^11`. PRESENT 2+14+1 (`2^48`) and
RECTANGLE 2+14+2 (`2^24`) are below the bound and unchanged. Nothing else moved.

The design notes' SKINNY `T = 2^4.29` is superseded, not contradicted: it was taken
on 2026-08-15, before the three word-cipher changes of 2026-08-16. See the note
added there.

**Still open: `N` assumes structures of full dimension.** `N = 2^(p + d_in + d_out
- n)` counts `2^(p+d_in)` pairs formed from the data, which needs `2^(p-d_in+1)`
structures -- below one when `d_in > p + 1`, where the attack builds a single
partial structure of `2^(p+1)` plaintexts instead and forms only `2^(2p+1)` pairs.
The general form is `min(d_in, p+1)` in place of `d_in`, the same bound `M` now
takes. LED 1+2+0 shows what the gap looks like: `D = 2^11` yields at most `2^21`
pairs, and `N = 2^24` is reported. The error is always toward a HIGHER cost, never
lower, so no attack is claimed cheaper than it is -- but it would move GIFT 3+13+2
from `T = 2^94.26` to `2^93.32` and LED from `2^31.70` to about `2^7.7`. The formula
is left exactly as the paper states it, and the condition is reported instead:
`report.n_is_upper_bound(p, d_in)` drives an `[INFO]` line in the Trail block giving
the pairs the data forms against the pairs `N` is counted from, and
`N_is_upper_bound` joins the result dict so a sweep keeps it after stdout is
redirected. It is silent on PRESENT 2+14+1, RECTANGLE 2+14+2 and SKINNY 1+5+1, and
fires on both GIFT splits, PRESENT 1+4+0, AES and LED. No reported figure moves.

**Written up: the greedy is a total order, the paper searches partitions.** The
design notes gain a section on the one known algorithmic gap against Boura et al.
-- their §2.2 chooses a partition of the active S-boxes with an order on each part,
solving several S-boxes jointly and independent parts in parallel, where
`dynamic_greedy` commits one S-box per step and never revisits it. Measured against
their own lower bound `N + N * 2^(|K| - d_in - d_out)` on this tool's parameters,
the headroom runs from 0.20 bits (GIFT 3+13+2, already optimal) to 13.17 (AES).
Against their published attacks: PRESENT-80 2+14+1 is +1.46 bits on `T` with
identical `d_in`/`d_out`/`N`, RECTANGLE-80 2+14+2 is +4.03. Conservative in every
case, and nothing in the code changes.

**Tests.** `test/key_recovery/test_key_recovery_units.py` — 20 solver-free tests
over `with_right_pair`, `_log2_sum_exp2`, the DDT filters, `boundary_pattern_bits`,
the word-mask algebra and `build_manual_trail`, running in 0.07 s. The `*_attack.py`
reproductions stay scripts, deliberately not named `test_*`: they take minutes each
and pytest should not collect them.

**Documentation.** README's `published` example showed the pre-sweep flat form
(`{"weight": ...}`), which `run_attack.py` keys by `R_d` — following it made the
tool silently search instead of pinning. README also still described
`sum(filter) == d_in + d_out` as a self-check the code must satisfy, which the
design notes had already established is not a theorem and which `print_summary`
had stopped printing. `requirements.txt` referred to `auto_attack.py`, renamed to
`run_attack.py`. `gift_64_results.md`'s "not re-run here" note is corrected: it
was, at different splits.

## 2026-08-17 — sweep the distinguisher length, not just where it sits

`auto_key_recovery` has always taken `r_d_values`, but `run_attack.py` passed
`r_d_values=(R_d,)` and only entered sweep mode when `r_b` or `r_f` was a list. So
the one question the sweep exists to answer — *how long a distinguisher can this
cipher support?* — was the one it could not be asked.

Any of `R_d`, `r_b`, `r_f` may now be a list. `published` is keyed by `R_d`
(`{14: {...}}`) so a sweep can pin a published trail at one length and search the
others; `full_rounds` is exposed to cap the sweep at the real cipher.

Given SKINNY-64-64, a 64-bit target, `R_d = [5, 6, 7]` and `r_f = [0, 1]`:

```
  [OK ] r_b=1 R_d=5 r_f=0 (total 6)   T=2^3.7    d_in=20 d_out=16
  [OK ] r_b=1 R_d=5 r_f=1 (total 7)   T=2^5.26   d_in=20 d_out=8
  [OK ] r_b=1 R_d=6 r_f=0 (total 7)   T=2^48.09  d_in=40 d_out=40
  [OK ] r_b=1 R_d=6 r_f=1 (total 8)   T=2^38.09  d_in=40 d_out=30
  [OK ] r_b=1 R_d=7 r_f=0 (total 8)   T=2^60.42  d_in=20 d_out=52
  [OK ] r_b=1 R_d=7 r_f=1 (total 9)   T=2^48.09  d_in=20 d_out=40

    rounds attacked : 9 (r_b=1, R_d=7, r_f=1)
    time complexity : 2^48.09  (< 2^64)
```

Three trail searches, six estimates, and the 9-round attack chosen. `1+6+1` and
`1+7+1` reproduce the standalone runs exactly, so the sweep and single-attack
paths agree.

The sweep is necessarily sequential: OCP writes its model to a fixed path under
`files/` keyed only by cipher and goal, so two splits at the same round count
overwrite each other's CNF.

## 2026-08-17 — derive what the cipher already knows; reject a stale round count

Three inputs the caller had to get right by hand, and one that was silently
wrong when they did not.

`objective_target` had to be written as `"OPTIMAL AT MOST <key size>"` in every
script. A bare `"OPTIMAL"` leaves AutoGuess' `maxguess` unset, and it then starts
the descent at the number of target variables — about 4 for a single S-box, below
any real guess basis — so no basis is found. The engine now reads the key size off
the cipher's key schedule and fills the bound in, printing an `[INFO]` line in the
same shape as the primitives' own messages. An explicit bound still wins.

`cipher_name` defaulted to the cipher's bare name. It now defaults to the name
plus the round split — `PRESENT64_80 (2+14+1)` — so the report identifies the run,
not just the cipher. `auto_key_recovery` takes its label from the first cipher its
factory builds instead of a required string.

Both are gone from all six scripts and from `run_attack.py`.

`attacks.key_recovery_attack`'s docstring said only "see `search_key_recovery`
for the accepted parameters", which is useless in an editor tooltip. It now lists
every argument, all four `objective_target` forms, every `config_model` key with
its default, and the returned dict keys, so hovering the call shows the whole
option surface.

**The round count is now checked.** The ciphertext handed to AutoGuess as known is
the state at the cipher's *last* round, so a cipher built over more rounds than
`r_b + R_d + r_f` posed a strictly harder problem and returned its cost, with no
error. Measured on PRESENT-80 `1+4+1`:

| `r` | modeled | T | key bits guessed |
| --- | --- | --- | --- |
| 6 (correct) | 7 | `2^9.29` | 41 |
| 7 | 8 | `2^35.58` | 71 |
| 9 | 10 | `2^63.08` | 80 |

Every one of them reported `Valid attack: Yes`. Only `r_f > 0` is affected — with
no forward extension the ciphertext is never used and the estimate does not move.
`search_key_recovery` now raises unless the cipher spans exactly the attacked
rounds, allowing one extra round only when it carries the final key addition alone
(`final_whitening=True`), detected by that round having no S-box layer.

All six attack scripts return their previous numbers.

## 2026-08-16 — remove dead code, correct the documentation

Pre-publication clean-up. No behaviour change: all six attack scripts return the
same numbers as before.

`propagation.py`'s module docstring claimed the propagation is *exact* for SKINNY
and *"conservative (mark everything active)"* for AES. Both were backwards.
SKINNY's MixColumns is a binary matrix and goes through `_xor_val_masks`, which
returns a superset; LED's GF(2^4) and AES's GF(2^8) MixColumns go through
`_gf_matrix_propagate`, which is exact. The docstring now states accuracy per
operator class rather than per cipher, describes both the bit path and the
word-value path, and names the per-word boxing as the reason a one-round
extension is exact while a two-round one over-states `d_in`/`d_out`.

Removed, none of it reachable:

| what | why |
| --- | --- |
| `key_recovery_modules/coupling_diagnostic.py` | nothing imported it |
| `report.print_report` | never called; the estimator streams its rows instead |
| `sbox_solver`'s `distinguisher_end is None` branch | the only caller always passes it, so the `trail` argument it needed went too — through `dynamic_greedy` as well |
| `stages[i]["marginal_filter_bits"]` | a verbatim copy of `filter_bits`, read by nothing |

`stages[i]["filter_model"]` is now spelled `conditional_target_side`, matching the
result dict's `C_KR_filter_model`. The three searched-distinguisher scripts
(SKINNY, LED, AES) no longer import `build_manual_trail` or bind an unused `perm`,
left over from the published-trail template they were copied from.

The README documented a `cipher_name` / `search_trail` parameter block that does
not exist, and a `REGISTRY` in `auto_wrapper.py` that was removed — as did
`docs/design/key-recovery-design.md`. Both now describe the factory-pair interface
the code actually has, and the README states that only one attack script may run
at a time per checkout, because OCP keys its model files under `files/` by cipher
and goal alone.

Smaller corrections:

* `search_key_recovery` now validates `objective_target` alongside its other
  arguments, like every sibling engine does. It was the only configurable
  argument left unchecked, so a typo surfaced only after the trail search and the
  propagation had already run.
* `build_manual_trail`'s docstring gave `last_layer = 5` for SKINNY; SKINNY's
  state has 5 layers, so the last index is 4. It now states the rule every caller
  actually uses — `perm.nbr_layers - 1` — instead of a list of magic numbers.
* `auto_wrapper`'s docstring pointed at "the reproduction scripts in this
  directory"; they live in `test/key_recovery/`.
* The `step_callback` lambda in the greedy call was a pass-through wrapper around
  `print_ordering_row`; the function is passed directly.

## 2026-08-16 — propagate differences through GF(2^m) MixColumns

The value path handled a `Matrix` operator only when its entries were 0/1. For a
GF(2^m) matrix it gave up:

```python
# non-binary (GF(2^m)) MixColumns or missing: conservative -> all active
return {oi: (0, full) for oi in out_ids}
```

Every output word came back fully free, nothing was ever pinned, and every
downstream filter was `0.00`. That is sound but useless — it silently excluded
every cipher with an MDS layer over an extension field, i.e. LED and AES.

`_gf_matrix_propagate` now multiplies the actual value sets through the field
using OCP's own `gf2_multiply`, and XOR-combines them. A word holds at most 2^n
values (16 for a nibble, 256 for a byte), so enumeration is exact and cheap; the
result is boxed back into `(fmask, amask)` for the record. The backward direction
needs `op.inverse_over_gf2m()` — the existing `_matrix_inverse` is GF(2)-only and
returns None for these matrices, which is why the first attempt still fell through
to the fallback.

Checked against hand arithmetic in GF(2^4) with `x^4+x+1`: `4*1 = 4`, and
`4*1 XOR 1*2 = 6`.

SKINNY is unaffected — its MixColumns is binary, so it keeps the exact XOR path
(`C_KR = 2^5.26`, filter check OK). PRESENT, GIFT and RECTANGLE have no matrix in
their extension rounds at all.

Two ciphers become usable:

| attack | before | after |
| --- | --- | --- |
| LED-64 1+2+0 | every filter 0.00, `F = 0.00` vs 48, FAILS | `F = 46.00 = 46` OK, `C_KR = 2^7.70` |
| AES-128 1+2+0 | (never tried) | `F = 64.00 = 64` OK, `C_KR = 2^13.17` |

AES also exercises the non-linear key schedule, which the reference tool cannot
handle — it replaces PRESENT's key-schedule S-box with a random matrix to fit.
Here `AES_Sbox` supplies AutoGuess constraints like any other operator.

Two-round *word* extensions still lose precision to cross-word correlation (LED
2+2+0: `F = 46` against `d_in = 64`), the same residual documented for SKINNY
2+5+1. Per-word masks cannot express that the inputs of a column are related.

## 2026-08-16 — count guessed key BITS, not key variables

The greedy charged `2^new_key_bits` per step with

```python
new_key_bits = len(guessed - committed_keys)
```

which counts guessed key *variables*. A key variable is a whole word: one bit for
PRESENT, GIFT and RECTANGLE, but four for SKINNY and LED. Guessing a nibble costs
`2^4`, and the greedy charged `2^1`.

Confirmed from a real SKINNY run rather than from the class definition — AutoGuess
returned `vk_1_0_5` with `bitsize=4`, reported as "Key bits committed: 1".

`_key_widths()` now carries each guessed variable's width, and both the per-step
`delta_K_bits` and the total sum widths instead of counting IDs.

Only word-oriented ciphers are affected; the key variables of every cipher in the
published table except SKINNY are 1 bit wide, so `count == bits` held by
coincidence there.

| | before | after |
| --- | --- | --- |
| SKINNY-64-64 1+5+1, key bits | 1 | 4 |
| SKINNY-64-64 1+5+1, C_KR | 2^4.29 | 2^5.26 |
| PRESENT-80 1+14+0 | 2^19.59 | 2^19.59 (unchanged) |

Surfaced by trying LED-64, the first cipher outside the validated set: it reported
12 "key bits" for 12 guessed nibbles, i.e. 48 real bits.

## 2026-08-15 — report a missing dependency as a missing dependency

An absent optional package surfaced from inside AutoGuess as an ordinary solve
failure, so the greedy raised its "raise maxsteps / the OPTIMAL AT MOST bound"
hint. On a fresh machine that sends the user tuning solver limits when the real
cause is `pip`. `dynamic_greedy` now recognises the import/availability failure and
says so instead:

```
RuntimeError: AutoGuess cannot run: the package 'pypblib' is not installed.
This is an environment problem, not a solver limit -- raising maxsteps will not help.
Install the dependencies with:  pip install -r requirements.txt
```

Verified against a venv built without `python-sat[pblib]`. The package name is
extracted from either wording AutoGuess uses (`No module named 'x'`,
`Package 'x' is unavailable`), with a generic fallback for a bare `ImportError`.
Genuine solver failures -- exhausted `maxsteps`, UNSAT, timeout -- still get the
original limits message; checked against all three so the detection cannot swallow
a real solver problem.

## 2026-08-15 — keep the forced bits when XOR-ing word differences

`_xor_val_masks` combined per-word `(fmask, amask)` differences by returning
`(0, OR of the active masks)` as soon as any operand was truncated — discarding
every bit it knew to be forced. XOR-ing an exact `0011` with a word free on bits
2,3 gave 16 possible values where the truth is 4 (`0011, 0111, 1011, 1111`: bits 0
and 1 are always set).

Per bit position an operand either pins it or leaves it free, so the XOR is free
iff *some* operand leaves it free, and otherwise pinned to the XOR of the forced
parts. The forced information survives a truncated operand; only the positions
that operand actually frees are lost.

Validated by brute force over 4004 random mask combinations against full
enumeration: 0 unsound (the true set is always contained), and exact in every case
where the operands are independent.

This is still an over-approximation. The masks are per word, so two operands whose
free bits share a source are treated as independent when their XOR is in fact
determined; representing that needs affine-subspace tracking, not masks. The result
remains a superset of the truth, so estimates stay conservative.

Scope: `_xor_val_masks` is reached only from the `word_bitsize > 1` value path, and
only from the second extension round — the first round's operands all come exact
from the trail. Bit ciphers (PRESENT, GIFT, RECTANGLE) never enter it, and SKINNY
1+5+1 is unchanged (`d_in=20, d_out=8, C_KR=2^4.29`). Measured on SKINNY 2+5+1, the
first configuration that reaches the branch:

| | Σfilter | T | check |
| --- | --- | --- | --- |
| before | 43.00 | 2^28.44 | fails (vs 68) |
| after | 58.00 | 2^28.42 | fails (vs 68) |

15 of the 25 missing bits recovered. The remaining 10 are the cross-word
correlation above, and the check now flags that genuine residual rather than
information the code had already thrown away.

## 2026-08-15 — d_in / d_out are set sizes, not active-bit counts

`propagated_d_in_bits` / `propagated_d_out_bits` returned
`len(active_words) * word_bitsize`. Boura et al. define these as sizes --
`|D_in| = 2^d_in` -- and counting active bits equals that size only when every
combination of the active bits actually occurs. Two things break it:

- a bit **forced to 1**: the bit count calls it free, but it is not a choice;
- a **mixing linear layer**: the bits become dependent. SKINNY's MixColumns
  spreads a 16-dimensional space over 40 active bit positions, and a bijective
  linear map cannot change a set's size.

Bit-permutation ciphers have neither, which is why PRESENT and GIFT were correct
and why the paper restricts its construction to that class.

`propagation.boundary_pattern_bits(sbox_records, side)` now computes `log2 |D|`
at the outermost extension S-box layer -- everything between it and the PT/CT is
a key-independent bijection, so it cannot change the size. `key_recovery.py`
extracts the S-box records before the trail numbers and uses this for `d_in` /
`d_out`; `M` keeps the active-bit footprint, since a structure really is built
over active bits.

Measured, all five published configurations:

| attack | d_in / d_out | N | T | filter check |
| --- | --- | --- | --- | --- |
| PRESENT-80 2+14+1 | 48 / 6 (same) | 2^52.00 (same) | 2^61.46 (same) | now OK |
| GIFT-64/128 3+13+2 | 64 / 32 (same) | 2^94.06 (same) | 2^94.26 (same) | now OK |
| GIFT-64/128 4+13+4 | 64 / 64 (same) | 2^126.06 (same) | 2^129.06 (same) | now OK |
| RECTANGLE-80 2+14+2 | 24/28 -> **22/27** | 2^50.83 -> **2^47.83** | 2^76.86 -> **2^73.86** | now OK |
| SKINNY-64-64 1+5+1 | 40/40 -> **20/8** | 2^40.00 -> **2^0.00** | 2^40.42 -> **2^4.29** | now OK |

PRESENT and both GIFT rows are bit-identical, every ordering row included.
RECTANGLE moves by exactly the 3 forced boundary bits (1 at the ciphertext, 2 at
the plaintext). GIFT 4+13+4 does not move because `r_b=r_f=4` spreads the
difference over the whole 64-bit state: `d = 64` is already the full space, so
there is nothing for the correction to remove.

Note RECTANGLE now differs from the value printed in Boura et al. (`d_in = 24`,
`d_out = 28`, `N = 2^50.83`). That model propagates ignoring the DDT; this code
propagates with it and so legitimately reaches a smaller set. The estimate here is
tighter, not in disagreement.

`report.py::print_summary`'s `sum(filter) == d_in + d_out` check now passes on all
five, because both sides finally measure the same quantity. It was never a
correctness check on the cost -- it is a seam check between the two halves of the
model, and it correctly flagged that they disagreed.

## 2026-08-14 — count the right pair in the key-recovery work

The pair counts in the estimator are expected counts of *wrong* pairs: `N = 2^(p +
d_in + d_out - n)` follows from forming `2^(p + d_in)` pairs out of `2^(p+1)` data
in structures of `2^d_in`, then applying the ciphertext sieve, which a *random*
pair passes with probability `2^(d_out - n)`.

The right pair is not subject to that probability. It satisfies the trail, so it
passes the boundary sieve and every S-box filter by construction, and the data is
sized so that one exists. It was never counted.

Above a handful of surviving wrong pairs this makes no difference, but when the
sieve is strong enough to remove them all the uncorrected count drops below 1 and
the work collapses toward zero. An end-to-end run on a 3-round PRESENT
distinguisher reported `N = 2^-20.00`, per-step `Work = 2^-16.00`, and
`T = 2^-12.75` — a key-recovery attack costing less than one operation — which
then passed the `T < 2^key_size` gate and printed `Valid attack: Yes`.

`dynamic_greedy.with_right_pair(x)` returns `log2(2^x + 1)` and is applied to the
initial `N0` and to the surviving count after each S-box. Same 3-round run now
reports `N = 2^0.00` (the one right pair) and `T = 2^9.71` against `2^9` data,
which is a sensible cost for a toy attack.

The correction is a no-op wherever the sieve leaves many wrong pairs. Re-verified
unchanged, every ordering row included: PRESENT-80 2+14+1 (`2^9.46`,
`T = 2^61.46`), RECTANGLE-80 2+14+2 (`2^26.03`, `T = 2^76.86`), GIFT-64/128
3+13+2 (`2^0.19`, `T = 2^94.26`), GIFT-64/128 4+13+4 (`2^3.00`, `T = 2^129.06`)
and SKINNY-64-64 1+5+1 (`2^0.42`, `T = 2^40.42`). The smallest surviving count
anywhere in those runs is `2^13`, far above the point where one extra pair shows.

Note the model is informative only while the key-recovery work dominates. With a
short distinguisher the data cost dominates instead, and a time-only figure — the
Boura et al. convention used here — says little about the real cost. Attacks are
in regime when `p + d_in + d_out > n`; widening the extension raises `d_in` and is
a far cheaper way to get there than searching a longer distinguisher.

## 2026-08-05 — `final_whitening` for PRESENT and RECTANGLE

`PRESENT_BLOCKCIPHER` and `RECTANGLE_BLOCKCIPHER` accept `final_whitening=False`.
When True, the final `AddRoundKey` is appended as an extra round for a *reduced*
round count too, not only at the full 31 / 25 rounds.

Both ciphers order their round as `ARK . Sbox . P`, so a reduced-round model ends
on the S-box/permutation layer and exposes that output key-free at the ciphertext.
Any ciphertext-side (`r_f`) key recovery is then under-counted: the last round's
S-boxes cost zero key guesses. Measured on the key-recovery scripts, the estimate
came out 5.57 bits cheap for PRESENT (`r_f=1`, two S-boxes) and 25.55 bits cheap
for RECTANGLE (`r_f=2`, seven S-boxes).

Default is off, so every existing call is bit-identical: `r=17` still models 17
rounds, `r=None` and `r=31`/`r=25` still model 32/26. The hardcoded final-round
index (`32` / `26`) in the round loop became a `final_round` variable. Both
key-recovery scripts pass `final_whitening=True`.

GIFT and SKINNY need no such flag: GIFT ends its round with `ARK`, and SKINNY's
`ARK` is followed only by the key-independent `ShiftRows`/`MixColumns`.

## 2026-08-05 — differential key-recovery attacks

Ported the key-recovery layer from the `key-reco` repository, which was built on
an older OCP snapshot, onto the current code base and conventions.

**New attack.** `attacks/key_recovery.py` estimates what a differential
key-recovery attack costs: it takes a distinguisher, extends it by `r_b` rounds
at the top and `r_f` at the bottom, finds the active S-boxes in those extension
rounds, and peels them one at a time with AutoGuess, accumulating the key bits
guessed and the DDT filter each S-box applies.

```python
key_recovery_attack(cipher, goal="KEYRECOVERY_DIFF", R_d=None, r_b=0, r_f=0,
                    trail=None, distinguisher=None, objective_target="OPTIMAL",
                    show_mode=0, config_model=None, config_solver=None)
```

`R_d` / `r_b` / `r_f` and the distinguisher (`trail` or `distinguisher`) state
the problem, so they are named arguments rather than `config_model` keys — the
same split `guess_and_determine_attack` makes for `known_vars` / `target_vars`.

`config_model` keys consumed by this attack: `independent_round_keys` (default
True — treat subkeys as independent and skip the KEY_SCHEDULE relations),
`cipher_name`, `distinguisher_goal`, `distinguisher_config_model`. Every other
key, and all of `config_solver`, is forwarded per S-box to `search_guess_basis`,
which validates it.

Support code lives in `attacks/key_recovery_modules/`, following
`tools/relation_generator.py` + `tools/relation_generator_modules/`:
`propagation` (truncated activity propagation, active-S-box extraction),
`ddt_filter` (per-S-box conditional filter), `dynamic_greedy` (the peel loop),
`sbox_solver` (one-S-box AutoGuess solve), `trail` (`build_manual_trail`, for
injecting a published distinguisher), `report` and `auto_wrapper` (a sweep over
round splits for a cipher given as a factory pair).

`auto_key_recovery` sweeps `(r_b, R_d, r_f)` splits and returns the best attack.
The set of splits, the meaning of "best" (`"max_rounds"` by default, or
`"min_time"`, or a caller-supplied key function) and the targeted security level
are all optional inputs. Cost is the time complexity T only: data complexity is
deliberately excluded, matching Boura et al. and the estimator's own
`valid_attack` gate, which is also the strict `T < 2^target` used here. Registry
rows carry the published distinguishers so a sweep is reproducible -- relying on
the trail search is not, since the minimum-weight trail is generally not unique.

Runnable examples in `test/key_recovery/`, plus a short demo in `OCP.py`.

**New objective target.** `_parse_objective_target` accepts
`"OPTIMAL AT MOST X"` → `(findmin=True, maxguess=X)`: minimise the guess basis,
but start the descent at X. `"OPTIMAL"` leaves `maxguess` unset, and AutoGuess
then defaults it to the number of target variables — fine when the targets are
the whole state, but in key recovery the targets are a single S-box, so the
descent would start below the true basis size. `EXISTENCE`, `OPTIMAL` and
`AT MOST X` are unchanged.

**Known deltas from `key-reco`.** `primitives/` is used as-is, with one exception
(the `final_whitening` flag added in the entry above, which restores `key-reco`'s
PRESENT/RECTANGLE round count under an opt-in). Still not carried over:

- `tools/autoguess_wrapper.py` keeps whatever guessed IDs resolve to cipher
  variables. `key-reco` raised when AutoGuess reported more than resolved, on
  the grounds that the count feeds `2^guesses` in the cost.

`present_80_attack.py` and `rectangle_attack.py` were run and compared against
`key-reco`; both reproduce its S-box set, ordering and per-S-box filters exactly,
and differ only through the whitening-round delta above (PRESENT: 5.57 bits
cheaper; RECTANGLE: 25.55 bits cheaper, since `r_f=2` exposes seven free
last-round S-boxes). Despite the two RECTANGLE implementations looking unrelated,
they encode the same cipher: ShiftRow, S-box column indices, round constants and
test vectors all match, and upstream's per-bit key-schedule wiring rebuilds to
`key-reco`'s 80x80 GF(2) Feistel matrix. `gift_64_attack.py`,
`skinny_64_attack.py` are ported and import-checked but not
run.

**Pre-existing issue, carried over unchanged.** RECTANGLE reports
`Total filter F = 49.00 (= d_out + d_in = 52) ✗` — in `key-reco` too, with
identical per-row filters. `report.py::print_summary` asserts
`sum(filter) == d_in + d_out`, which only holds when each active S-box re-checks a
disjoint set of difference bits; the rows with `filter = 2.00` rather than `3.00`
are partially active S-boxes where that assumption breaks. Not investigated here.

## 2026-08-02 — guess-and-determine follows the OCP attack convention

**Breaking.** `guess_and_determine_attack` / `search_guess_basis` now take the
same arguments as every other OCP attack entry point, instead of `*args,
**kwargs` over two dataclasses. Behaviour is unchanged: the kwargs reaching
`generate_relations` and `run_autoguess` are identical before and after for all
seven scripts in `test/autoguess/`.

**New signature:**

```python
guess_and_determine_attack(cipher, goal="GUESSBASIS", known_vars=None,
                           target_vars=None, not_guessed_vars=None,
                           protect_all_targets=False, objective_target="EXISTENCE",
                           show_mode=0, config_model=None, config_solver=None)
```

**Migration:**

- `relgen_cfg=RelGenConfig(**kw)` → `config_model={**kw}`
- `solver_cfg=SolverConfig(solver=F)` → `config_model={"model_type": F}`
- `solver_cfg=SolverConfig(satsolver=B)` → `config_solver={"solver": B}`
- `SolverConfig(maxguess=N)` → `objective_target="AT MOST N"`
- `SolverConfig(findmin=True)` → `objective_target="OPTIMAL"`
- `SolverConfig(reducebasis=True)` → `goal="REDUCEBASIS"`
- `SolverConfig(maxsteps=N)` → `config_model={"maxsteps": N}`
- `name_prefix=P` / `output_file=F` → `config_model={"name_prefix": P}` / `{"filename": F}`
- `drawgraph` / `tikz` / `log` → `show_mode` (0 results, 1 +graph, 2 +log, 3 +tikz).
  The old defaults (`drawgraph=True`, `log=0`) correspond to `show_mode=1`.

`RelGenConfig` and `SolverConfig` still exist but are internal plumbing;
callers no longer import them.

**Also:**

- Unknown `config_model` / `config_solver` keys now raise `ValueError` listing
  the accepted keys, instead of being silently ignored.
- The relation-file path is resolved once up front rather than derived in two
  places; it is named from the cipher and modelling options only, so runs
  differing only in objective reuse it.
- `test/autoguess/files/` is now gitignored.
- `autoguess_usage_guide.md` rewritten. Beyond the API change it also corrected
  pre-existing errors: `flat_sbox` / `canonical` / `cross_round_dir` were listed
  as `RelGenConfig` fields but do not exist (the real ones are `sbox_form` and
  `cleaning_direction`); the graph artifacts are `*_graph` and `*_graph.pdf`,
  not `*_graph.gv` / `*_graph.gv.pdf`; `MatrixLayer` covers `Matrix` only, with
  `GF2Linear_Trans` under `LFSRLayer`; and the quick-start example returned no
  solution because it relied on the default `maxguess`.

## 2026-05-13 — audit fixes in cleaner + emitter

Eleven issues from an external review were addressed. The one rejected
item (audit #5: dedup target ∩ not_guessed) is intentionally NOT a bug —
`protect_all_targets=True` requires the overlap to forbid targets from
being guessed; deduping it would silently disable that protection
(already documented in the 2026-05-09 entry).

**Cleaner (`tools/relation_generator_modules/cleaner.py`):**

- [#1] `strict_anchored` is now enforced in `collapse_cross_round` too,
  matching `collapse_same_round`. Cross-round equivalence classes
  containing 2+ anchored variables raise `RuntimeError` when the
  flag is on.
- [#4] `_is_rename` now requires both tokens to be identifier-shaped
  (matching `[A-Za-z_][A-Za-z0-9_]*`). Numeric literals or other
  2-token comma lines that slipped past the old length-only check
  are no longer misclassified as renames.
- [#7] `_remove_trivial` deduplicates tokens within a line and emits
  the deduped form. `a, a, b` (which can arise post-substitution)
  now becomes `a, b` instead of surviving verbatim.
- [#8] `_strip_nonrename_markers` now uses a whitespace-tolerant
  regex (`,\s*NONRENAME\s*$`) instead of an exact-string `.replace`.

**Emitter (`tools/relation_generator_modules/emitter.py`):**

- [#2] `gen_autoguess_constr` exceptions are no longer swallowed into
  a `# Error …` comment line. They now propagate as `RuntimeError`
  with op/round/layer context, so genuine op bugs become visible
  instead of disappearing.
- [#3] `Equal` ops are routed as always-rename
  (`treat_as_nonrename=False`) regardless of the
  `perm_rename`/`rot_rename`/`gf2linear_rename` toggles. Previously
  `Equal` was bucketed with permutations, so `perm_rename=False`
  also forced LINK_EQ and identity-layer ops to NONRENAME — wrong,
  because `Equal` is an equality by definition.
- [#6] Built-in `LINK_EQ` is now stripped **only** when one of its
  round endpoints is in `skip_round_set`. The previous logic
  stripped ALL `LINK_EQ` whenever any round was skipped, throwing
  away legitimate intra-active connections that the gap-linker had
  to rebuild for no reason.
- [#9] `emit_function` raises `ValueError` when `nbr_rounds` or
  `nbr_layers` is missing/invalid instead of silently emitting an
  empty relation list (defaults were `0` / `-1`).
- [#10] Non-int entries in `skip_rounds` now raise `TypeError`. The
  old `isinstance(int)` filter silently dropped string/bool entries,
  so a typo like `skip_rounds=["3"]` produced no skip and no warning.
- [#11] `zip(..., strict=True)` in the gap-linker's three loops, with
  the surrounding `try/except` narrowed to
  `(IndexError, KeyError, AttributeError)` so a width mismatch
  surfaces as `ValueError` instead of being silently truncated.
- [#12] `emit_cipher` restores the caller's `kwargs["skip_rounds"]`
  inside a `try/finally`, so the mapping isn't left mutated when
  `emit_function` raises mid-loop.

**Smoke-tested with `/tmp/relgen_sweep.py` after the changes: 400 OK,
1 pre-existing SHACAL2 primitive bug unrelated to these fixes.**
SKINNY-TK2 boundary diagnostic histograms unchanged: `default {0:4,3:15}`,
`input {0:19}`, `output {3:19}`, `opp_default {0:16,2:3}`.

## 2026-05-12 — single-knob `cleaning_direction` + legacy removal

**Breaking.** `RelGenConfig`, `generate_relations`, and `CleanerConfig`
now expose only `cleaning_direction` — the four-way enum that selects
which round boundary the canonical reps land on. The legacy trio
(`canonical`, `cross_round_dir`, `boundary_naming`) has been removed.

- `CleanerConfig`:
    - Removed fields: `layer_side`, `round_side`.
    - New field: `cleaning_direction: Literal["input", "output", "default",
      "opp_default"] = "default"`.
    - `__post_init__` validates the value; `_resolve()` maps it to the
      internal `(layer_side, round_side)` pair the rep-picker consumes.
- `clean_relations(lines, *, config=...)`:
    - Legacy kwargs (`canonical`, `cross_round_dir`, `boundary_naming`,
      `debug_cross_renames`, `strict_anchored`) **removed**. The
      `DeprecationWarning` shim from 2026-05-10 is gone.
    - Pass `config=CleanerConfig(...)` or omit for the default.
- `tools/relation_generator.generate_relations`:
    - Removed parameters: `canonical`, `cross_round_dir`, `boundary_naming`.
    - Kept: `cleaning_direction`, `debug_cross_renames`, `strict_anchored`.
- `RelGenConfig`:
    - Removed fields: `canonical`, `cross_round_dir`, `boundary_naming`.
    - Kept: `cleaning_direction`.
- `test/autoguess/boundary_diagnostic.py` updated to drive all four
  corners via `cleaning_direction`.

**Migration cheat sheet for user scripts:**

| Old | New |
|---|---|
| `boundary_naming="input"` | `cleaning_direction="input"` |
| `boundary_naming="output"` | `cleaning_direction="output"` |
| (default; no flag) | `cleaning_direction="default"` (or omit) |
| `canonical=True, cross_round_dir=True` | `cleaning_direction="input"` |
| `canonical=False, cross_round_dir=False` | `cleaning_direction="output"` |
| `canonical=False, cross_round_dir=True` | `cleaning_direction="opp_default"` |

`automated_key_recovery/` is **not** mirrored — it tracks its own
cleaner pipeline at user request.

## 2026-05-10 — cleaner.py refactor + caller migration

**The cleaner now has a structured `CleanerConfig` API and a 4-stage
pipeline (`parse_input` → `collapse_same_round` → `collapse_cross_round`
→ `rewrite_and_format`). Callers updated to the new surface; legacy
keyword arguments still work with a `DeprecationWarning`.**

- New public types in `tools/relation_generator_modules/cleaner.py`:
  `CleanerConfig`, `ParsedInput`, `SubstitutionMap`, `CollapseResult`.
- `CleanerConfig` fields:
    - `layer_side: "input" | "output"` — replaces the old `canonical`
      bool. `"input"` ≡ `canonical=True` (earliest layer wins);
      `"output"` ≡ `canonical=False` (latest layer wins).
    - `round_side: "earlier" | "later"` — replaces the old
      `cross_round_dir` bool. `"earlier"` ≡ `cross_round_dir=False`;
      `"later"` ≡ `cross_round_dir=True`.
    - `debug_cross_renames`, `strict_anchored`, `var_describer`.
- `clean_relations(lines, config=CleanerConfig(...))` is the preferred
  call. Legacy kwargs (`canonical`, `cross_round_dir`, `boundary_naming`,
  `debug_cross_renames`, `strict_anchored`) still work but emit a
  `DeprecationWarning`. Mixing `config=` with legacy kwargs raises
  `TypeError`.
- `decide_collapse` now preserves an equality chain only when **≥2
  distinct targets** share a class (previously: ≥2 anchored vars of any
  section). Other anchored mixes (e.g. known + not_guessed) collapse to
  one rep, since the SAT-level guarantees only matter for keeping
  distinct targets distinct.
- `UnionFind.find` is now iterative (was recursive) — removes the
  Python-recursion-limit landmine on long chains.
- `tools/relation_generator.py` and
  `automated_key_recovery/tools/relation_generator.py` both translate
  their legacy flags (`canonical`, `cross_round_dir`, `boundary_naming`)
  into a `CleanerConfig` and pass `config=` to `clean_relations`, so
  pipeline runs no longer trip the `DeprecationWarning`.
- `RelGenConfig` user-facing fields are unchanged.
  Existing scripts that pass `canonical=`, `cross_round_dir=`, or
  `boundary_naming=` to `RelGenConfig(...)` keep working with no
  changes.
- `automated_key_recovery/tools/relation_generator_modules/cleaner.py`
  is mirrored from the outer copy — no drift between the two trees.

## 2026-05-09 — `cleaner.py` (revert + proper orphan fix)

**Revert of the 2026-04 dense-anchor collapse — the original
preserved-equality-chain behavior is restored. The orphan-leak bug
that motivated the collapse is now patched at its true source.**

- `_build_same_round_map` (dense-anchor branch, 2+ anchored vars in one
  same-round class) once again keeps distinct anchored vars in the output
  via an explicit equality chain among `anchored_in_cls ∪ {rep}`. The
  collapse-everything behavior added in 2026-04 mis-merged distinct
  target IDs that happened to share a rename equivalence class —
  downstream verifiers that check per-ID derivability could not find
  the merged-away IDs.
- The orphan leak (e.g. `vs_2_0_0` surviving in a preserved rename line
  but renamed to a different rep in `not_guessed` via cross-round
  substitution) is fixed in `clean_relations` by running `preserved_same`
  through `cross_map` and `_remove_trivial` — same as `non_rename`. This
  keeps preserved chains in sync with the anchored sections instead of
  letting them go stale.



## 2026-04 — `relation_generator_modules/cleaner.py`

**Dense-anchor same-round equivalence classes now collapse to a single
representative instead of preserving an equality chain.**

- Affected function: `_build_same_round_map`.
- Previous behavior: when 2+ anchored variables (members of `known`,
  `target`, or `not_guessed`) landed in the same same-round equivalence
  class, the cleaner kept all of them distinct and emitted equality-chain
  rename lines among them.
- Problem: under dense anchoring (e.g. `trail_to_key_recovery` placing
  every state variable into `not_guessed`), the preserved-chain pass did
  not coordinate with the cross-round substitution pass. Orphaned IDs
  like `vs_2_0_0` survived in preserved rename lines but were never
  substituted in the `not_guessed` section, so AutoGuess saw them as
  free variables and "guessed" state cells, producing spurious state-
  variable leakage in the reported guess basis.
- New behavior: collapse the entire class to one representative, same as
  the 0/1-anchored case. Mathematically sound — anchored vars in the same
  rename class are asserted equal by construction, so distinguishing them
  was never information-bearing.
- Introduced in commit `0c03653` ("updated the code base").

## 2026-05 — `cleaner.py`, `relation_generator.py`, `RelGenConfig`

- New `boundary_naming: "input" | "output" | None` parameter on
  `clean_relations`, `generate_relations`, and `RelGenConfig`. When set,
  it pins `canonical` and `cross_round_dir` to a consistent pair so the
  boundary basis is reported under a single naming convention.
- Documented that the default raw flag pair
  (`canonical=True, cross_round_dir=False`) is a mixed convention.
- Removed dead `# ORIGINAL PRESERVED-CHAIN LOGIC` block from
  `_build_same_round_map` (rationale moved to the 2026-04 entry above).
- Removed unused `cross_round` parameter from `_choose_rep`.
- Post-substitution dedup: drops entries from `target` that collide with
  `known` (already-known targets are already achieved). The original
  `known` ∩ `not_guessed` dedup is preserved. Note: `target` ∩ `not_guessed`
  is intentionally NOT deduped because `protect_all_targets=True` in
  `search_guess_basis` adds every target to `not_guessed` on purpose;
  dropping the overlap would silently disable the protection.
- `canonical` and `cross_round_dir` are now `Optional[bool]` with default
  `None` ("use default") on `clean_relations`, `generate_relations`, and
  `RelGenConfig`. When `boundary_naming` is set, passing an explicit
  non-None value that conflicts with the forced setting issues a
  `UserWarning` instead of silently overriding. Default behavior unchanged
  for callers that don't explicitly set these flags.
