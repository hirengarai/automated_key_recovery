# key_reco

Differential **key-recovery** cost estimation on top of
[OCP](https://github.com/Open-CP/OCP) and AutoGuess.

Give it a cipher, a differential distinguisher and a round split, and it estimates
what recovering the involved key bits costs: it extends the distinguisher by `r_b`
rounds at the top and `r_f` at the bottom, finds the active S-boxes in those
extension rounds, and peels them one at a time with AutoGuess — accumulating the
key bits guessed and the differential filtering each S-box provides.

It can also sweep many round splits and report the best attack.

## Install

Python 3.12 or 3.14, and six packages — five to run an attack, plus pytest for the
tests. No solver licence is required: key recovery runs entirely on the open-source
SAT backend, and Gurobi, SCIP, OR-Tools, Z3 and MiniZinc are all optional.

```
python3 -m venv env
./env/bin/pip install -r requirements.txt
```

Build your own virtualenv rather than copying someone else's — the one in `env312/`
is machine-specific and is not part of the source.

Two things to know before comparing numbers with someone else:

* **Run one script at a time.** OCP writes its model to a fixed path under `files/`,
  keyed by cipher and goal, so two concurrent runs overwrite each other.
* **A searched distinguisher is not guaranteed stable across solver versions.** The
  minimum-weight trail is generally not unique, so a different `python-sat` may
  return a different — equally optimal — trail, and every number derived from it
  moves with it. In practice it has held: `skinny_64_attack.py` returns a
  byte-identical trail and `T = 2^5.26` under both 1.9.dev2 and 1.9.dev15 (measured
  2026-08-18). It is not something to rely on, though, so compare against the scripts
  that pin a published trail — `present_80_attack.py`, `rectangle_attack.py` and
  `gift_64_attack.py` are identical on every version, and `present_80_attack.py`
  gives `T = 2^61.46` on both.

## Use

Edit the parameter block at the top of `run_attack()` and run the file:

```
./env/bin/python test/key_recovery/run_attack.py
```

The cipher is chosen by the import and the two factories at the top of the file;
everything else is the parameter block:

```python
from primitives.present import PRESENT_BLOCKCIPHER, PRESENT_PERMUTATION

def cipher_factory(r):
    return PRESENT_BLOCKCIPHER(r=r, version=[64, 80], final_whitening=True)

def perm_factory(r):
    return PRESENT_PERMUTATION(r=r)

key_bits = 80

# Round split: R_d rounds of distinguisher, r_b rounds before, r_f rounds after.
# Give ANY of the three a list (e.g. R_d = [4, 5, 6], r_f = [0, 1]) to try every
# combination and report the best.
R_d = 4
r_b = 1
r_f = 0

# None: search for a distinguisher. A dict keyed by R_d pins published ones instead;
# any R_d not listed is still searched:
#   published = {14: {"weight": 62, "delta_in": 0x0700000000000700,
#                     "delta_out": 0x0000000900000009}}
published = None

independent_round_keys = False   # True: treat subkeys as independent
maxsteps = 40                    # raise if AutoGuess runs out of steps

# Used when R_d, r_b or r_f is a list.
targeted_security = None         # None = key_bits
objective = "max_rounds"   # "max_rounds" (then lowest time) | "min_time"
```

A number gives one attack with a full report; a list sweeps every combination and
reports the best one within `targeted_security` bits.

`R_d = 4, r_b = 1, r_f = 0` finishes in well under a minute (about 15 s, most of it
the trail search) and is the quickest way to check an install. Cost grows roughly quadratically in the number of active S-boxes, because
the greedy re-solves every remaining S-box at each step — the published PRESENT-80
attack (`2 + 14 + 1`, 17 S-boxes) takes about 4 minutes.

## Output

```
Trail                          what the distinguisher gives: p, d_in, d_out, N
Ordering                       one row per S-box: key bits, filter, work, pairs left
Summary                        C_KR, T = C_KR * N, F, the key-completion floor,
                               and whether T < 2^keysize
```

`T = C_KR * N` is the cost of the key-recovery step and decides validity, following
Boura et al.: their tables report and gate on exactly this quantity, with the data
complexity deliberately excluded.

`T` is not the whole attack. The key bits the peel does not determine are filled in
by search over the surviving triplets, at `N * 2^(keysize - F)` where `F` is the
total filtering — printed as `Key completion`. Both `N` and `F` are fixed before the
greedy runs, so no ordering can change that term; it is a floor on the attack, and
on a short distinguisher (few active S-boxes, hence small `F`) it is the term that
dominates. The Summary flags which of the two binds.

## Layout

```
attacks/
  key_recovery.py              the engine: search_key_recovery(...)
  key_recovery_modules/        propagation, DDT filters, greedy peel, AutoGuess bridge
  attacks.py                   key_recovery_attack(), the timing wrapper
test/key_recovery/
  run_attack.py                the script to edit
  *_attack.py                  one attack at a fixed split
  sweep_*.py                   many splits, best one reported
docs/design/                   design notes, findings and measured results
```

Everything outside `attacks/key_recovery*` and `test/key_recovery/` is OCP.

## Sweeping round splits

One attack needs a split you already chose. `auto_key_recovery` chooses it for you:
it tries many `(r_b, R_d, r_f)` combinations, drops any attack costing more than the
targeted security level, and returns the best of what is left.

```python
from attacks.key_recovery_modules.auto_wrapper import auto_key_recovery

auto_key_recovery(
    cipher_factory, perm_factory, key_bits=80,
    r_b_values=(1, 2), r_d_values=(4, 14), r_f_values=(0, 1),  # the combinations
    targeted_security=None,        # default: key_bits -- nothing costlier is returned
    objective="max_rounds",        # default: most rounds, ties broken on lowest T
)
```

Every input is optional except the two factories and `key_bits`:

| input | default | meaning |
| --- | --- | --- |
| `r_b_values`, `r_d_values`, `r_f_values` | `(1,2)`, `(10,)`, `(0,1)` | the combinations to try, as a cross product |
| `splits` | built from the three above | the combinations given explicitly, `[(r_b, R_d, r_f), ...]` |
| `objective` | `"max_rounds"` | `"max_rounds"` (most rounds, then lowest T), `"min_time"`, or a callable taking a result row and returning a sort key |
| `targeted_security` | `key_bits` | attacks costing more are never returned |
| `full_rounds` | none | splits totalling more rounds than the real cipher are skipped |
| `manual_distinguishers` | none | `{R_d: {"weight", "delta_in", "delta_out"}}`; any R_d not listed is searched |

It returns `{"cipher", "targeted_security", "best", "results", "valid_results"}`.
`results` holds every split tried -- over-budget ones flagged `valid=False`, failed
ones carrying a `skipped` reason instead of numbers -- so a run can be kept and
re-ranked under a different objective without solving anything again.

## Scripts

`test/key_recovery/` ships one script per configuration.

| script | what it is |
| --- | --- |
| `run_attack.py` | the one to edit; a single attack, or a sweep if any of `R_d`/`r_b`/`r_f` is a list |
| `present_80_attack.py` | 2+14+1, published distinguisher (Wang) |
| `rectangle_attack.py` | 2+14+2, published (design paper, App. E) |
| `gift_64_attack.py` | 3+13+2, published (Chen-Zong-Dong) |
| `skinny_64_attack.py` | 1+5+1, distinguisher searched |
| `led_64_attack.py` | 1+2+0, searched |
| `aes_128_attack.py` | 1+2+0, searched |
| `sweep_present_80.py` | sweep, all defaults; pinned 14-round trail and a searched 4-round one in one run |
| `sweep_rectangle_80.py` | sweep with the combinations given explicitly as `splits=[...]` |
| `sweep_skinny_64.py` | sweep over distinguisher LENGTH, ranked by `min_time` |
| `sweep_twine_80.py` | sweep ranked by a custom `objective` callable |
| `sweep_gift_64.py` | sweep with `targeted_security` below the key size |
| `sweep_led_64.py` | sweep, reading `results` and re-ranking without re-solving |
| `test_key_recovery_units.py` | solver-free unit tests: DDT filters, mask algebra, trail construction |
| `test_greedy_recurrence.py` | the cost model itself, with `_run_candidate` substituted -- no cipher, no solver |

`sweep_present_80.py` selects the published `2+14+1` attack at `T = 2^61.46`, the
same figure `present_80_attack.py` produces on its own, so the sweep path and the
single-attack path agree.

`pytest test/key_recovery` runs the two test modules in well under a second — 48
tests, none of which starts a solver. The `*_attack.py` and `sweep_*.py` runs take
minutes each and are deliberately not named `test_*` so pytest does not collect
them.

There is no registry — any OCP block cipher with an S-box layer works, so adding a
cipher means importing it and writing the two factories. Two known exceptions: GIFT
cannot search a distinguisher (`attack_trace.save_json` raises `Object of type
GIFT_Sbox is not JSON serializable`, in upstream OCP too), so it must be given a
published one; and LBlock's differential search returns weight 0 for a non-zero
trail, so its `p` — and everything derived from it — is meaningless. Both are
recorded in `CHANGELOG.md`.

The estimate is an upper bound: the difference sets are tracked as per-word
patterns, which over-approximate when a linear layer mixes words, so costs are
conservative rather than tight. `sum(filter) == d_in + d_out` is NOT a theorem — it
holds only when no boundary bit is forced, words fill, and the extension's linear
layers are bit permutations (PRESENT and GIFT happen to satisfy all three). Where it
does not hold the filtering is under-counted, so the reported cost is too high
rather than too low. See `docs/design/key-recovery-design.md`.

Only one attack script may run at a time on a given checkout: OCP writes its
model to a fixed path under `files/`, keyed by cipher and goal, so two concurrent
runs at the same round count overwrite each other's model.

See `CHANGELOG.md` and `docs/design/key-recovery-design.md` for the detail.

## Reference

C. Boura, N. David, P. Derbez, R. Heim Boissier, M. Naya-Plasencia,
*A generic algorithm for efficient key recovery in differential attacks – and its
associated tool*, EUROCRYPT 2023.
