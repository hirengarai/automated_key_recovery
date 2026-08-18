# GIFT-64 differential key-recovery — run log

> Carried over from the `key-reco` repository: the numbers below were produced
> there, against that repository's primitives, at the `2+13+2` and `3+13+1` splits.
> Treat them as a historical record, not as this repository's output.
>
> `gift_64_attack.py` has since been run here, at the `3+13+2` and `4+13+4` splits
> — see `docs/design/key-recovery-design.md` for those measurements. No split is
> common to both, so the two sets of numbers are not directly comparable.
>
> Three changes post-date this log and would move it: the right-pair correction to
> `N`, the set-size definition of `d_in`/`d_out`, and bounding memory by the data
> (Run B below reports `M = 2^64` against `D = 2^63.06`, which the current code no
> longer does).

Cipher: **GIFT-64/128** (28 rounds). Distinguisher fixed across runs:
Chen-Zong-Dong, *Improved Differential Attacks on GIFT-64*, ICICS 2019
(`articles/gift.pdf`), Table 8 / §5.2.

- 13-round single differential, p ≈ 2^-62.0634 (weight 62.0634)
- Δin = `0x0000000000000202` (bits 1, 9, Hamming weight 2)
- Δout = `0x0000000500000005` (bits 0, 2, 32, 34) — output difference shared by the paper's differentials

Paper reference complexities (single-key, single differential):
20-round (3+13+4) = data 2^64 / time 2^101.68 / mem 2^96;
21-round (4+13+4) = 2^64 / 2^107.61 / 2^96.

> Note: the script's `cipher_name` string still reads "21-round attack" — it is static.
> The real attack length is `r_b + 13 + r_f`, which is **17 rounds for both runs below**.
> `T` reported by the tool is key-recovery distillation work over the *committed* subkey
> bits only; it excludes the data term and the `2^(128 − committed)` final key search.

## Summary

| Run | r_b, r_f | Rounds | Distinguisher | Active S-boxes | d_in | d_out | N | D (data) | M (mem) | Key bits | C_KR | T | Valid |
|-----|----------|--------|---------------|----------------|------|-------|---------|----------|---------|----------|--------|---------|-------|
| A   | 2, 2     | 17     | [3, 15]       | 16             | 16   | 32    | 2^46.06 | 2^63.06  | 2^16.00 | 22       | 2^0.20 | 2^46.27 | Yes   |
| B   | 3, 1     | 17     | [4, 16]       | 24             | 64   | 8     | 2^70.06 | 2^63.06  | 2^64.00 | 16       | 2^0.19 | 2^70.26 | Yes   |

Observations:
- **Run A (2,2)** keeps the input side small (d_in = 16) — the practical split.
- **Run B (3,1)** pushes 3 rounds onto the input side, so the difference fully diffuses
  backward: d_in = 64 (whole block) → M = 2^64 and N = 2^70.06 **exceeds the full
  codebook (2^63.06)**. So 3,1 is degenerate in practice even though the gate marks it valid
  — the structure would need the entire codebook and still lacks the required pairs.
- Both recover few subkey bits (22 / 16); the bulk of the key still needs exhaustive search.

---

## Run A — r_b = 2, r_f = 2

```
GIFT-64 (Chen-Zong-Dong 13-round distinguisher, 21-round attack)
R_d=13, r_b=2, r_f=2   (attack 17 rounds, distinguisher = [3, 15])

Trail
  weight p       = 62.0634
  active S-boxes = 16
  d_in           = 16
  d_out          = 32
  N              = 2^46.06
  D (data)       = 2^63.06
  M (memory)     = 2^16.00

Ordering (16 S-boxes)  [AutoGuess + conditional target-side filter]
  Step  S-box                          ΔK    filter   Work        Pairs left
  1     sb_b_r1_[4,5,6,7]              0     3.00     2^46.06     2^43.06    key vars: (none)
  2     sb_b_r1_[12,13,14,15]         0     3.00     2^43.06     2^40.06    key vars: (none)
  3     sb_b_r1_[0,1,2,3]             0     2.00     2^40.06     2^38.06    key vars: (none)
  4     sb_b_r1_[8,9,10,11]           0     2.00     2^38.06     2^36.06    key vars: (none)
  5     sb_f_r17_[0,1,2,3]            2     3.00     2^38.06     2^35.06    key vars: vk_1_0_108, vk_1_0_120
  6     sb_b_r2_[32,33,34,35]         1     3.00     2^36.06     2^33.06    key vars: vk_1_0_104
  7     sb_f_r17_[8,9,10,11]          2     3.00     2^35.06     2^32.06    key vars: vk_1_0_100, vk_1_0_112
  8     sb_b_r2_[0,1,2,3]             1     3.00     2^33.06     2^30.06    key vars: vk_1_0_96
  9     sb_f_r17_[16,17,18,19]        2     3.00     2^32.06     2^29.06    key vars: vk_1_0_109, vk_1_0_121
  10    sb_f_r17_[24,25,26,27]        2     3.00     2^31.06     2^28.06    key vars: vk_1_0_101, vk_1_0_113
  11    sb_f_r17_[32,33,34,35]        2     3.00     2^30.06     2^27.06    key vars: vk_1_0_110, vk_1_0_122
  12    sb_f_r17_[40,41,42,43]        2     3.00     2^29.06     2^26.06    key vars: vk_1_0_102, vk_1_0_114
  13    sb_f_r17_[48,49,50,51]        2     3.00     2^28.06     2^25.06    key vars: vk_1_0_111, vk_1_0_123
  14    sb_f_r16_[0,1,2,3]            2     4.00     2^27.06     2^23.06    key vars: vk_1_0_14, vk_1_0_20
  15    sb_f_r17_[56,57,58,59]        2     3.00     2^25.06     2^22.06    key vars: vk_1_0_103, vk_1_0_115
  16    sb_f_r16_[32,33,34,35]        2     4.00     2^24.06     2^20.06    key vars: vk_1_0_0, vk_1_0_22

Summary
  C_KR (ESTIMATE)      : 2^0.20
  Key bits committed   : 22
  T = C_KR * N         : 2^46.27   (= 2^0.20 * 2^46.06; key-recovery work, data cost excluded)
  Total filter F       : 48.00   (= d_out + d_in = 48) ✓
  Valid attack         : Yes  (T < 2^128)
```

---

## Run B — r_b = 3, r_f = 1

```
GIFT-64 (Chen-Zong-Dong 13-round distinguisher, 21-round attack)
R_d=13, r_b=3, r_f=1   (attack 17 rounds, distinguisher = [4, 16])

Trail
  weight p       = 62.0634
  active S-boxes = 24
  d_in           = 64
  d_out          = 8
  N              = 2^70.06
  D (data)       = 2^63.06
  M (memory)     = 2^64.00

Ordering (24 S-boxes)  [AutoGuess + conditional target-side filter]
  Step  S-box                          ΔK    filter   Work        Pairs left
  1     sb_b_r1_[0,1,2,3]             0     3.00     2^70.06     2^67.06    key vars: (none)
  2     sb_b_r1_[4,5,6,7]             0     3.00     2^67.06     2^64.06    key vars: (none)
  3     sb_b_r1_[8,9,10,11]           0     3.00     2^64.06     2^61.06    key vars: (none)
  4     sb_b_r1_[12,13,14,15]         0     3.00     2^61.06     2^58.06    key vars: (none)
  5     sb_b_r1_[16,17,18,19]         0     3.00     2^58.06     2^55.06    key vars: (none)
  6     sb_b_r1_[20,21,22,23]         0     3.00     2^55.06     2^52.06    key vars: (none)
  7     sb_b_r1_[24,25,26,27]         0     3.00     2^52.06     2^49.06    key vars: (none)
  8     sb_b_r1_[28,29,30,31]         0     3.00     2^49.06     2^46.06    key vars: (none)
  9     sb_b_r1_[32,33,34,35]         0     3.00     2^46.06     2^43.06    key vars: (none)
  10    sb_b_r1_[36,37,38,39]         0     3.00     2^43.06     2^40.06    key vars: (none)
  11    sb_b_r1_[40,41,42,43]         0     3.00     2^40.06     2^37.06    key vars: (none)
  12    sb_b_r1_[44,45,46,47]         0     3.00     2^37.06     2^34.06    key vars: (none)
  13    sb_b_r1_[48,49,50,51]         0     3.00     2^34.06     2^31.06    key vars: (none)
  14    sb_b_r1_[52,53,54,55]         0     3.00     2^31.06     2^28.06    key vars: (none)
  15    sb_b_r1_[56,57,58,59]         0     3.00     2^28.06     2^25.06    key vars: (none)
  16    sb_b_r1_[60,61,62,63]         0     3.00     2^25.06     2^22.06    key vars: (none)
  17    sb_f_r17_[0,1,2,3]            2     4.00     2^24.06     2^20.06    key vars: vk_1_0_108, vk_1_0_120
  18    sb_f_r17_[32,33,34,35]        2     4.00     2^22.06     2^18.06    key vars: vk_1_0_110, vk_1_0_122
  19    sb_b_r2_[4,5,6,7]             2     3.00     2^20.06     2^17.06    key vars: vk_1_0_113, vk_1_0_97
  20    sb_b_r2_[12,13,14,15]         2     3.00     2^19.06     2^16.06    key vars: vk_1_0_115, vk_1_0_99
  21    sb_b_r2_[0,1,2,3]             2     2.00     2^18.06     2^16.06    key vars: vk_1_0_112, vk_1_0_96
  22    sb_b_r2_[8,9,10,11]           2     2.00     2^18.06     2^16.06    key vars: vk_1_0_114, vk_1_0_98
  23    sb_b_r3_[0,1,2,3]             2     3.00     2^18.06     2^15.06    key vars: vk_1_0_64, vk_1_0_80
  24    sb_b_r3_[32,33,34,35]         2     3.00     2^17.06     2^14.06    key vars: vk_1_0_72, vk_1_0_88

Summary
  C_KR (ESTIMATE)      : 2^0.19
  Key bits committed   : 16
  T = C_KR * N         : 2^70.26   (= 2^0.19 * 2^70.06; key-recovery work, data cost excluded)
  Total filter F       : 72.00   (= d_out + d_in = 72) ✓
  Valid attack         : Yes  (T < 2^128)
```
