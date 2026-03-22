# Autoguess (without SageMath)

A standalone implementation of the [Autoguess](https://github.com/hadipourh/autoguess) tool that does **not** require SageMath. This tool automates **guess-and-determine** attacks and **key-bridging** techniques on symmetric ciphers using a variety of solvers:

- **SAT** via [PySAT](https://github.com/pysathq/pysat) (default)
- **CP** via [MiniZinc](https://www.minizinc.org/) (with OR-Tools / Gecode / Chuffed)
- **MILP** via [Gurobi](https://www.gurobi.com/)
- **SMT** via [pySMT](https://github.com/pysmt/pysmt) (Z3 backend)
- **Propagation** — lightweight solver-free mode

> This implementation follows the same directory structure and relation file format as the original [autoguess](https://github.com/hadipourh/autoguess) project. The Groebner basis solver is not available (it requires SageMath).

---

## Table of Contents

- [Autoguess (without SageMath)](#autoguess-without-sagemath)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Python Setup](#python-setup)
    - [Optional Dependencies](#optional-dependencies)
  - [Example 1](#example-1)
  - [***CP***](#cp)
  - [***SAT***](#sat)
  - [***SMT***](#smt)
  - [***MILP***](#milp)
  - [***Propagate***](#propagate)
  - [Input File Format](#input-file-format)
  - [Command Line Reference](#command-line-reference)
  - [Examples](#examples)
    - [Example 1 — Simple Connection Relations](#example-1--simple-connection-relations)
    - [Example 4 — Algebraic Relations with Preprocessing](#example-4--algebraic-relations-with-preprocessing)
    - [SKINNY-TK3 — Key Bridging with Findmin](#skinny-tk3--key-bridging-with-findmin)
  - [New Features](#new-features)
    - [Find Minimum Guesses (`--findmin`)](#find-minimum-guesses---findmin)
    - [Extra Known Variables (`--known`)](#extra-known-variables---known)
    - [Reduce Basis (`--reducebasis`)](#reduce-basis---reducebasis)
    - [Propagation Mode](#propagation-mode)
  - [Solver-Specific Notes](#solver-specific-notes)
  - [Troubleshooting](#troubleshooting)
    - [Common Issues](#common-issues)
    - [Performance Tips](#performance-tips)
  - [Credits](#credits)
  - [License](#license)

---

## Installation

### Prerequisites

| Dependency | Required? | Purpose |
|---|---|---|
| Python 3.10+ | Yes | Runtime |
| [PySAT](https://github.com/pysathq/pysat) | Yes | SAT solving (core solver) |
| [Graphviz](https://graphviz.org/) (system package) | Recommended | Render determination flow graphs |
| [MiniZinc](https://www.minizinc.org/) | For CP solver | Constraint programming |
| [Gurobi](https://www.gurobi.com/) | For MILP solver | Mixed-integer linear programming (requires license) |
| [pySMT](https://github.com/pysmt/pysmt) + Z3 | For SMT solver | Satisfiability modulo theories |

### Python Setup

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install core dependencies (SAT solver + visualization)
pip install 'python-sat[pblib,aiger]' graphviz dot2tex
```

### Optional Dependencies

Install only the solvers you plan to use:

```bash
# CP solver (requires MiniZinc system binary)
pip install minizinc
# Then install MiniZinc: brew install minizinc (macOS) or apt install minizinc (Ubuntu)

# SMT solver
pip install pysmt
pysmt-install --z3   # Downloads and installs the Z3 backend

# MILP solver (requires Gurobi license)
pip install gurobipy

# Preprocessing (--preprocess 1) uses Macaulay basis reduction over GF(2),
# which requires numba for JIT-compiled linear algebra
pip install numba

# Graphviz system binary (for rendering graphs to PDF)
# macOS:  brew install graphviz
# Ubuntu: apt install graphviz libpangocairo-1.0-0
```

---

## Example 1
Find a minimal guess basis for Example1 using CP

## ***CP***
```bash
python3 autoguess.py --inputfile ciphers/Example1/relationfile.txt --solver cp --maxsteps 5 --dglayout circo
```

Output:
```
OR Tools is available
Generating the CP model ...
CP model was generated after 0.00 seconds
Solving the CP model with cp-sat ...
Solving process was finished after 0.39 seconds

============================================================
RESULTS
============================================================
Number of guesses:         2
Known in final state:      7 / 7
Max steps used:            5
------------------------------------------------------------
Guessed variable(s) (2):
  v, u
============================================================
```
Using SAT solver
## ***SAT***
```bash
python3 autoguess.py --inputfile ciphers/Example1/relationfile.txt --solver sat --maxguess 2 --maxsteps 5
```
Output:
```
============================================================
SAT SOLVER — Taken from https://doi.org/10.1007/978-3-642-00862-7_11: Speeding up Collision Search for Byte-Oriented Hash Functions
============================================================
Variables: 7 | Relations: 5
Max guess: 2 | Max steps: 5
Solver: cadical153
------------------------------------------------------------
MODEL GENERATION
------------------------------------------------------------
SAT model generated in 0.00 seconds
------------------------------------------------------------
SOLVING
------------------------------------------------------------
Solving finished in 0.00 seconds

============================================================
RESULTS
============================================================
Number of guesses:         2
Known in final state:      7 / 7
Max steps used:            5
------------------------------------------------------------
Guessed variable(s) (2):
  x, s
============================================================
```
Using ```--findmin```

```bash
python3 autoguess.py --inputfile ciphers/Example1/relationfile.txt --solver sat --findmin 
```

```
============================================================
FIND-MIN MODE: searching for minimum guesses (starting from 7)
============================================================
  max_guess = 7:  SAT  — a guess basis of size 7 exists  (0.00s)
  max_guess = 6:  SAT  — a guess basis of size 6 exists  (0.00s)
  max_guess = 5:  SAT  — a guess basis of size 5 exists  (0.00s)
  max_guess = 4:  SAT  — a guess basis of size 4 exists  (0.00s)
  max_guess = 3:  SAT  — a guess basis of size 2 exists  (0.00s)
  max_guess = 2:  SAT  — a guess basis of size 2 exists  (0.00s)
  max_guess = 1:  UNSAT  (0.00s)

############################################################
FIND-MIN RESULT: minimum number of guesses = 2
Total findmin time: 0.00s
############################################################

Re-solving with max_guess = 2 for detailed output ...

(Note: the timings below are for this single verification
 solve only, not for the entire findmin search.)

============================================================
SAT SOLVER — Taken from https://doi.org/10.1007/978-3-642-00862-7_11: Speeding up Collision Search for Byte-Oriented Hash Functions
============================================================
Variables: 7 | Relations: 5
Max guess: 2 | Max steps: 7
Solver: cadical153
------------------------------------------------------------
MODEL GENERATION
------------------------------------------------------------
SAT model generated in 0.00 seconds
------------------------------------------------------------
SOLVING
------------------------------------------------------------
Solving finished in 0.00 seconds

============================================================
RESULTS
============================================================
Number of guesses:         2
Known in final state:      7 / 7
Max steps used:            7
------------------------------------------------------------
Guessed variable(s) (2):
  x, s
============================================================

Total findmin search time: 0.00s
```
Using SMT solver
## ***SMT***
```bash
python3 autoguess.py --inputfile ciphers/Example1/relationfile.txt --solver smt --maxguess 2 --maxsteps 5
```
Output:
```
Generating the SMT model ...
SMT model was generated after 0.01 seconds
Checking the satisfiability of the constructed SMT model using z3 ...
Checking was finished after 0.00 seconds

============================================================
RESULTS
============================================================
Number of guesses:         2
Known in final state:      7 / 7
Max steps used:            5
------------------------------------------------------------
Guessed variable(s) (2):
  x, v
============================================================
```

Using MILP solver
## ***MILP***
```bash
python3 autoguess.py --inputfile ciphers/Example1/relationfile.txt --solver milp --maxsteps 5
```

Output:
```
Generating the MILP model ...
MILP model was generated after 0.00 seconds
Set parameter Username
Set parameter LicenseID to value 2762404
Academic license - for non-commercial use only - expires 2027-01-09
Read LP format model from file temp/milp_mg7_ms5_min_55355325835fbfb9cb871ab7586d43.lp
Reading time = 0.00 seconds
: 287 rows, 167 columns, 1084 nonzeros
Set parameter MIPFocus to value 0
Set parameter Threads to value 0
Set parameter OutputFlag to value 1
Gurobi Optimizer version 13.0.0 build v13.0.0rc1 (mac64[arm] - Darwin 25.3.0 25D2128)

CPU model: Apple M3 Pro
Thread count: 11 physical cores, 11 logical processors, using up to 11 threads

Optimize a model with 287 rows, 167 columns and 1084 nonzeros (Min)
Model fingerprint: 0x0a059f52
Model has 7 linear objective coefficients
Variable types: 0 continuous, 167 integer (167 binary)
Coefficient statistics:
  Matrix range     [1e+00, 5e+00]
  Objective range  [1e+00, 1e+00]
  Bounds range     [1e+00, 1e+00]
  RHS range        [1e+00, 7e+00]
Found heuristic solution: objective 7.0000000
Presolve removed 90 rows and 67 columns
Presolve time: 0.01s
Presolved: 197 rows, 100 columns, 802 nonzeros
Variable types: 0 continuous, 100 integer (100 binary)

Root relaxation: objective 2.516199e-02, 119 iterations, 0.00 seconds (0.00 work units)

    Nodes    |    Current Node    |     Objective Bounds      |     Work
 Expl Unexpl |  Obj  Depth IntInf | Incumbent    BestBd   Gap | It/Node Time

     0     0    0.02516    0   75    7.00000    0.02516   100%     -    0s
H    0     0                       2.0000000    0.02516  98.7%     -    0s
     0     0    1.00000    0   55    2.00000    1.00000  50.0%     -    0s

Cutting planes:
  Gomory: 2
  Cover: 6
  Clique: 6
  MIR: 2
  RLT: 12
  BQP: 6

Explored 1 nodes (245 simplex iterations) in 0.02 seconds (0.02 work units)
Thread count was 11 (of 11 available processors)

Solution count 2: 2 7

Optimal solution found (tolerance 1.00e-04)
Best objective 2.000000000000e+00, best bound 2.000000000000e+00, gap 0.0000%
Solving process was finished after 0.02 seconds

============================================================
RESULTS
============================================================
Number of guesses:         2
Known in final state:      7 / 7
Max steps used:            5
------------------------------------------------------------
Guessed variable(s) (2):
  x, v
============================================================
```
Using ```--propagate```
## ***Propagate***

``` bash
python3 autoguess.py --inputfile ciphers/Example1/relationfile.txt --solver propagate --known "u,v"
```
Output:
```
============================================================
Knowledge propagation started - 2026-03-15 14:14:24.987280
Problem: Taken from https://doi.org/10.1007/978-3-642-00862-7_11: Speeding up Collision Search for Byte-Oriented Hash Functions
Total variables: 7
Total relations: 5 (symmetric: 5, implication: 0)
Initially known variables: 2
  u, v
============================================================

Iteration 1: learned 1 new variable(s)
  s  <--  [v, u, s]

Iteration 2: learned 1 new variable(s)
  x  <--  [x, s, v]

Iteration 3: learned 1 new variable(s)
  t  <--  [u, t, x]

Iteration 4: learned 1 new variable(s)
  z  <--  [z, s, v, t]

Iteration 5: learned 1 new variable(s)
  y  <--  [x, u, s, y, z]

============================================================
PROPAGATION SUMMARY
============================================================
Total iterations:          5
Initially known:           2
Newly learned:             5
Total known after prop.:   7 / 7
Unreachable variables:     0
Target variables covered:  7 / 7
Elapsed time:              0.0001 seconds
============================================================
```

---

## Input File Format

The input file is a plain text file with the following sections:

```text
# Lines starting with '#' are comments

# Optional: algebraic relations over GF(2) (requires preprocessing)
algebraic relations
X1*X4 + X2*X5 + X1 + X3 + X4
X2*X3 + X1*X6 + X3*X4 + X1

# Connection relations (symmetric or implication)
connection relations
X3, X5, X2             # Symmetric: if all but one are known, deduce the last
X1, X2, X4, X6 => X5   # Implication: if LHS known, deduce RHS

# Variables known at the start
known
X2

# Variables that must be determined
target
X1
X3
X4
X5
X6

end
```

**Relation types:**
- **Symmetric** (`a, b, c`): If all variables except one are known, the remaining one can be deduced.
- **Implication** (`a, b => c`): If all LHS variables are known, the RHS can be deduced.
- **Algebraic** (`X1*X2 + X3 + X4`): Polynomial relations over GF(2). Requires `--preprocess 1 --D <degree>` to expand via Macaulay matrix.

Many example input files are provided in the [ciphers/](ciphers/) directory.

---

## Command Line Reference

```
python3 autoguess.py [options]
```

**Core options:**

| Flag | Description | Default |
|---|---|---|
| `-i`, `--inputfile FILE` | Input relation file | `ciphers/AES/...` |
| `-o`, `--outputfile FILE` | Output file for detailed results | `output` |
| `-s`, `--solver SOLVER` | Solver: `sat`, `cp`, `milp`, `smt`, `mark`, `elim`, `propagate` | `sat` |
| `-mg`, `--maxguess N` | Upper bound on guessed variables | Auto (= #target vars) |
| `-ms`, `--maxsteps N` | Depth of search (state copies) | Auto (= #variables) |

**Solver selection:**

| Flag | Description | Default |
|---|---|---|
| `-sats`, `--satsolver` | SAT solver: `cadical153`, `glucose3`, `glucose4`, `lingeling`, `minisat22`, ... | `cadical153` |
| `-cps`, `--cpsolver` | CP solver: `cp-sat`, `gecode`, `chuffed`, `or-tools`, ... | `cp-sat` |
| `-smts`, `--smtsolver` | SMT solver: `z3`, `yices`, `btor`, `cvc5`, ... | `z3` |
| `-milpd`, `--milpdirection` | MILP: `min` or `max` | `min` |
| `-cpopt`, `--cpoptimization` | CP: `1` = minimize, `0` = satisfy | `1` |

**New features:**

| Flag | Description |
|---|---|
| `--findmin` | Find the minimum number of guesses (incremental for SAT, descent for SMT) |
| `-kn`, `--known VAR1,VAR2,...` | Extra known variables (in addition to those in the relation file) |
| `--reducebasis` | Reduce a guess basis via propagation (use with `-kn`) |
| `--nograph` | Skip graph generation (faster) |
| `-t`, `--threads N` | Thread count for MILP/CP solvers (0 = auto) |

**Preprocessing & misc:**

| Flag | Description | Default |
|---|---|---|
| `-prep`, `--preprocess` | Enable preprocessing (Macaulay matrix) | `0` |
| `-D` | Degree for Macaulay matrix | `2` |
| `-tl`, `--timelimit N` | Time limit in seconds | unlimited |
| `-tk`, `--tikz` | Generate TikZ LaTeX code | `0` |
| `-dgl`, `--dglayout` | Graphviz layout: `dot`, `circo`, `neato`, `fdp`, ... | `dot` |
| `-log` | Save intermediate models to `temp/` | `0` |

> **Note on defaults:** When `-mg` and `-ms` are not specified, they are automatically derived from the input file. `maxguess` defaults to the number of target variables, and `maxsteps` defaults to the total number of variables. This usually gives optimal results without manual tuning.

---

## Examples

### Example 1 — Simple Connection Relations

**SAT solver:**
```bash
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s sat --maxguess 2 --maxsteps 5
```

```
============================================================
SAT SOLVER — Taken from https://doi.org/10.1007/978-3-642-00862-7_11
============================================================
Variables: 7 | Relations: 5
Max guess: 2 | Max steps: 5
Solver: cadical153
------------------------------------------------------------
MODEL GENERATION
------------------------------------------------------------
SAT model generated in 0.00 seconds
------------------------------------------------------------
SOLVING
------------------------------------------------------------
Solving finished in 0.00 seconds

============================================================
RESULTS
============================================================
Number of guesses:         2
Known in final state:      7 / 7
Max steps used:            5
------------------------------------------------------------
Guessed variable(s) (2):
  x, s
============================================================
```

**With a different SAT solver (e.g., glucose3):**
```bash
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s sat --satsolver glucose3 --maxguess 2 --maxsteps 5
```

**CP solver:**
```bash
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s cp --maxsteps 5
```

**SMT solver:**
```bash
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s smt --maxguess 2 --maxsteps 5
```

### Example 4 — Algebraic Relations with Preprocessing

This example demonstrates algebraic relations over GF(2). The `--preprocess` flag expands them via the Macaulay matrix before solving.

```bash
python3 autoguess.py -i ciphers/Example4/algebraic_relations.txt -s sat --maxguess 1 --maxsteps 5 --preprocess 1 --D 3
```

### SKINNY-TK3 — Key Bridging with Findmin

Find the minimum guess basis for 23-round SKINNY-TK3 zero-correlation key bridging:

```bash
python3 autoguess.py -i ciphers/SKINNY-TK3/relationfile_skinnytk3zckb_23r_mg25_ms12_z16_13.txt -s sat --findmin -mg 25
```

```
============================================================
FIND-MIN MODE: searching for minimum guesses (starting from 25)
============================================================
  max_guess = 25:  SAT  — a guess basis of size 25 exists  (0.43s)
  max_guess = 24:  UNSAT  (0.27s)

############################################################
FIND-MIN RESULT: minimum number of guesses = 25
Total findmin time: 0.87s
############################################################

Re-solving with max_guess = 25 for detailed output ...

============================================================
RESULTS
============================================================
Number of guesses:         25
Known in final state:      36 / 104
Max steps used:            104
------------------------------------------------------------
Guessed variable(s) (25):
  tk2_2, tk3_2, tk2_5, tk3_5, tk1_9, tk3_9, sk_17_0, sk_19_5, ...
============================================================
```

---

## New Features

### Find Minimum Guesses (`--findmin`)

Automatically finds the smallest number of guesses needed. For SAT, this uses **incremental solving** with ITotalizer + assumption-based bounds — the solver is created once and learned clauses are reused, making it very efficient.

```bash
# SAT (incremental, fast)
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s sat --findmin

# SMT (per-iteration descent, slower)
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s smt --findmin
```

### Extra Known Variables (`--known`)

Supply additional known variables without editing the relation file:

```bash
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s sat --known x,s --maxsteps 5
```

### Reduce Basis (`--reducebasis`)

Given a known guess basis, try to reduce it using propagation:

```bash
python3 autoguess.py -i ciphers/Example1/relationfile.txt --reducebasis --known x,s,v
```

### Propagation Mode

A lightweight solver-free mode that iteratively deduces variables from the known set:

```bash
python3 autoguess.py -i ciphers/Example1/relationfile.txt -s propagate --known x,s
```

---

## Solver-Specific Notes

| Solver | Strengths | Notes |
|---|---|---|
| **SAT** (`cadical153`) | Fast, supports `--findmin` incrementally | Default. Best for most problems. |
| **CP** (`cp-sat`) | Good for optimization (`-cpopt 1`) | Requires MiniZinc. Falls back to gecode/chuffed if cp-sat unavailable. |
| **MILP** (Gurobi) | Optimal solutions, good for large problems | Requires Gurobi license. Use `-t` for threads. |
| **SMT** (`z3`) | Flexible, supports bitvector reasoning | Slower than SAT for pure boolean problems. |
| **Propagate** | No external solver needed | Only deduces from known variables, no search. |

---

## Troubleshooting

### Common Issues

**`ModuleNotFoundError: No module named 'minizinc'`**
CP solver requires: `pip install minizinc` + system MiniZinc binary.

**`ModuleNotFoundError: No module named 'pysmt'`**
SMT solver requires: `pip install pysmt && pysmt-install --z3`

**`ModuleNotFoundError: No module named 'gurobipy'`**
MILP solver requires: `pip install gurobipy` + valid Gurobi license.

**`WARNING: Could not render graph`**
Install the Graphviz system binary: `brew install graphviz` (macOS) or `apt install graphviz` (Ubuntu). Or use `--nograph` to skip.

**`The problem is UNSAT`**
Increase `--maxguess` and/or `--maxsteps`. Use `--findmin` to automatically find the minimum.

### Performance Tips

- Use `--nograph` to skip graph rendering for faster runs.
- Use `--findmin` with SAT for efficient minimum search (incremental solver).
- For large problems, use `-t N` to control thread count with MILP/CP solvers.
- The `--preprocess 1 --D N` flag can significantly reduce problem size for algebraic relations.

---

## Credits

This project is based on the [Autoguess](https://github.com/hadipourh/autoguess) tool by [Hosein Hadipour](mailto:hsn.hadipour@gmail.com).

**Paper:** [Autoguess: A Tool for Finding Guess-and-Determine Attacks and Key Bridges](https://doi.org/10.1007/978-3-030-81652-0_1), ACNS 2021.

```bibtex
@inproceedings{hadipourS21,
  author    = {Hosein Hadipour and Maria Eichlseder},
  title     = {Autoguess: A Tool for Finding Guess-and-Determine Attacks and Key Bridges},
  booktitle = {ACNS 2021},
  series    = {LNCS},
  volume    = {12727},
  pages     = {230--250},
  publisher = {Springer},
  year      = {2021},
  doi       = {10.1007/978-3-030-81652-0_1}
}
```

## License

MIT License. See [autoguess.py](autoguess.py) for details.
