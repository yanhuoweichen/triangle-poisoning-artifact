# Robust Triangle Counting under Poisoning Attacks

This repository organizes the source code, run scripts, experimental CSV outputs, and final result figures for the robustness study of differentially private graph triangle-counting protocols under poisoning attacks.

## Repository structure

```text
.
├── src/cpp/                     # C++ source files and original shell scripts; build artifacts removed
├── data/raw_results/            # Cleaned and normalized CSV result files
├── data/processed/              # Merged tables, schema summaries, and file inventory
├── figures/final_panels/        # Final paper-ready result panels
├── logs/raw_run_logs.zip        # Compressed original run logs
├── docs/code_index.md           # Source-code grouping by experiment family
├── data/README.md               # Description of raw and processed result tables
├── Makefile                     # Optional convenience build helper
└── .gitignore
```

## Main processed tables

| File | Purpose |
|---|---|
| `data/processed/all_results_long.csv` | Long merged table containing all parsed CSV rows with metadata columns. |
| `data/processed/result_summary_by_file.csv` | Compact one-row-per-result-file summary. |
| `data/processed/result_file_index.csv` | File inventory with row counts, schema IDs, sizes, and checksums. |
| `data/processed/result_schema_summary.csv` | Overview of the different CSV schemas found in the original results. |
| `data/processed/file_mapping.csv` | Mapping from original paths to cleaned GitHub-style paths. |

## Contents summary

- C++/script files retained: **366**
- Raw CSV result files retained: **505**
- Merged result rows: **19456**
- Distinct CSV schemas: **13**
- Final PNG panels retained: **12**
- Raw log files archived: **2138**

## Build and run

The original shell scripts are kept under `src/cpp/`. For a quick compile test of a single C++ file, use:

```bash
make build TARGET=EdgeOrientDelta_TriangleLDP_RRAttack_strict
```

For full experiments, use the corresponding `run_*.sh` script in `src/cpp/` and check or adjust file paths according to your local dataset location.

## Notes for conference artifact upload

- Compiled binaries, `.o` files, `.d` dependency files, and temporary outputs were removed.
- Result CSVs were copied into English, lower-snake-case directories for easier browsing on GitHub.
- Original filenames and locations are preserved in `data/processed/file_mapping.csv`.
- Raw graph datasets are not included in the uploaded archive unless separately added by the author.
