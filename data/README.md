# Data Directory

This directory contains experimental outputs only. Raw graph datasets are not included in the uploaded package.

## Layout

- `raw_results/`: normalized copies of the original CSV result files.
- `processed/all_results_long.csv`: row-wise merged table across all raw result CSV files. Extra metadata columns are added at the beginning.
- `processed/result_summary_by_file.csv`: one-row-per-CSV summary with inferred study, dataset, attack family, ratios, and key aggregate metrics when available.
- `processed/result_file_index.csv`: inventory of all raw CSV files, including row count, schema ID, and SHA-256 checksum.
- `processed/result_schema_summary.csv`: summary of distinct CSV schemas.
- `processed/file_mapping.csv`: mapping from the original uploaded paths to the cleaned repository paths.

## Log files

The original package contained 2138 `.log` files. To keep the repository tidy, they are compressed in `logs/raw_run_logs.zip` rather than mixed into the main result tables.
