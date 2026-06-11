# GitHub Upload Steps

1. Create a new GitHub repository, for example `triangle-poisoning-dp-artifact`.
2. Unzip `triangle_poisoning_artifact_github_ready.zip`.
3. Upload the contents of the `triangle_poisoning_artifact/` folder to the repository root.
4. Check `README.md`, `data/README.md`, and `docs/code_index.md` before making the repository public.
5. If the conference submission system asks for a repository URL, submit the GitHub repository link after the files are uploaded.

## Recommended checks before submission

- Confirm whether raw graph datasets are allowed or required. The current package contains experimental results, code, figures, and logs, but not raw graph edge-list datasets.
- Confirm whether large logs should remain in `logs/raw_run_logs.zip`. If not required, remove that zip before upload.
- Confirm that all shell scripts still point to the correct local dataset paths on your machine.
