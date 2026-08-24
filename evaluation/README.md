# Real-world MCP scanner evaluation

This directory contains the reproducible metadata, scripts, labels, and reports
for evaluating the scanner against pinned public MCP source code.

Third-party repositories are downloaded into `corpus/` and are never installed
or executed. Generated JSON is written to `raw-results/`; disposable fixer
experiments use `work/`. Those directories are intentionally ignored by Git.

Run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File evaluation/scripts/acquire.ps1
python evaluation/scripts/run_evaluation.py
```

See `REPORT.md` for findings, limitations, and interpretation guidance.

## Clean holdout

The clean holdout has a separate, one-way workflow under `holdout/`. Its source
directory, results, and one-time authorization token are ignored. Normal
evaluation commands never read or scan it. See `holdout/README.md` before adding
labels or consuming the holdout.
