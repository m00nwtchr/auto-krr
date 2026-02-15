# Repository Guidelines

## Project Structure & Module Organization
- `src/auto_krr/` contains the Python package and core logic (CLI, git/forgejo helpers, KRR parsing, YAML patching).
- `main.py` is a lightweight entry point for running the CLI without installing.
- `examples/` holds sample manifests like `examples/helmrelease-auto-krr.yaml`.
- `Containerfile`, `devenv.nix`, and `devenv.yaml` define container/dev environment tooling.

## Build, Test, and Development Commands
- `python -m venv .venv && source .venv/bin/activate` sets up a local venv.
- `pip install -e .` installs the CLI in editable mode.
- `uv sync --extra dev` installs dev dependencies (recommended).
- `python main.py --help` runs the CLI without installing.
- `auto-krr --krr-json /path/to/krr.json --repo /path/to/git/repo` runs a dry-run (default).
- `auto-krr --krr-json ... --repo ... --write` writes changes to manifests.

## Coding Style & Naming Conventions
- Use 4-space indentation, type hints where they add clarity, and snake_case for functions/variables.
- Keep module names short and descriptive (e.g., `git_utils.py`, `yaml_utils.py`).
- Formatting/linting is managed via `ruff` through `treefmt` (see `devenv.nix`).
- Prefer small, focused functions; keep CLI behavior in `src/auto_krr/cli.py`.

## Testing Guidelines
- No dedicated test suite is present yet. If adding tests, place them under `tests/` and name files `test_*.py`.
- Prefer `pytest` conventions if you introduce it; document how to run tests in the PR.
- Tests should reflect intended behaviour and be used to validate whether changes match that intent.

## Commit & Pull Request Guidelines
- Recent commits use short, imperative summaries; some follow Conventional Commits (`fix: ...`).
- Use concise messages like `fix: handle forgejo auth` or `add krr severity filter`.
- PRs should include: a brief description, example command(s) run, and any relevant output or screenshots for YAML changes.

## Configuration & Safety Notes
- The tool is dry-run by default; `--write` is required to modify files.
- Only tracked YAML files are scanned, so ensure target manifests are committed before running.
- Forgejo PR creation requires `FORGEJO_TOKEN` and related `--forgejo-*` flags.
- KRR reports live in-cluster workloads (Deployments, StatefulSets, etc.) while the repo contains upstream controllers (HelmReleases, CRs) that generate them; mapping between the two must remain explicit.
- The `controller=` target value refers to the runtime workload resource name (from KRR), e.g. `controller=trivy-operator` means a workload named `trivy-operator` exists (Deployment/StatefulSet/etc.), not the repo controller.
- Namespaces from KRR are hints only and should not overwrite repo-derived resource references unless the mapping is certain.
