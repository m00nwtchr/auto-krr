# auto-krr

Apply KRR (Kubernetes Resource Recommender) resource recommendations to Flux HelmRelease manifests. The tool reads a `krr.json` report, uses flate to discover which Helm values produce each rendered container, and updates the corresponding `resources` fields. It can optionally commit and open a Forgejo PR.

This is a CLI-first project and is **dry-run by default**.

## Features
- Reads `krr.json` and aggregates per-container recommendations.
- Filters by severity (OK/GOOD/WARNING/CRITICAL).
- Matches Flux HelmReleases by probing chart values and rendering them with flate.
- Updates the discovered Helm values path with CPU/memory requests/limits.
- Git-aware: only touches tracked YAML files; can stage/commit/push and open a PR.

## KRR vs repo objects (summary)
KRR reports live in-cluster workloads (Deployments, StatefulSets, etc.), but this tool updates the upstream repo resources (HelmReleases/CRs) that generate those workloads. The `controller=` target value refers to the runtime workload resource name from KRR, e.g. `controller=trivy-operator` means a workload named `trivy-operator` exists (Deployment/StatefulSet/etc.), not the repo controller. Any namespace or identity from KRR is treated as a hint and only used when the mapping is certain.

## Requirements
- Python 3.13+
- `ruamel-yaml`
- `flate` executable (default name: `flate`)
- `helm` executable (default name: `helm`)

## Install

### From source (editable)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### With uv (recommended)
```bash
uv sync --extra dev
```

### Run without installing
```bash
python main.py --help
```

## Usage

### Dry-run (default)
```bash
auto-krr --krr-json /path/to/krr.json --repo /path/to/git/repo
```

### Write changes
```bash
auto-krr --krr-json /path/to/krr.json --repo /path/to/git/repo --write
```

### Only set missing fields
```bash
auto-krr --krr-json /path/to/krr.json --repo /path/to/git/repo --only-missing --write
```

### Create a Forgejo PR
```bash
auto-krr \
  --krr-json /path/to/krr.json \
  --repo /path/to/git/repo \
  --pr \
  --forgejo-url https://forgejo.example.com \
  --forgejo-owner my-org \
  --forgejo-repo my-repo \
  --forgejo-token $FORGEJO_TOKEN
```

## How it matches HelmReleases
- The HelmRelease must be `kind: HelmRelease` with `apiVersion: helm.toolkit.fluxcd.io/...`.
- The chart reference must resolve to a chart source available to Helm. OCIRepository, HelmRepository, and inline chart references are supported.
- auto-krr enumerates chart defaults/schema and release values, injects unique resource sentinels, and asks flate to render the selected HelmRelease.
- A rendered workload/container is patched only when exactly one Helm value path is identified. Missing, failed, or ambiguous discovery is reported as a skip; chart-shape heuristics are not used.
- KRR scan entries must include Flux labels:
  - `helm.toolkit.fluxcd.io/name`
  - `helm.toolkit.fluxcd.io/namespace`

If a HelmRelease does not set `metadata.namespace`, the tool tries to infer it from the file path (common `apps/<ns>` or `namespaces/<ns>` layouts).

## What gets updated
For a matched HelmRelease/controller/container, the tool updates the resource map discovered by flate, for example:
```
spec.values.controllers.<controller>.containers.<container>.resources
```
It converts CPU to millicores (`m`) and memory to Mi/Gi (rounded up). When multiple KRR entries match the same target, it keeps the **maximum** recommendation per field.

Discovery uses temporary repository copies and caches chart metadata and the flate probe for the duration of one run. The original checkout is never rendered with sentinel values.

## CLI options (high level)
- `--krr-json`: path to KRR report (required)
- `--repo`: path inside repo or clone destination
- `--repo-url`: git URL or `owner/repo` shorthand (auto-clone)
- `--flate-bin`: flate executable (default: `flate`)
- `--helm-bin`: Helm executable used to inspect chart values (default: `helm`)
- `--git-base-url`: base URL for shorthand (defaults to `FORGEJO_URL` or GitHub)
- `--min-severity`: `OK|GOOD|WARNING|CRITICAL` (default: `WARNING`)
- `--only-missing`: only set fields that are currently missing
- `--no-name-fallback`: disable name-only matching when namespace is missing
- `--write`: write changes (default is dry-run)
- `--stage`: `git add` changed files
- `--commit`: `git commit` changed files
- `--commit-message`: custom commit message
- `--pr`: create a Forgejo PR (implies `--write --stage --commit`)
- `--remote`: git remote to push (default: `origin`)
- `--pr-base`: base branch for PR
- `--pr-branch`: branch name to create/push
- `--pr-title`: PR title
- `--forgejo-url`, `--forgejo-owner`, `--forgejo-repo`: Forgejo repo details
- `--forgejo-token`: Forgejo API token
- `--forgejo-api-prefix`: API prefix (default: `/api/v1`)
- `--forgejo-auth-scheme`: auth scheme (default: `token`)
- `--insecure-tls`: disable TLS verification for Forgejo API
- `--allow-dirty`: allow running in a dirty git tree

## Environment variables
Every flag also maps to an environment variable with an optional `APPLY_KRR_` prefix (example: `REPO` or `APPLY_KRR_REPO`).

Common ones:
- `KRR_JSON`
- `REPO`
- `REPO_URL`
- `FLATE_BIN`
- `HELM_BIN`
- `GIT_BASE_URL`
- `CLONE_DEPTH`
- `MIN_SEVERITY`
- `ONLY_MISSING`
- `NO_NAME_FALLBACK`
- `WRITE`
- `STAGE`
- `COMMIT`
- `COMMIT_MESSAGE`
- `PR`
- `REMOTE`
- `PR_BASE`
- `PR_BRANCH`
- `PR_TITLE`
- `FORGEJO_URL`
- `FORGEJO_OWNER`
- `FORGEJO_REPO`
- `FORGEJO_TOKEN` (also read directly)
- `FORGEJO_API_PREFIX`
- `FORGEJO_AUTH_SCHEME`
- `INSECURE_TLS`
- `ALLOW_DIRTY`

## Notes
- If `--pr` is set without `--pr-branch`, the tool creates a timestamped branch (`krr-resources-YYYYmmdd-HHMMSS`).
- Only tracked YAML files (`git ls-files`) are scanned.

## AI Disclosure
This entire Python project was written with AI assistance (ChatGPT).
