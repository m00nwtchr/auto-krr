# Flate-Based Helm Resource Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace chart-shape HelmRelease resource heuristics with generic chart-value probing rendered by flate, then patch the discovered Helm value path for each KRR workload/container target.

**Architecture:** A chart-values module resolves a HelmRelease chart and enumerates concrete resource candidate paths from chart defaults/schema plus release values. A flate-discovery module injects unique sentinels into all candidates in a temporary repository copy, renders one selected HelmRelease with flate, and maps rendered workload/container names back to paths. `HelmReleaseMatcher` consumes the cached mapping and the patching layer creates and updates the discovered path.

**Tech Stack:** Python 3.13+, ruamel.yaml, stdlib `json`/`subprocess`/`tempfile`, external `flate` and `helm` executables, pytest.

**Spec:** `docs/superpowers/specs/2026-11-13-flate-resource-discovery-design.md`

## Global Constraints

- Use flate as the rendering authority; do not use `helm template` for workload rendering.
- Do not retain or reintroduce app-template or `spec.values.resources` fallback heuristics.
- Probe in temporary repository copies and never write sentinels to the user's checkout.
- Render all candidates for one HelmRelease in one flate invocation and cache the result for the run.
- Zero or multiple candidate matches are skips, never guessed mappings.
- Keep existing dry-run, write, only-missing, comment matcher, and PR behavior unchanged.
- Runtime dependencies remain limited to the existing Python dependencies; flate and helm are configurable external executables.

## Review Focus

- Empty `values.yaml` with schema-driven dynamic maps (app-template controllers/containers) must still yield concrete paths; test in Task 1.
- OCIRepository, HelmRepository, and inline chart references must resolve without assuming one chart shape; test in Task 1.
- A rendered container affected by multiple probes must be reported ambiguous and not patched; test in Task 2.
- Missing flate/helm binaries, nonzero renders, and malformed output must produce bounded skip notes; test in Task 2.
- A discovered path absent from the original release values must be created while preserving `--only-missing`; test in Task 3.

---

### Task 1: Resolve chart values and enumerate resource candidates

**Files:**
- Create: `src/auto_krr/helm_values.py`
- Create: `tests/test_helm_values.py`

**Interfaces:**
- Produces `ChartRef`, `ChartValues`, and `ChartCandidate` dataclasses, plus `_resolve_chart_ref(repo_root: Path, hr_doc: CommentedMap) -> Optional[ChartRef]` and `_enumerate_resource_candidates(chart_values: ChartValues, release_values: CommentedMap) -> List[ChartCandidate]`.
- `ChartCandidate.path` is a concrete path below `spec.values`; it includes the terminal `resources` key and supports string and integer path components.
- `ChartValues` contains parsed `values.yaml` and optional `values.schema.json` data; `_load_chart_values(chart_ref: ChartRef, helm_bin: str, cache_dir: Path) -> ChartValues` loads through a configurable Helm executable and a per-run cache.

- [ ] **Step 1: Write failing tests**
  - Assert an OCIRepository-backed app-template release resolves its URL/version from repository objects.
  - Assert a HelmRepository-backed release resolves chart name/version/source URL.
  - Assert an inline `spec.chart.spec` release resolves its chart and source reference.
  - Assert schema `additionalProperties` expands `controllers.main.containers.app.resources` even when defaults are empty.
  - Assert existing release values contribute a candidate when the schema is incomplete.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_helm_values.py -q`

  Expected: FAIL because the chart reference and candidate enumeration interfaces do not exist.

- [ ] **Step 3: Implement chart resolution and candidate enumeration**
  - Parse Flux chart references by matching referenced repository objects by kind/name/namespace.
  - Pull or inspect charts through the configured Helm executable, cache by immutable chart identity, and parse `values.yaml` plus `values.schema.json` with existing YAML utilities/stdlib JSON.
  - Walk schema properties and concrete release/default maps, expanding dynamic map keys from `spec.values`; record only resource-shaped mappings.
  - Return deterministic, de-duplicated paths so sentinel IDs remain stable in tests and logs.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_helm_values.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/helm_values.py tests/test_helm_values.py
  git commit -m "feat: enumerate Helm resource value candidates"
  ```

### Task 2: Probe candidates with flate and map rendered containers

**Files:**
- Create: `src/auto_krr/flate_discovery.py`
- Create: `tests/test_flate_discovery.py`

**Interfaces:**
- Produces `DiscoveryResult` with `path_for(controller: str, container: str) -> Optional[List[object]]`, ambiguity tracking, and human-readable notes.
- Produces `FlateDiscovery(repo_root: Path, flate_bin: str = "flate", helm_bin: str = "helm")` with `discover(hr_loc: HrDocLoc) -> DiscoveryResult`.
- The discovery result maps rendered workload metadata names and regular/init container names to one concrete `spec.values` resource path; ambiguous keys are deliberately absent.

- [ ] **Step 1: Write failing tests**
  - Use a fake flate command/output to prove distinct sentinels map `Deployment/demo` container `app` to the expected values path.
  - Assert `CronJob`/pod-template and init-container extraction works.
  - Assert two candidates affecting one rendered container produce an ambiguity note and no path.
  - Assert missing executables, nonzero subprocess exits, malformed YAML, and no sentinel match return skip notes without raising through the matcher boundary.
  - Assert one discovery call renders all candidates once and subsequent calls reuse the per-release cache.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_flate_discovery.py -q`

  Expected: FAIL because flate probing and rendered-container extraction do not exist.

- [ ] **Step 3: Implement sentinel probing and rendered mapping**
  - Clone the repository/target YAML into a temporary directory, inject unique valid CPU/memory quantities at every candidate path, and invoke `flate build hr <name> -n <namespace> -p kubernetes --allow-missing-kinds Secret,ConfigMap --no-progress -o yaml`.
  - Parse workload pod specs from Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob, and Pod-shaped output; inspect containers and initContainers.
  - Match exact sentinel values, preserve candidate paths, reject ambiguity, capture bounded stderr/exit diagnostics, and cache results per HelmRelease location/value identity.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_flate_discovery.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/flate_discovery.py tests/test_flate_discovery.py
  git commit -m "feat: discover Helm resources through flate"
  ```

### Task 3: Replace heuristic patching with generic discovered paths

**Files:**
- Modify: `src/auto_krr/patching.py`
- Modify: `tests/test_helm_values_resources.py`
- Modify: `tests/test_patching.py` if generic path helper coverage belongs there

**Interfaces:**
- Produces `_resolve_resources_path(doc: CommentedMap, path: List[object], create_missing: bool) -> Tuple[Optional[CommentedMap], bool, List[str]]`.
- `_apply_to_hr_doc` and resource updates consume a discovered concrete path rather than `HELM_VALUES_CONFIGS` or controller/container fallback rules.

- [ ] **Step 1: Write failing tests**
  - Assert a nested discovered path is resolved without chart-specific names.
  - Assert missing intermediate maps and the terminal resources map are created when allowed.
  - Assert non-mapping path components produce a skip rather than replacing unrelated values.
  - Preserve existing quantity conversion and `only_missing` behavior on a discovered path.
  - Replace tests that assert app-template or `spec.values.resources` heuristic selection with generic path tests.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_helm_values_resources.py tests/test_patching.py -q`

  Expected: FAIL because patching still depends on the removed chart configuration.

- [ ] **Step 3: Implement generic path resolution and remove heuristic configuration**
  - Resolve/create only the exact path returned by discovery, preserving ruamel mappings and insertion behavior.
  - Delete `HELM_VALUES_CONFIGS`, app-template fallback selection, and the single-workload `spec.values.resources` branch.
  - Keep `_apply_to_resources_map`, quantity formatting, notes, and `only_missing` semantics intact.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_helm_values_resources.py tests/test_patching.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/patching.py tests/test_helm_values_resources.py tests/test_patching.py
  git commit -m "refactor: patch discovered Helm resource paths"
  ```

### Task 4: Integrate discovery into the matcher and CLI

**Files:**
- Modify: `src/auto_krr/resources_matchers.py`
- Modify: `src/auto_krr/cli.py`
- Modify: `tests/test_resources_matchers.py`
- Modify: `tests/test_cli.py`
- Modify: `README.md`

**Interfaces:**
- `HelmReleaseMatcher` receives the repository root and a `FlateDiscovery` instance/configuration, caches discovery per HelmRelease, and resolves each target through `path_for`.
- `_apply_krr_to_repo(..., flate_bin: str = "flate", helm_bin: str = "helm")` constructs the configured discovery service.
- CLI adds `--flate-bin` / `FLATE_BIN` and `--helm-bin` / `HELM_BIN`, passing them into `_apply_krr_to_repo` without changing existing defaults or write/PR flags.

- [ ] **Step 1: Write failing integration tests**
  - Inject a fake discovery result into `HelmReleaseMatcher` and assert the target resolves to the generic nested path.
  - Assert an unmatched/ambiguous discovery result appears as a skip and does not update the release.
  - Assert `_apply_krr_to_repo` updates a non-app-template-shaped release through a fake flate mapping and no longer updates the old `spec.values.resources` heuristic.
  - Assert CLI/environment resolution supplies configurable flate and Helm executable names.
  - Keep comment-based resource matching tests green.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_resources_matchers.py tests/test_cli.py -q`

  Expected: FAIL because the matcher still selects chart-shape paths and the CLI has no discovery configuration.

- [ ] **Step 3: Implement integration**
  - Construct one discovery service in `_apply_krr_to_repo` and pass it to `HelmReleaseMatcher`.
  - In `resolve_resources`, look up the target's workload/container mapping, resolve/create its path, and return discovery notes on failure.
  - Remove imports and branches tied to chart-name configurations; leave the comment matcher untouched.
  - Add the two binary settings to argument parsing/environment resolution and document the external tools and dry-run example in README.

- [ ] **Step 4: Run focused and full tests**

  Run: `pytest tests/test_resources_matchers.py tests/test_cli.py tests/test_helm_values_resources.py tests/test_patching.py -q`

  Expected: PASS with no heuristic tests remaining.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/resources_matchers.py src/auto_krr/cli.py tests/test_resources_matchers.py tests/test_cli.py README.md
  git commit -m "feat: use flate discovery for HelmRelease matching"
  ```

### Task 5: Validate against homelab-cluster and finish verification

**Files:**
- Modify: `docs/superpowers/specs/2026-11-13-flate-resource-discovery-design.md` only if validation reveals a behavior correction
- Modify: `README.md` only if the documented command needs an exact correction

**Interfaces:**
- No new production interface; this task verifies the integrated behavior against the supplied repository and records measured limitations.

- [ ] **Step 1: Run the complete Python test suite**

  Run: `pytest -q`

  Expected: PASS with zero failures.

- [ ] **Step 2: Run the real flate validation**

  From the homelab checkout at commit `0ab865d`, use flate `v0.7.3` and run a dry-run against a representative KRR input that targets `media/kavita`/`Deployment kavita`/container `app`. Confirm the output identifies the discovered Helm values path and applies no repository changes without `--write`.

- [ ] **Step 3: Run broader homelab discovery validation**

  Exercise the available HelmRelease set, record successful mappings and expected skips for the five known unrelated render failures (`wks`, `wordpress`, `gotosocial`, `continuwuity`, `tor-operator`), and confirm no sentinel values remain in the checkout.

- [ ] **Step 4: Inspect final diff and verify hygiene**

  Run: `git diff --check && git status --short && git diff --stat HEAD~4..HEAD`

  Expected: no whitespace errors, only intended source/tests/docs changes, and no generated probe files.

- [ ] **Step 5: Commit any documentation-only correction**

  ```bash
  git add docs/superpowers/specs/2026-11-13-flate-resource-discovery-design.md README.md
  git commit -m "docs: record flate integration validation"
  ```
