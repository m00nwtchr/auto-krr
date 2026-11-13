# Flate Reporting, Ambiguity Suggestions, and CRD Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run one repository-wide in-place flate probe, preserve repository transformations, refuse ambiguous automatic mappings, report actionable suggestions, detect CRD resource schemas, and optionally validate existing KRR comments.

**Architecture:** Discovery will clone/copy the current worktree into independent Git metadata, inject deterministic hash-derived sentinels into each original HelmRelease file, and run one `flate build` against the real manifest root. A batch result will map rendered workloads back to release-scoped Helm value paths while retaining ambiguous/unmapped/failed evidence. A separate CRD schema detector and report layer will expose suggested matches without allowing them to patch files; explicit comments remain authoritative.

**Tech Stack:** Python 3.13+, ruamel.yaml, stdlib `hashlib`/`json`/`subprocess`/`urllib`, external `flate`, `helm`, and optional `kubectl`, pytest.

**Spec:** `docs/superpowers/specs/2026-11-13-flate-reporting-and-crd-discovery-design.md`

## Global Constraints

- Edit HelmRelease files only inside an isolated probe copy with independent Git metadata/index state; never modify the user checkout with sentinels.
- Run exactly one repository-wide `flate build -p <manifest-root> --allow-missing-kinds Secret,ConfigMap --no-progress -o yaml` per discovery batch.
- Preserve real repository Kustomizations, substitutions, source objects, and dependency selection; do not merge probe documents or synthesize source objects in repository-wide mode.
- Sentinel keys include relative manifest path, document index, HelmRelease namespace/name, and candidate path; field values are domain-separated SHA-256-derived valid quantities with deterministic collision avoidance.
- Never patch an ambiguous, unmapped, failed, or CRD-only suggestion automatically.
- Explicit `# krr: controller=... container=...` comments are authoritative during normal application; `--check-comments` is diagnostic only and never edits comments.
- Discovery/report failures are nonfatal to unrelated explicit comments and safe automatic matches.
- Preserve dry-run-by-default, `--write`, `--only-missing`, tracked-manifest selection, legacy summary fields, and Forgejo PR behavior.
- CRD schemas come from the Kubernetes API first, with HTTPS yaml-language-server schema-comment fallback; no credentials are sent and fetched content is in-run only.

## Review Focus

- A dirty source worktree must be probed with current tracked file content but an independent index; test that the source index and files remain unchanged.
- A nonzero flate exit with parseable stdout must still map successful sentinels and fail only unresolved releases; test partial output handling.
- Same controller/container names across namespaces or releases must remain release-scoped; test collision refusal rather than name guessing.
- Hash-derived sentinels must be stable, distinct, valid quantities, and avoid existing resource scalar collisions; test repeatability and forced collision resolution.
- An explicit comment conflicting with automatic discovery must still apply normally but become a suggested correction in `--check-comments`; test both modes.

---

### Task 1: Add deterministic release-scoped sentinel allocation

**Files:**
- Create: `src/auto_krr/sentinels.py`
- Modify: `src/auto_krr/flate_discovery.py` only for imports/types after the allocator exists
- Test: `tests/test_sentinels.py`

**Interfaces:**
- `ProbeCandidate` frozen dataclass: `manifest_path: Path`, `doc_index: int`, `namespace: str`, `release_name: str`, `value_path: Tuple[object, ...]`.
- `SentinelValues` frozen dataclass: `requests_cpu: str`, `requests_memory: str`, `limits_cpu: str`, `limits_memory: str`.
- `allocate_sentinels(candidates: Sequence[ProbeCandidate], occupied_values: Set[str]) -> Dict[ProbeCandidate, SentinelValues]`.
- `sentinel_values(values: SentinelValues) -> Set[str]` for exact rendered-output matching.

- [ ] **Step 1: Write failing tests**
  - Assert the same candidate list produces byte-for-byte identical values across calls and candidate order changes do not change assignments.
  - Assert two releases with identical value paths receive different values because manifest/release identity is included.
  - Assert all four values use valid CPU/memory quantity suffixes and are within the bounded numeric range.
  - Monkeypatch/hash-fixture a collision and assert deterministic probing produces distinct values.
  - Assert generated values avoid `occupied_values` from existing resource maps.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_sentinels.py -q`

  Expected: FAIL because `src/auto_krr/sentinels.py` does not exist.

- [ ] **Step 3: Implement the allocator**
  - Serialize the canonical candidate key with stable JSON separators and domain-separate each resource field before SHA-256 hashing.
  - Map digests to a bounded numeric quantity range, process canonical keys sorted, reserve occupied values, and deterministically advance on collisions.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_sentinels.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/sentinels.py tests/test_sentinels.py
  git commit -m "feat: allocate deterministic flate sentinels"
  ```

### Task 2: Replace per-release probes with one in-place repository batch

**Files:**
- Modify: `src/auto_krr/flate_discovery.py`
- Modify: `src/auto_krr/helm_values.py` only where candidate identity metadata is required
- Modify: `src/auto_krr/resources_matchers.py`
- Test: `tests/test_flate_discovery.py`
- Test: `tests/test_resources_matchers.py`

**Interfaces:**
- `ReleaseIdentity` frozen dataclass: `namespace: str`, `name: str`, `manifest_path: Path`, `doc_index: int`.
- `DiscoveryResult.path_for(identity: ReleaseIdentity, controller: str, container: str) -> Optional[List[object]]` plus `ambiguous`, `unmapped`, `failed`, and `notes`.
- `DiscoveryBatch.results: Dict[ReleaseIdentity, DiscoveryResult]`, `render_invocations: int`, and bounded diagnostics.
- `FlateDiscovery.discover_many(hr_locs: Sequence[HrDocLoc]) -> DiscoveryBatch`; retain `discover()` as a one-location compatibility wrapper.
- `HelmReleaseMatcher` accepts one `DiscoveryBatch` and never invokes flate while resolving an individual target.

- [ ] **Step 1: Write failing tests**
  - Build two HelmRelease fixtures in different directories, inject candidates into their original paths in a fake probe copy, and assert the fake flate sees one invocation with no merged synthetic manifest.
  - Assert the flate command uses repository manifest root, no `hr` selector, and the required flags.
  - Assert the source repository file bytes, Git status, and Git index remain unchanged after discovery.
  - Assert a fake flate emits one successful workload and one unrelated failure with parseable stdout; the successful release maps and the failed release is recorded separately.
  - Assert same workload/container names in different namespaces map to their owning release; cross-release sentinel consumption becomes ambiguous.
  - Assert one sentinel appearing in multiple rendered containers yields one path per container and patching deduplicates the resources map.
  - Assert no candidate sentinel match creates an unmapped suggestion rather than a guessed path.
  - Assert `HelmReleaseMatcher` consumes the precomputed batch and repeated target resolution performs no subprocess call.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_flate_discovery.py tests/test_resources_matchers.py -q`

  Expected: FAIL because discovery is still per-release and path lookup is not release-scoped.

- [ ] **Step 3: Implement isolated in-place batch probing**
  - Create an independent temporary Git clone/index, overlay current worktree file contents, and preserve the tracked-manifest selection contract.
  - Load each selected YAML file once, inject sentinels at its original document/path, and write it back only in the temporary copy.
  - Run one `flate build -p <manifest-root> --allow-missing-kinds Secret,ConfigMap --no-progress -o yaml`, parse stdout even on nonzero exit, and bound stderr diagnostics.
  - Extend rendered workload extraction with namespace and sentinel ownership; produce release-scoped auto/ambiguous/unmapped/failed results.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_flate_discovery.py tests/test_resources_matchers.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/flate_discovery.py src/auto_krr/helm_values.py src/auto_krr/resources_matchers.py tests/test_flate_discovery.py tests/test_resources_matchers.py
  git commit -m "feat: render HelmRelease probes in one repository pass"
  ```

### Task 3: Detect CRD resource definitions from API and schema comments

**Files:**
- Create: `src/auto_krr/crd_schema.py`
- Modify: `src/auto_krr/types.py` for shared CRD finding dataclasses if needed
- Test: `tests/test_crd_schema.py`

**Interfaces:**
- `CrdResourceDefinition` frozen dataclass: CRD group/kind/version, schema path, source (`kube-api` or `schema-comment`), and confidence.
- `CrdSchemaReport`: `definitions`, `notes`, `debug`, and `failed` lists.
- `CrdSchemaDetector(repo_root: Path, kubectl_bin: str = "kubectl", timeout: float = 10.0)`.
- `CrdSchemaDetector.detect(yaml_docs: Sequence[YamlDocLoc]) -> CrdSchemaReport`.

- [ ] **Step 1: Write failing tests**
  - Fake `kubectl get crd -o json` output and assert exact `apiVersion` matching finds nested `resources` schema paths.
  - Assert recursive schema `$ref` cycles terminate and do not duplicate paths.
  - Assert API failure/malformed/incomplete CRD data triggers HTTPS yaml-language-server schema-comment fallback.
  - Assert non-HTTPS schema URLs are rejected without network access and fetched schemas are cached per run.
  - Assert custom resources without a workload/container mapping produce schema-only suggested evidence and never an automatic mapping.
  - Assert CRD debug records identify source, CRD identity, version, and resource paths.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_crd_schema.py -q`

  Expected: FAIL because the CRD detector does not exist.

- [ ] **Step 3: Implement API-first schema detection**
  - Invoke `kubectl get crd -o json` once with bounded timeout, index served/versioned OpenAPI schemas, and fall back per CRD when unusable.
  - Parse yaml-language-server `$schema` comments with bounded HTTPS retrieval and in-run caching.
  - Walk `properties` and `$ref` safely, associate custom-resource documents by group/kind/version, and emit evidence only; do not map to containers.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_crd_schema.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/crd_schema.py src/auto_krr/types.py tests/test_crd_schema.py
  git commit -m "feat: discover resource fields in CRD schemas"
  ```

### Task 4: Add structured unambiguous, suggested, and failed reporting

**Files:**
- Create: `src/auto_krr/discovery_reports.py`
- Modify: `src/auto_krr/cli.py`
- Modify: `src/auto_krr/resources_matchers.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_resources_matchers.py`

**Interfaces:**
- `MatchOption` with `path` and exact location-based comment template.
- `SuggestedFinding`, `UnambiguousFinding`, and `FailedFinding` dataclasses with target identity, reason, provenance, and bounded details.
- `DiscoveryReport` with `unambiguous`, `suggested`, `failed`, `debug`, and `legacy_summary()`.
- `build_discovery_report(batch: DiscoveryBatch, crd_report: CrdSchemaReport, rec_map: Dict[TargetKey, RecommendedResources]) -> DiscoveryReport`.
- `_format_cli_summary` and `_format_pr_body` render the three new sections while retaining updated/skipped/unmatched compatibility keys.

- [ ] **Step 1: Write failing tests**
  - Assert a two-option ambiguity is suggested with both full paths and `# krr: controller=... container=...`, and produces no changed file.
  - Assert unambiguous automatic and explicit-comment matches appear in the unambiguous section with provenance.
  - Assert CRD-only evidence appears under suggested and never under unambiguous/updated.
  - Assert render/chart/schema failures appear under failed without hiding unrelated updates.
  - Assert CLI and PR body contain `Unambiguous matches`, `Suggested matches`, and `Failed matches`, including options/comment templates.
  - Assert legacy summary counts and existing dry-run/write behavior remain unchanged.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_cli.py tests/test_resources_matchers.py -q`

  Expected: FAIL because no structured report exists and PR output has only legacy sections.

- [ ] **Step 3: Implement report aggregation and rendering**
  - Keep suggestions/failures separate from patchable resources; make explicit comments authoritative for normal application.
  - Add bounded CLI/PR formatting and pass report data through `_apply_krr_to_repo` without changing its public tuple shape.
  - Add `--kubectl-bin` / `KUBECTL_BIN` and `--debug-discovery` / `DEBUG_DISCOVERY` configuration.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_cli.py tests/test_resources_matchers.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/discovery_reports.py src/auto_krr/cli.py src/auto_krr/resources_matchers.py tests/test_cli.py tests/test_resources_matchers.py
  git commit -m "feat: report safe and suggested resource matches"
  ```

### Task 5: Add optional wrong-comment validation

**Files:**
- Create: `src/auto_krr/comment_validation.py`
- Modify: `src/auto_krr/cli.py`
- Modify: `src/auto_krr/discovery_reports.py`
- Test: `tests/test_comment_validation.py`
- Modify: `tests/test_cli_helpers.py`

**Interfaces:**
- `CommentValidationFinding` with location, current path, expected path/options, classification, and suggestion.
- `validate_comments(comment_index, batch, *, include_non_krr_targets: bool) -> List[CommentValidationFinding]`.

- [ ] **Step 1: Write failing tests**
  - Assert a comment at the sole auto-detected path is reported as unnecessary/suggested without being removed.
  - Assert a comment at a different path is reported as seemingly wrong with the discovered path, while normal explicit application still uses the comment.
  - Assert ambiguous/failed discovery produces an unvalidated/failed finding.
  - Assert comments without current KRR entries and comments on custom resources are inspected.
  - Assert `--check-comments` / `CHECK_COMMENTS=1` parsing and default-off behavior.

- [ ] **Step 2: Run focused tests to verify failure**

  Run: `pytest tests/test_comment_validation.py tests/test_cli_helpers.py -q`

  Expected: FAIL because comment validation and its CLI flag do not exist.

- [ ] **Step 3: Implement diagnostic validation**
  - Compare explicit comment locations to fresh release-scoped auto results.
  - Classify unnecessary/wrong as suggested and ambiguous/failed/unmapped as failed; never mutate comments or override normal explicit matching.
  - Wire the flag through CLI, report, dry-run, write, and PR paths.

- [ ] **Step 4: Run focused tests to verify success**

  Run: `pytest tests/test_comment_validation.py tests/test_cli_helpers.py -q`

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/auto_krr/comment_validation.py src/auto_krr/cli.py src/auto_krr/discovery_reports.py tests/test_comment_validation.py tests/test_cli_helpers.py
  git commit -m "feat: validate explicit KRR comments"
  ```

### Task 6: Update documentation and validate the complete behavior

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-11-13-flate-reporting-and-crd-discovery-design.md` only for measured corrections
- Test: existing full test suite plus a new focused integration fixture if needed

- [ ] **Step 1: Add failing documentation/integration coverage**
  - Add CLI help/env tests for `kubectl`, debug discovery, and comment checking.
  - Add an end-to-end fixture proving ambiguous automatic detection is report-only while an explicit comment patches the selected location.

- [ ] **Step 2: Run the focused integration tests to verify failure**

  Run: `pytest tests/test_cli.py tests/test_comment_validation.py tests/test_flate_discovery.py -q`

  Expected: FAIL until final wiring and documentation-facing flags are complete.

- [ ] **Step 3: Update README**
  - Document one repository-wide flate pass, isolated sentinel probing, report categories, ambiguity comment suggestions, CRD API/schema fallback, and `--check-comments`.
  - Document `KUBECTL_BIN`, `DEBUG_DISCOVERY`, and `CHECK_COMMENTS`.

- [ ] **Step 4: Run complete verification**

  Run: `pytest -q`

  Expected: all feature tests pass; record the known environment-sensitive Git failure only if it remains unchanged.

  Run against `homelab-cluster` at commit `0ab865d` with flate `v0.7.3`:

  ```bash
  auto-krr --krr-json /tmp/kavita-krr.json --repo /path/to/homelab-cluster --flate-bin /tmp/flate-bin/flate --helm-bin helm
  ```

  Confirm one flate invocation for discovery, Kavita’s mapped path, categorized reports, no sentinel values in the checkout, and no checkout changes in dry-run mode.

- [ ] **Step 5: Inspect final diff and commit documentation**

  ```bash
  git diff --check
  git status --short
  git diff --stat HEAD~6..HEAD
  git add README.md docs/superpowers/specs/2026-11-13-flate-reporting-and-crd-discovery-design.md
  git commit -m "docs: describe discovery reports and comment validation"
  ```
