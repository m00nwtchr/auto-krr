# Flate Reporting, Ambiguity Suggestions, and CRD Resource Discovery

**Date:** 2026-11-13  
**Status:** Approved and implemented

## Intent

Extend the generic Helm value discovery introduced by the flate integration so
it remains useful when automatic evidence is incomplete without ever silently
choosing an ambiguous path. The CLI and Forgejo PR body will distinguish paths
that are safe to apply, paths that are useful suggestions for an explicit KRR
comment, and paths that failed discovery.

The probe renderer will process all repository HelmReleases in one flate
invocation. Custom-resource schemas will be inspected separately: their
`resources` fields are valuable evidence, but their relationship to a runtime
container is not inferable from the schema alone and must never be guessed.

## Goals

- Edit all probe HelmReleases in place inside one isolated Git worktree copy
  and render the repository with one flate build invocation.
- Preserve exact, unambiguous automatic mappings and apply only those mappings.
- Refuse ambiguous automatic mappings and report every candidate path.
- Suggest an explicit `krr` comment for each candidate choice without writing
  comments automatically.
- Detect `resources` definitions in CRD OpenAPI schemas using the Kubernetes API
  first and yaml-language-server schema comments as a fallback.
- Report unambiguous matches, suggested matches, and failed matches separately
  in CLI output and PR bodies.
- Add an opt-in mode that validates existing comments against fresh discovery,
  identifies comments that are unnecessary, and flags comments whose target
  disagrees with the discovered evidence.
- Keep dry-run-by-default, `--write`, `--only-missing`, explicit comment
  matching, and Forgejo PR behavior intact.

## Non-goals and anti-goals

- Never choose one of multiple candidate Helm paths automatically.
- Never map a CRD schema field to a workload/container automatically.
- Never write, remove, or rewrite `krr` comments automatically.
- Do not use app-template, chart-name, `spec.values.resources`, or other
  chart-shape heuristics as a fallback.
- Do not make the Kubernetes API a required runtime dependency; unavailable
  credentials, `kubectl`, or API access are bounded discovery failures/fallbacks
  rather than reasons to abort the whole run.

## Existing behavior and constraints

The current `FlateDiscovery` copies the repository, injects resource sentinels
into one HelmRelease, invokes flate, and returns a mapping keyed by rendered
workload/container. `HelmReleaseMatcher` consumes that mapping and the comment
matcher handles explicit `# krr: controller=... container=...` comments. CLI
summary construction already separates updated, skipped, and unmatched lists,
and `_format_pr_body` mirrors those lists for Forgejo.

The new global discovery result must include the HelmRelease identity and
namespace in its key. A controller/container name is not globally unique when
several namespaces are rendered in one pass.

## Approaches considered

### A. In-place isolated repository probe (chosen)

Build one temporary Git-backed copy of the repository, inject sentinels into
the original HelmRelease files/documents in that copy, and invoke
`flate build` once against the repository manifest root. Parse every rendered
workload and retain per-HelmRelease results keyed by namespace/name.

This is the chosen approach because it preserves Kustomizations, substitutions,
source objects, dependency selection, and other repository transformations.
The probe copy has independent Git metadata/index state; it must not reuse a
worktree `.git` file that points at the user's index. The original checkout is
never edited.

### B. One invocation per chart/source group

Group compatible releases and render each group once. This reduces process
startup and dependency duplication but is not a single pass, complicates
cross-group reporting, and still leaves one failure boundary per group.

### C. Static chart/CRD inference without merged rendering

Use values/schema paths and comments without rendering. This is cheaper but
cannot establish which workload/container consumes a path and would encourage
the guessing behavior this feature is intended to prevent.

## Design

### 1. Discovery inputs and one-pass probe

`FlateDiscovery.discover_many(hr_locs)` will replace repeated per-release
rendering for a run. The caller supplies all indexed HelmRelease locations;
the default selection is every HelmRelease with resolvable chart candidate
paths, so a KRR target does not need to be known before discovery. This same
full selection is used with `--only-missing`; that flag controls patch fields,
not discovery coverage. `--check-comments` validates every existing KRR
comment in the repository, including comments on custom resources.

For each release, the service will:

1. Resolve chart values/schema and enumerate concrete resource candidate paths.
2. Allocate globally unique sentinel values for that release/path.
3. Copy the repository once into a temporary Git-backed probe tree with an
   independent index/worktree metadata set.
4. Rewrite each selected HelmRelease at its original repository path in the
   probe tree, injecting sentinels into its concrete `spec.values` paths. Do
   not merge documents, relocate manifests, or replace Kustomization inputs.
5. Invoke `flate build` once against the repository's manifest root (the
   existing `kubernetes/` root when present, otherwise the repository root),
   without a single-HelmRelease selector. Do not use synthetic source supply
   objects when the repository contains the real source/dependency graph.
6. Parse all rendered output and associate each sentinel with the HelmRelease
   candidate that owns it. A sentinel observed in several containers is
   reported per container; a rendered identity consuming sentinels owned by
   multiple releases is ambiguous and is never patched.

Sentinels are deterministic and release-global. The canonical sentinel key is
the repository-relative manifest path, document index, HelmRelease namespace
and name, and candidate path, serialized with stable separators. Each resource
field derives a domain-separated SHA-256 digest from that key and the field
name. The digest is mapped into a bounded, valid numeric quantity range and
given the appropriate `m` or `Mi` suffix. Candidate keys are processed in
sorted order; generated values are checked against every other sentinel and
against scalar resource values already present in the probe inputs. Any
collision advances deterministically through the digest-derived range until a
free value is found. Thus values are stable across runs for unchanged inputs,
distinct across all releases in one pass, and never depend on discovery order.

A nonzero exit does not discard parseable stdout: rendered objects are still
mapped, while releases with no usable output receive failed-match entries with
bounded stderr. If no usable output can be parsed, every pending release is
failed rather than guessed.

The concrete invocation is `flate build -p <manifest-root>
--allow-missing-kinds Secret,ConfigMap --no-progress -o yaml`. A chart source
or dependency absent from the repository is a failed discovery, not a reason
to synthesize an object that could bypass repository transformations. A
release that fails candidate loading or probe injection is removed from the
injected set and recorded as failed; the remaining releases still participate
in the one repository-wide build.

The probe copy starts from current worktree file contents, including edits to
tracked files when dirty execution is explicitly allowed, but uses independent
Git metadata and index state. Untracked manifests remain outside the existing
tracked-manifest selection contract and are not made discoverable implicitly.

Rendered workload identity is `(namespace, metadata.name, container name)`.
If a workload lacks a namespace or identity collision remains, the affected
mapping is suggested/failed instead of being assigned to a release by name.
The HelmRelease namespace/name scopes the mapping before workload identity is
used for KRR matching. A KRR target with multiple possible HelmRelease
locations remains unresolved. One candidate path may intentionally configure
several rendered workload/container identities; that is valid evidence and is
reported once per identity, while the patcher deduplicates writes to the same
resources map.

The result retains provenance for every mapping:

- `auto`: exactly one sentinel path observed for one rendered container.
- `ambiguous`: two or more sentinel paths observed for the same identity.
- `unmapped`: candidates existed but no rendered container consumed them.
- `failed`: chart loading, probe construction, flate execution, or output
  parsing prevented a reliable result.

### 2. Ambiguous and suggested matches

An ambiguous automatic result is never passed to `_resolve_resources_path`.
An explicit comment remains an allowed resolution: the comment matcher owns a
specific YAML `resources` location, and that location is applied as an explicit
user mapping even when automatic discovery reports ambiguity.

Every ambiguity is rendered in the CLI and PR body as a suggested match. The
report includes all concrete options and a comment template:

```text
Suggested match: HelmRelease media/demo controller=demo container=app
Reason: automatic mapping is ambiguous; no change was applied
Options:
  1. spec.values.controllers.demo.containers.app.resources
     add immediately above that resources map:
     # krr: controller=demo container=app
  2. spec.values.workloads.demo.containers.app.resources
     add immediately above that resources map:
     # krr: controller=demo container=app
```

The comment is intentionally location-based: placing the same explicit
`controller`/`container` comment on the selected `resources` map resolves the
path without adding a second path syntax to the existing comment format. No
suggestion is written to disk.

An explicit comment is authoritative during normal application even when
automatic discovery finds a different sole path. In `--check-comments` mode,
that disagreement is reported as a suggested correction; neither the comment
nor the automatic path is silently rewritten. If the suggested path is absent,
the report shows the `resources:` block and comment that the user can add at
that location.

Suggested entries also include CRD schema resource definitions and other
best-effort evidence that cannot establish a unique runtime mapping. They are
informational only and cannot contribute to `changed_targets`.

### 3. CRD schema resource detection

The CRD detector runs once per repository/run and records resource definitions
separately from HelmRelease container mappings.

1. Invoke configurable `kubectl` (`KUBECTL_BIN`, default `kubectl`) with a
   bounded request to retrieve CRDs as JSON from the current Kubernetes API.
2. Index each CRD version's `openAPIV3Schema` and recursively find object
   properties named `resources`, retaining the CRD identity, version, and
   schema path. Recursive `$ref` traversal is cycle-safe and bounded.
3. Associate repository custom-resource documents with an indexed CRD by API
   group/kind and exact `apiVersion`. If no exact version is available, served
   versions may be retained only as lower-confidence suggestions. A CRD schema
   may produce one or more suggested `resources` locations, but no
   workload/container mapping.
4. If the API query is unavailable or incomplete, scan YAML comments for
   `yaml-language-server: $schema=<URL>` and retrieve/cache the referenced
   schema with a bounded timeout. Parse the same resource-property paths.
5. Emit debug diagnostics identifying the source (`kube-api`, `schema-comment`,
   or unavailable), CRD identity, and discovered paths. The normal report
   includes these as suggested matches; the patcher never consumes them.

The detector must not treat arbitrary fields named `resources` in ordinary
Helm values as CRD evidence. Only CRD schema/property context or a matched
custom-resource document qualifies.

An API result is incomplete when the command fails, returns malformed JSON,
omits the requested CRD identity/version, or contains no usable OpenAPI schema.
Fallback is per CRD where possible, so one missing schema does not discard
other API results. Schema-comment retrieval accepts HTTPS URLs only, uses a
bounded timeout, and caches responses for the current run; it does not send
credentials or persist fetched content in the repository. A schema path with
no matching custom-resource document is still a schema-only suggested finding;
it receives a concrete KRR comment template only when a KRR target provides
the controller/container context.

### 4. Reports and PR body

The internal summary gains separate lists:

- `unambiguous`: auto-resolved or explicitly comment-resolved targets that may
  be updated, including provenance and changed fields.
- `suggested`: ambiguous Helm paths, unmapped candidate paths, CRD schema
  definitions, and comment suggestions. These never count as updates.
- `failed`: target-specific discovery/render/schema failures.

The new discovery report covers all indexed HelmReleases with candidate
evidence and all associated CRD schema evidence. Legacy `updated`, `skipped`,
and `unmatched` counts remain scoped to KRR targets so existing automation does
not change meaning.

The compact CLI prints all three sections with bounded list lengths. Pretty
output includes the same options and comment templates. The PR body uses
collapsible `Unambiguous matches`, `Suggested matches`, and `Failed matches`
sections before the existing YAML warnings/errors sections. Existing updated,
skipped, and unmatched summary compatibility fields remain populated for
callers/tests that use them.

### 5. Optional wrong-comment validation

Add `--check-comments` / `CHECK_COMMENTS=1`, disabled by default. When enabled,
the run performs normal explicit-comment matching and also compares each
comment location with fresh automatic discovery. It examines every existing
KRR comment, including comments whose target is absent from the current KRR
input and comments on custom resources:

- If the comment's location is the sole automatic path, report it as an
  unnecessary comment and suggest removing it; do not remove it.
- If automatic discovery finds a different sole path, report the comment as
  seemingly wrong and show the discovered path; do not move or rewrite it.
- If automatic discovery is ambiguous or failed, report that the comment could
  not be validated and leave the explicit comment behavior unchanged.

The mode is diagnostic: it must not turn a valid explicit comment into an
automatic patch, and it must not cause a dry-run/write/PR operation to modify
comments.

Unnecessary and apparently wrong comments are `suggested` findings. A comment
that cannot be validated because automatic discovery is ambiguous or failed is
a `failed` finding. These diagnostics are nonfatal: safe automatic matches and
explicit comment mappings may still be written or included in a PR.

Unnecessary and apparently wrong comments are `suggested` findings. A comment
that cannot be validated because automatic discovery is ambiguous or failed is
a `failed` finding. These diagnostics are nonfatal: safe automatic matches and
explicit comment mappings may still be written or included in a PR.

### 6. Interfaces and compatibility

- `FlateDiscovery.discover_many(...) -> DiscoveryBatch` owns one probe/render
  invocation and per-release results.
- `DiscoveryResult.path_for(controller, container)` becomes release-scoped
  through the batch result; callers must provide the HelmRelease identity.
- `HelmReleaseMatcher` consumes the batch and exposes suggested/failed notes
  without treating them as resources.
- `_apply_krr_to_repo` accepts the discovery/report configuration and returns
  the expanded summary while preserving its existing tuple shape.
- CLI adds `--kubectl-bin` / `KUBECTL_BIN`, `--check-comments` /
  `CHECK_COMMENTS`, and a discovery debug switch (`--debug-discovery` /
  `DEBUG_DISCOVERY`). Existing executable flags remain unchanged.

## Safety and failure policy

- No ambiguous automatic path is patched.
- No CRD schema path is patched without an explicit comment location.
- Missing tools, API access, chart sources, malformed output, or partial
  rendering produce failed/suggested entries with actionable diagnostics and
  never abort unrelated explicit comment matches.
- Sentinels are written only inside a temporary probe tree and are removed with
  it. The user's checkout and generated PR do not contain probe values.
- Reported paths and command diagnostics are bounded; secrets from subprocess
  stderr and schema URLs are not echoed beyond the existing bounded failure
  note policy.

## Acceptance criteria

- One repository-wide flate invocation renders all probe HelmReleases.
- A two-path ambiguity produces no automatic file change and a CLI/PR
  suggestion listing both paths and the exact KRR comment template.
- An explicit comment resolves that ambiguity and remains patchable.
- CRD schemas are detected from the Kubernetes API, with schema-comment
  fallback, and appear as debug/suggested evidence without automatic mapping.
- CLI and PR reports contain unambiguous, suggested, and failed sections.
- `--check-comments` diagnoses unnecessary and apparently wrong comments
  without changing comments.
- Existing dry-run, write, only-missing, explicit comment, and PR tests remain
  green.
