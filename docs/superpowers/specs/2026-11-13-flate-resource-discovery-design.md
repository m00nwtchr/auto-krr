# Flate-Based Helm Resource Discovery

## Goal

Replace chart-specific Helm value-shape heuristics with a generic discovery
algorithm that identifies the Helm values path responsible for each rendered
Kubernetes workload/container resource block.

## Approved approach

`auto-krr` remains a Python application and invokes the external `flate`
executable as the rendering authority. Discovery operates on temporary copies
of the repository and never mutates the user's checkout during probing.

The executable is configurable through `--flate-bin` / `FLATE_BIN` and defaults
to `flate`. A missing executable, unresolved chart, failed render, or ambiguous
mapping produces a skip note for the affected HelmRelease; it does not fall
back to the old chart-shape heuristics.

## Discovery algorithm

For each HelmRelease that has KRR targets:

1. Resolve the referenced chart from the repository's Flux objects. Support the
   chart references used by the target repository, including OCIRepository and
   HelmRepository references and inline HelmRelease chart definitions.
2. Fetch and cache the chart with Helm, then load both `values.yaml` and
   `values.schema.json` when present. The schema is required for charts whose
   defaults file is empty, such as app-template.
3. Enumerate concrete values paths by combining chart defaults/schema with the
   HelmRelease's `spec.values`. Expand schema `additionalProperties` using the
   actual map keys in the release values. Retain mappings that are resource
   candidates: an existing `resources` mapping or a schema-defined resources
   object containing request/limit fields. Existing release values are also
   scanned so charts with incomplete schemas remain discoverable.
4. Assign every candidate a unique sentinel resource quadruple for
   `requests.cpu`, `requests.memory`, `limits.cpu`, and `limits.memory`. Inject
   all candidate sentinels into a temporary copy of the HelmRelease in one
   probe document. This allows one flate render per HelmRelease rather than one
   render per candidate.
5. Run flate against a temporary copy that retains Git metadata (flate uses
   the repository index when selecting manifests). Restrict `--path` to the
   HelmRelease's containing directory and supply a temporary, namespaced chart
   source object so unrelated HelmRelease failures do not block discovery.
   Infer a missing HelmRelease namespace from the repository path using the
   same convention as the matcher. The command allows the same missing
   Secret/ConfigMap kinds as the existing manual validation command. Parse
   rendered workload Pod templates and inspect all regular and init
   containers.
6. For each rendered `(workload metadata.name, container.name)`, record the
   candidate path whose sentinel appears in the container's resources. A
   single path is a valid mapping. Zero paths is unmatched. Multiple paths are
   ambiguous and are skipped rather than guessed.

The result is cached for the duration of one `auto-krr` run, keyed by the
HelmRelease document and chart/value identity. Multiple KRR targets for one
HelmRelease reuse the same probe.

## Patching behavior

The matcher uses the discovered Helm values path as a concrete path below the
HelmRelease document. The patching layer creates missing intermediate mappings
along that discovered path, then applies the existing KRR quantity conversion
and `--only-missing` semantics to the resource map.

The current `HELM_VALUES_CONFIGS`, app-template controller/container fallback
rules, and non-app-template `spec.values.resources` heuristic are removed from
the HelmRelease path. Comment-based matching remains unchanged.

## Operational behavior

- `flate` and `helm` are external dependencies for HelmRelease discovery; both
  binary names are configurable and failures are reported as skips.
- Probe files live in a temporary directory and are deleted after the run.
- Flate's rendered output, warnings, and command failures are summarized in
  matcher notes without exposing secrets or writing probe sentinels to the
  repository.
- Existing dry-run/write/PR behavior is unchanged.

## Validation target

Run discovery against commit `0ab865d` of
`https://github.com/m00nwtchr/homelab-cluster`, using flate `v0.7.3`. The
validation must demonstrate mappings for ordinary app-template releases such
as `media/kavita`, including the rendered `Deployment/kavita` container
`app`, and must report unsupported or externally-missing releases as skips
rather than applying heuristic patches. The original full-repository render
reported failures for `wks`, `wordpress`, `gotosocial`, `continuwuity`, and
`tor-operator`; isolated per-HelmRelease probing may resolve some of those
independently, while remaining target-specific failures must still be skips.

## Testing strategy

- Unit-test chart reference extraction and schema/default candidate enumeration.
- Unit-test sentinel injection and rendered workload/container extraction.
- Unit-test ambiguity and render-failure handling with a fake flate command.
- Unit-test matcher/patcher integration with a temporary HelmRelease fixture.
- Run the existing pytest suite and a real flate integration check against the
  supplied homelab repository when the required Python dependencies and
  binaries are available.
