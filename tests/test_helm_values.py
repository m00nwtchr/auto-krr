import stat
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from auto_krr.helm_values import (
	ChartRef,
	ChartValues,
	_enumerate_resource_candidates,
	_load_chart_values,
	_resolve_chart_ref,
)


def _load_doc(text: str) -> CommentedMap:
	yaml = YAML(typ="rt")
	doc = yaml.load(text)
	assert isinstance(doc, CommentedMap)
	return doc


def _write_executable(path: Path, body: str) -> None:
	path.write_text(body, encoding="utf-8")
	path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_resolve_oci_repository_chart_ref(tmp_path: Path) -> None:
	(tmp_path / "sources.yaml").write_text(
		"""\
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: app-template
  namespace: flux-system
spec:
  url: oci://ghcr.io/example/app-template
  ref:
    tag: 5.3.0
""",
		encoding="utf-8",
	)
	doc = _load_doc(
		"""\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chartRef:
    kind: OCIRepository
    name: app-template
    namespace: flux-system
"""
	)

	ref = _resolve_chart_ref(tmp_path, doc)

	assert ref is not None
	assert ref.source_kind == "OCIRepository"
	assert ref.chart == "oci://ghcr.io/example/app-template"
	assert ref.version == "5.3.0"


def test_resolve_helm_repository_chart_ref(tmp_path: Path) -> None:
	(tmp_path / "sources.yaml").write_text(
		"""\
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: bitnami
  namespace: flux-system
spec:
  url: https://charts.bitnami.com/bitnami
""",
		encoding="utf-8",
	)
	doc = _load_doc(
		"""\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chartRef:
    kind: HelmRepository
    name: bitnami
    namespace: flux-system
    chart: nginx
    version: 18.2.0
"""
	)

	ref = _resolve_chart_ref(tmp_path, doc)

	assert ref is not None
	assert ref.source_kind == "HelmRepository"
	assert ref.chart == "nginx"
	assert ref.source_url == "https://charts.bitnami.com/bitnami"
	assert ref.version == "18.2.0"


def test_resolve_inline_chart_spec(tmp_path: Path) -> None:
	(tmp_path / "sources.yaml").write_text(
		"""\
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: charts
  namespace: default
spec:
  url: https://example.test/charts
""",
		encoding="utf-8",
	)
	doc = _load_doc(
		"""\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chart:
    spec:
      chart: demo-chart
      version: 1.2.3
      sourceRef:
        kind: HelmRepository
        name: charts
        namespace: default
"""
	)

	ref = _resolve_chart_ref(tmp_path, doc)

	assert ref is not None
	assert ref.chart == "demo-chart"
	assert ref.source_url == "https://example.test/charts"
	assert ref.version == "1.2.3"


def test_load_chart_values_uses_helm_and_reads_schema(tmp_path: Path) -> None:
	bin_path = tmp_path / "fake-helm"
	_write_executable(
		bin_path,
		r"""#!/usr/bin/env python3
import pathlib
import sys

args = sys.argv[1:]
root = pathlib.Path(args[args.index("--untardir") + 1]) / "demo-chart"
root.mkdir(parents=True)
(root / "values.yaml").write_text("defaults:\n  enabled: true\n")
(root / "values.schema.json").write_text('{"type":"object","properties":{}}')
(root / "Chart.yaml").write_text("name: demo-chart\n")
""",
	)
	ref = ChartRef(
		chart="demo-chart",
		version="1.2.3",
		source_kind="HelmRepository",
		source_url="https://example.test/charts",
	)

	values = _load_chart_values(ref, str(bin_path), tmp_path / "cache")

	assert values.defaults["defaults"]["enabled"] is True
	assert values.schema == {"type": "object", "properties": {}}


def test_schema_dynamic_maps_produce_resource_candidate_with_empty_defaults() -> None:
	chart_values = ChartValues(
		defaults=CommentedMap(),
		schema={
			"type": "object",
			"properties": {
				"controllers": {
					"type": "object",
					"additionalProperties": {
						"type": "object",
						"properties": {
							"containers": {
								"type": "object",
								"additionalProperties": {
									"type": "object",
									"properties": {
										"resources": {
											"type": "object",
											"properties": {
												"requests": {"type": "object"},
												"limits": {"type": "object"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	)
	release_values = _load_doc(
		"""\
controllers:
  main:
    containers:
      app:
        image: example/app:1
"""
	)

	candidates = _enumerate_resource_candidates(chart_values, release_values)

	assert [candidate.path for candidate in candidates] == [
		["controllers", "main", "containers", "app", "resources"]
	]


def test_existing_values_produce_candidate_when_schema_is_incomplete() -> None:
	chart_values = ChartValues(defaults=CommentedMap(), schema={"type": "object"})
	release_values = _load_doc(
		"""\
worker:
  resources:
    requests:
      cpu: 10m
"""
	)

	candidates = _enumerate_resource_candidates(chart_values, release_values)

	assert [candidate.path for candidate in candidates] == [["worker", "resources"]]
