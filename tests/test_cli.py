from pathlib import Path

from ruamel.yaml.comments import CommentedMap

import auto_krr.resources_matchers as resources_matchers
from auto_krr.cli import (
	_apply_krr_to_repo,
	_build_hr_index,
	_format_cli_summary,
	_format_pr_body,
	_parse_args,
	_resolve_env_args,
)
from auto_krr.crd_schema import CrdResourceDefinition, CrdSchemaReport
from auto_krr.discovery_reports import build_discovery_report
from auto_krr.flate_discovery import DiscoveryBatch, DiscoveryResult, ReleaseIdentity
from auto_krr.types import RecommendedResources, ResourceRef, TargetKey
from auto_krr.yaml_utils import _read_all_yaml_docs


def _write_yaml(tmp_path: Path, name: str, content: str) -> Path:
	path = tmp_path / name
	path.write_text(content, encoding="utf-8")
	return path


def _install_fake_discovery(monkeypatch, result: DiscoveryResult) -> None:
	class FakeDiscovery:
		def __init__(self, _repo_root, *, flate_bin: str, helm_bin: str) -> None:
			self.flate_bin = flate_bin
			self.helm_bin = helm_bin

		def discover(self, _loc):
			return result

	monkeypatch.setattr(resources_matchers, "FlateDiscovery", FakeDiscovery)


def test_format_summaries_include_sections() -> None:
	# Intended behavior: summary formatting includes each section with counts.
	summary = {
		"updated": ["a"],
		"skipped": ["b"],
		"yaml_warnings": ["w"],
		"yaml_errors": ["e"],
	}
	unmatched = ["u"]

	pr_body = _format_pr_body(summary, unmatched)
	assert "Updated targets" in pr_body
	assert "Skipped targets" in pr_body
	assert "Unmatched targets" in pr_body
	assert "YAML warnings" in pr_body
	assert "YAML errors" in pr_body

	cli_body = _format_cli_summary(summary, unmatched)
	assert "Updated targets" in cli_body
	assert "Skipped targets" in cli_body
	assert "Unmatched targets" in cli_body
	assert "YAML warnings" in cli_body
	assert "YAML errors" in cli_body


def test_format_summaries_include_discovery_categories() -> None:
	summary = {
		"updated": [],
		"skipped": [],
		"unambiguous": ["auto match"],
		"suggested": ["suggested match"],
		"failed": ["failed match"],
	}

	pr_body = _format_pr_body(summary, [])
	cli_body = _format_cli_summary(summary, [])

	for body in (pr_body, cli_body):
		assert "Unambiguous matches" in body
		assert "Suggested matches" in body
		assert "Failed matches" in body
		assert "suggested match" in body


def test_discovery_report_suggests_every_ambiguous_option_and_keeps_crd_evidence_non_patchable() -> None:
	identity = ReleaseIdentity("media", "demo", Path("demo.yaml"), 0)
	batch = DiscoveryBatch(
		results={
			identity: DiscoveryResult(
				identity=identity,
				ambiguous={
					("demo", "app"): [
						["spec", "values", "controllers", "demo", "containers", "app", "resources"],
						["spec", "values", "workloads", "demo", "containers", "app", "resources"],
					]
				}
			)
		}
	)
	crd = CrdSchemaReport(
		definitions=[
			CrdResourceDefinition(
				crd_name="widgets.example.com",
				group="example.com",
				kind="Widget",
				version="v1",
				api_version="example.com/v1",
				schema_path=("spec", "resources"),
				source="kube-api",
				confidence="exact",
			)
		]
	)

	report = build_discovery_report(batch, crd, {})

	assert not report.unambiguous
	assert len(report.suggested) == 2
	ambiguous = next(finding for finding in report.suggested if finding.provenance == "ambiguous")
	assert len(ambiguous.options) == 2
	assert ambiguous.options[0].comment == "# krr: controller=demo container=app"
	assert any("CRD" in finding.reason for finding in report.suggested)
	assert not report.failed


def test_cli_resolves_flate_and_helm_binaries_from_environment(monkeypatch) -> None:
	monkeypatch.setenv("FLATE_BIN", "/opt/tools/flate")
	monkeypatch.setenv("HELM_BIN", "/opt/tools/helm")
	monkeypatch.setattr("sys.argv", ["auto-krr"])

	args = _resolve_env_args(_parse_args())

	assert args.flate_bin == "/opt/tools/flate"
	assert args.helm_bin == "/opt/tools/helm"


def test_cli_resolves_crd_discovery_configuration_from_environment(monkeypatch) -> None:
	monkeypatch.setenv("KUBECTL_BIN", "/opt/tools/kubectl")
	monkeypatch.setenv("DEBUG_DISCOVERY", "1")
	monkeypatch.setattr("sys.argv", ["auto-krr"])

	args = _resolve_env_args(_parse_args())

	assert args.kubectl_bin == "/opt/tools/kubectl"
	assert args.debug_discovery is True


def test_apply_krr_to_repo_uses_flate_discovered_path(tmp_path: Path, monkeypatch) -> None:
	# Intended behavior: a generic discovered values path is matched and updated.
	_install_fake_discovery(
		monkeypatch,
		DiscoveryResult(
			paths={("demo", "app"): ["spec", "values", "controllers", "main", "containers", "app", "resources"]}
		),
	)
	manifest = """\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chartRef:
    kind: OCIRepository
    name: app-template
  values:
    controllers:
      main:
        containers:
          app:
            image: ghcr.io/example/app:1.0
"""
	path = _write_yaml(tmp_path, "hr.yaml", manifest)
	raw, docs, _ = _read_all_yaml_docs(path)
	assert isinstance(docs[0], CommentedMap)

	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path],
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="demo", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	changed_files, changed_paths, total_changed, unmatched, summary = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hints_map={},
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		only_missing=False,
		no_name_fallback=True,
		cli_format="compact",
		yaml_issues={"warnings": [], "errors": []},
	)

	assert path in changed_files
	assert path in changed_paths
	assert total_changed == 1
	assert unmatched == []
	assert any("demo" in item for item in summary["updated"])


def test_apply_krr_to_repo_skips_without_flate_mapping(tmp_path: Path, monkeypatch) -> None:
	# Intended behavior: values.resources is not used when discovery cannot map a target.
	_install_fake_discovery(
		monkeypatch,
		DiscoveryResult(notes=["SKIP: flate rendered no resource sentinel for a workload container"]),
	)
	manifest = """\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chartRef:
    kind: OCIRepository
    name: custom-chart
  values:
    resources:
      requests:
        cpu: 10m
"""
	path = _write_yaml(tmp_path, "hr.yaml", manifest)

	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path],
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="demo", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	changed_files, changed_paths, total_changed, unmatched, summary = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hints_map={},
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		only_missing=False,
		no_name_fallback=True,
		cli_format="compact",
		yaml_issues={"warnings": [], "errors": []},
	)

	assert path in changed_files
	assert path not in changed_paths
	assert total_changed == 0
	assert any("no resource sentinel" in item for item in summary["skipped"])
	assert "10m" in path.read_text(encoding="utf-8")


def test_apply_krr_to_repo_reports_ambiguous_paths_without_changing_file(tmp_path: Path, monkeypatch) -> None:
	_install_fake_discovery(
		monkeypatch,
		DiscoveryResult(
			ambiguous={
				("demo", "app"): [
					["spec", "values", "controllers", "demo", "containers", "app", "resources"],
					["spec", "values", "workloads", "demo", "containers", "app", "resources"],
				]
			},
			notes=["SKIP: flate mapping is ambiguous for demo/app (2 resource paths)"],
		),
	)
	manifest = """\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chartRef:
    kind: OCIRepository
    name: custom-chart
  values:
    controllers:
      demo:
        containers:
          app: {}
"""
	path = _write_yaml(tmp_path, "hr.yaml", manifest)
	before = path.read_bytes()
	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path],
		yaml_issues={"warnings": [], "errors": []},
	)
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="demo", container="app")

	_, changed_paths, total_changed, _, summary = _apply_krr_to_repo(
		tmp_path,
		{target: RecommendedResources(req_cpu_cores=0.5)},
		hints_map={},
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		only_missing=False,
		no_name_fallback=True,
		yaml_issues={"warnings": [], "errors": []},
	)

	assert changed_paths == set()
	assert total_changed == 0
	assert path.read_bytes() == before
	assert len(summary["suggested"]) == 1
	assert "controllers.demo.containers.app.resources" in summary["suggested"][0]
	assert "# krr: controller=demo container=app" in summary["suggested"][0]


def test_apply_krr_to_repo_comment_matching_remains_available(tmp_path: Path, monkeypatch) -> None:
	# Intended behavior: comment matching still updates explicit resources blocks.
	_install_fake_discovery(monkeypatch, DiscoveryResult(notes=["SKIP: no flate mapping"]))
	manifest = """\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chartRef:
    kind: OCIRepository
    name: custom-chart
  values:
    resources: # krr: controller=main container=app
      requests:
        cpu: 10m
"""
	path = _write_yaml(tmp_path, "hr.yaml", manifest)

	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path],
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	changed_files, changed_paths, total_changed, unmatched, summary = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hints_map={},
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		only_missing=False,
		no_name_fallback=True,
		cli_format="compact",
		yaml_issues={"warnings": [], "errors": []},
	)

	assert path in changed_files
	assert path in changed_paths
	assert total_changed == 1
	assert unmatched == []
	assert any("demo" in item for item in summary["updated"])


def test_apply_krr_to_repo_name_only_ambiguity(tmp_path: Path) -> None:
	# Intended behavior: ambiguous name-only matches are treated as unmatched.
	manifest = """\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
spec:
  chartRef:
    kind: OCIRepository
    name: app-template
  values:
    controllers:
      main:
        containers:
          app:
            image: ghcr.io/example/app:1.0
"""
	path_a = _write_yaml(tmp_path, "hr-a.yaml", manifest)
	path_b = _write_yaml(tmp_path, "hr-b.yaml", manifest)

	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path_a, path_b],
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	_, _, _, unmatched, _ = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hints_map={},
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		only_missing=False,
		no_name_fallback=False,
		yaml_issues={"warnings": [], "errors": []},
	)

	assert unmatched == []


def test_unmatched_excludes_comment_targets(tmp_path: Path) -> None:
	# Intended behavior: comment-based matches suppress unmatched entries.
	manifest = """\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: trivy-operator
spec:
  chartRef:
    kind: OCIRepository
    name: trivy-operator
  values:
    # krr: controller=trivy-operator container=trivy-operator
    resources:
      requests:
        cpu: 10m
"""
	path = _write_yaml(tmp_path, "hr.yaml", manifest)

	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path],
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="trivy-operator"), controller="trivy-operator", container="trivy-operator")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	_, _, _, unmatched, _ = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hints_map={},
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		only_missing=False,
		no_name_fallback=True,
		cli_format="compact",
		yaml_issues={"warnings": [], "errors": []},
	)

	assert unmatched == []
