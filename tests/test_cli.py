from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from auto_krr.cli import _apply_krr_to_repo, _build_hr_index, _format_cli_summary, _format_pr_body
from auto_krr.types import RecommendedResources, ResourceRef, TargetKey
from auto_krr.yaml_utils import _read_all_yaml_docs


def _write_yaml(tmp_path: Path, name: str, content: str) -> Path:
	path = tmp_path / name
	path.write_text(content, encoding="utf-8")
	return path


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


def test_apply_krr_to_repo_app_template(tmp_path: Path) -> None:
	# Intended behavior: app-template HRs are matched and updated.
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
		chart_name="app-template",
		chartref_kind="OCIRepository",
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	changed_files, total_changed, unmatched, summary = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		chart_name="app-template",
		only_missing=False,
		no_name_fallback=True,
		yaml_issues={"warnings": [], "errors": []},
	)

	assert path in changed_files
	assert total_changed == 1
	assert unmatched == []
	assert any("demo" in item for item in summary["updated"])


def test_apply_krr_to_repo_heuristic(tmp_path: Path) -> None:
	# Intended behavior: heuristic uses values.resources when only one workload exists.
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
		chart_name="custom-chart",
		chartref_kind="OCIRepository",
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	changed_files, total_changed, unmatched, summary = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		chart_name="custom-chart",
		only_missing=False,
		no_name_fallback=True,
		yaml_issues={"warnings": [], "errors": []},
	)

	assert path in changed_files
	assert total_changed == 1
	assert unmatched == []
	assert any("demo" in item for item in summary["updated"])


def test_apply_krr_to_repo_dedup_resources_blocks(tmp_path: Path) -> None:
	# Intended behavior: only apply one matcher per resources block, even if multiple match.
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
		chart_name="custom-chart",
		chartref_kind="OCIRepository",
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	changed_files, total_changed, unmatched, summary = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		chart_name="custom-chart",
		only_missing=False,
		no_name_fallback=True,
		yaml_issues={"warnings": [], "errors": []},
	)

	assert path in changed_files
	assert total_changed == 1
	assert unmatched == []
	assert any("resources block already matched" in item for item in summary["skipped"])


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
		chart_name="app-template",
		chartref_kind="OCIRepository",
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	_, _, unmatched, _ = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		chart_name="app-template",
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
		chart_name="trivy-operator",
		chartref_kind="OCIRepository",
		yaml_issues={"warnings": [], "errors": []},
	)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="trivy-operator"), controller="trivy-operator", container="trivy-operator")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	_, _, unmatched, _ = _apply_krr_to_repo(
		tmp_path,
		rec_map,
		hr_index=hr_index,
		hr_index_by_name=hr_index_by_name,
		comment_index=comment_index,
		chart_name="trivy-operator",
		only_missing=False,
		no_name_fallback=True,
		yaml_issues={"warnings": [], "errors": []},
	)

	assert unmatched == []
