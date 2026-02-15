import warnings
from argparse import Namespace
from pathlib import Path

from auto_krr.cli import (
	_apply_implied_flags,
	_build_hr_index,
	_fmt_rel_path,
	_parse_args,
	_record_yaml_error,
	_record_yaml_warnings,
	_resolve_env_args,
)
from auto_krr.types import ResourceRef


def test_parse_args_and_resolve_env(monkeypatch) -> None:
	# Intended behavior: resolve args from env defaults when flags are not provided.
	monkeypatch.setenv("KRR_JSON", "/tmp/krr.json")
	monkeypatch.setenv("REPO", "/tmp/repo")
	monkeypatch.setenv("CHART_NAME", "custom-chart")
	monkeypatch.setenv("MIN_SEVERITY", "CRITICAL")
	monkeypatch.setenv("WRITE", "1")

	monkeypatch.setattr("sys.argv", ["auto-krr"])
	args = _parse_args()
	args = _resolve_env_args(args)

	assert str(args.krr_json) == "/tmp/krr.json"
	assert str(args.repo) == "/tmp/repo"
	assert args.chart_name == "custom-chart"
	assert args.min_severity == "CRITICAL"
	assert args.write is True


def test_apply_implied_flags() -> None:
	# Intended behavior: enabling later steps implies earlier ones.
	args = Namespace(pr=True, write=False, stage=False, commit=False)
	_apply_implied_flags(args)
	assert args.write is True
	assert args.stage is True
	assert args.commit is True


def test_record_yaml_warnings_and_errors(tmp_path: Path) -> None:
	# Intended behavior: capture warnings and errors with relative paths.
	fp = tmp_path / "file.yaml"
	fp.write_text("{}", encoding="utf-8")
	repo_root = tmp_path
	issues = {"warnings": [], "errors": []}

	with warnings.catch_warnings(record=True) as caught:
		warnings.simplefilter("always")
		warnings.warn("test warning", UserWarning)
	_record_yaml_warnings(repo_root, fp, "read", caught, issues)
	assert any("test warning" in msg for msg in issues["warnings"])

	_record_yaml_error(repo_root, fp, "read", ValueError("bad"), issues)
	assert any("ValueError" in msg for msg in issues["errors"])


def test_fmt_rel_path(tmp_path: Path) -> None:
	# Intended behavior: format paths relative to repo root when possible.
	fp = tmp_path / "dir" / "file.yaml"
	fp.parent.mkdir()
	fp.write_text("{}", encoding="utf-8")
	assert _fmt_rel_path(tmp_path, fp) == "dir/file.yaml"


def test_build_hr_index_collects_comment_targets(tmp_path: Path) -> None:
	# Intended behavior: comment targets are indexed from resources keys.
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
    resources: # krr: controller=main container=app
      requests:
        cpu: 10m
"""
	path = tmp_path / "hr.yaml"
	path.write_text(manifest, encoding="utf-8")

	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path],
		chart_name="app-template",
		chartref_kind="OCIRepository",
		yaml_issues={"warnings": [], "errors": []},
	)

	assert ResourceRef(kind="HelmRelease", namespace="default", name="demo") in hr_index
	assert "demo" in hr_index_by_name
	assert len(comment_index) == 1


def test_build_hr_index_handles_invalid_yaml(tmp_path: Path) -> None:
	# Intended behavior: invalid YAML records an error and continues.
	path = tmp_path / "bad.yaml"
	path.write_text("not: [valid", encoding="utf-8")

	yaml_issues = {"warnings": [], "errors": []}
	hr_index, hr_index_by_name, comment_index = _build_hr_index(
		tmp_path,
		[path],
		chart_name="app-template",
		chartref_kind="OCIRepository",
		yaml_issues=yaml_issues,
	)

	assert hr_index == {}
	assert hr_index_by_name == {}
	assert comment_index == {}
	assert yaml_issues["errors"]
