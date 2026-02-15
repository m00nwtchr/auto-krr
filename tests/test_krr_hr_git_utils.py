import json
from pathlib import Path

from auto_krr.git_utils import _mask_git_args, _normalize_repo_url, _repo_dir_name
from auto_krr.hr import _infer_namespace_from_path
from auto_krr.krr import _aggregate_krr, _safe_float


def test_safe_float() -> None:
	# Intended behavior: tolerate unknowns and parse numeric strings.
	assert _safe_float("1.25") == 1.25
	assert _safe_float(" ? ") is None
	assert _safe_float("") is None
	assert _safe_float(None) is None


def test_aggregate_krr_merges_and_filters(tmp_path: Path) -> None:
	# Intended behavior: merge max values at or above min_severity into both maps.
	data = {
		"scans": [
			{
				"severity": "OK",
				"object": {
					"labels": {
						"helm.toolkit.fluxcd.io/name": "app",
						"helm.toolkit.fluxcd.io/namespace": "default",
					},
					"name": "app",
				},
				"container": "app",
				"recommended": {
					"requests": {"cpu": {"value": "0.1"}},
				},
			},
			{
				"severity": "WARNING",
				"object": {
					"labels": {
						"helm.toolkit.fluxcd.io/name": "app",
						"helm.toolkit.fluxcd.io/namespace": "default",
					},
					"name": "app",
				},
				"container": "app",
				"recommended": {
					"requests": {"cpu": {"value": "0.5"}, "memory": {"value": 1048576}},
					"limits": {"cpu": {"value": "1.0"}},
				},
			},
			{
				"severity": "CRITICAL",
				"object": {
					"labels": {
						"helm.toolkit.fluxcd.io/name": "app",
						"helm.toolkit.fluxcd.io/namespace": "default",
					},
					"name": "app",
				},
				"container": "app",
				"recommended": {
					"requests": {"cpu": {"value": "0.8"}},
					"limits": {"cpu": {"value": "0.9"}},
				},
			},
		]
	}
	json_path = tmp_path / "krr.json"
	json_path.write_text(json.dumps(data), encoding="utf-8")

	hr_out, comment_out = _aggregate_krr(json_path, min_severity="WARNING")
	assert len(hr_out) == 1
	assert len(comment_out) == 1
	rec = next(iter(hr_out.values()))
	assert rec.req_cpu_cores == 0.8
	assert rec.req_mem_bytes == 1048576
	assert rec.lim_cpu_cores == 1.0


def test_aggregate_krr_skips_invalid_entries(tmp_path: Path) -> None:
	# Intended behavior: skip scans with missing controller/container or no values.
	data = {
		"scans": [
			{"severity": "WARNING", "object": {"name": "app"}, "container": "", "recommended": {}},
			{"severity": "WARNING", "object": {}, "container": "c", "recommended": {}},
		]
	}
	json_path = tmp_path / "krr.json"
	json_path.write_text(json.dumps(data), encoding="utf-8")

	hr_out, comment_out = _aggregate_krr(json_path, min_severity="WARNING")
	assert hr_out == {}
	assert comment_out == {}


def test_infer_namespace_from_path() -> None:
	# Intended behavior: infer namespaces from common repo layouts.
	repo_root = Path("/repo")
	assert _infer_namespace_from_path(repo_root, Path("/repo/apps/media/app/hr.yaml")) == "media"
	assert _infer_namespace_from_path(repo_root, Path("/repo/namespaces/prod/helmrelease.yaml")) == "prod"
	assert _infer_namespace_from_path(repo_root, Path("/repo/apps/base/app/hr.yaml")) is None


def test_git_url_helpers_and_masking() -> None:
	# Intended behavior: normalize URLs and redact secrets in git args.
	assert (
		_normalize_repo_url("org/repo", git_base_url="https://forgejo.example.com")
		== "https://forgejo.example.com/org/repo.git"
	)
	assert _normalize_repo_url("org/repo.git", git_base_url="https://forgejo.example.com") == "https://forgejo.example.com/org/repo.git"
	assert _repo_dir_name("https://github.com/org/repo.git") == "repo"
	assert _repo_dir_name("org/repo") == "repo"

	cmd = [
		"git",
		"-c",
		"http.https://example.com/.extraHeader=Authorization: token secret",
		"clone",
		"https://user:pass@example.com/org/repo.git",
	]
	masked = _mask_git_args(cmd)
	assert "Authorization: <redacted>" in " ".join(masked)
	assert "https://<redacted>@example.com/org/repo.git" in " ".join(masked)
