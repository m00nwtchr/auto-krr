from argparse import Namespace
from pathlib import Path

from auto_krr import cli
from auto_krr.types import RecommendedResources, ResourceRef, TargetKey


def _base_args(tmp_path: Path) -> Namespace:
	return Namespace(
		krr_json=tmp_path / "krr.json",
		repo=tmp_path,
		repo_url="",
		git_base_url="",
		clone_depth=None,
		min_severity="WARNING",
		only_missing=False,
		no_name_fallback=True,
		write=False,
		stage=False,
		commit=False,
		commit_message="msg",
		pr=False,
		remote="origin",
		pr_base="",
		pr_branch="",
		pr_title="title",
		forgejo_url="",
		forgejo_owner="",
		forgejo_repo="",
		forgejo_token="",
		forgejo_api_prefix="/api/v1",
		forgejo_auth_scheme="token",
		insecure_tls=False,
		allow_dirty=True,
		verbose_git=False,
	)


def _write_manifest(tmp_path: Path) -> Path:
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
	path = tmp_path / "hr.yaml"
	path.write_text(manifest, encoding="utf-8")
	return path


def test_main_dry_run(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: dry-run prints summary and exits 0 when changes exist.
	manifest_path = _write_manifest(tmp_path)
	args = _base_args(tmp_path)

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	krr_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	monkeypatch.setattr(cli, "_parse_args", lambda: args)
	monkeypatch.setattr(cli, "_resolve_env_args", lambda a: a)
	monkeypatch.setattr(cli, "_set_git_verbose", lambda *_: None)
	monkeypatch.setattr(cli, "_prepare_repo", lambda *_: (tmp_path, "main", "branch"))
	monkeypatch.setattr(cli, "_aggregate_krr", lambda *_args, **_kw: (krr_map, {}))
	monkeypatch.setattr(cli, "_git_ls_yaml_files", lambda *_: [manifest_path])

	assert cli.main() == 0


def test_main_no_changes(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: exit 0 with "No changes needed" when no targets change.
	manifest_path = _write_manifest(tmp_path)
	args = _base_args(tmp_path)

	monkeypatch.setattr(cli, "_parse_args", lambda: args)
	monkeypatch.setattr(cli, "_resolve_env_args", lambda a: a)
	monkeypatch.setattr(cli, "_set_git_verbose", lambda *_: None)
	monkeypatch.setattr(cli, "_prepare_repo", lambda *_: (tmp_path, "main", "branch"))
	monkeypatch.setattr(cli, "_aggregate_krr", lambda *_args, **_kw: ({}, {}))
	monkeypatch.setattr(cli, "_git_ls_yaml_files", lambda *_: [manifest_path])

	assert cli.main() == 2


def test_main_write_path(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: write path calls _write_changes and exits 0.
	manifest_path = _write_manifest(tmp_path)
	args = _base_args(tmp_path)
	args.write = True

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	krr_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	monkeypatch.setattr(cli, "_parse_args", lambda: args)
	monkeypatch.setattr(cli, "_resolve_env_args", lambda a: a)
	monkeypatch.setattr(cli, "_set_git_verbose", lambda *_: None)
	monkeypatch.setattr(cli, "_prepare_repo", lambda *_: (tmp_path, "main", "branch"))
	monkeypatch.setattr(cli, "_aggregate_krr", lambda *_args, **_kw: (krr_map, {}))
	monkeypatch.setattr(cli, "_git_ls_yaml_files", lambda *_: [manifest_path])
	monkeypatch.setattr(cli, "_write_changes", lambda *_args, **_kw: [manifest_path])

	assert cli.main() == 0


def test_maybe_create_pr_short_circuits(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: no PR requested exits cleanly.
	args = _base_args(tmp_path)
	args.pr = False
	assert cli._maybe_create_pr(args, tmp_path, base_branch="main", head_branch="branch", had_changes=True, summary={}, unmatched=[]) == 0


def test_main_retries_on_rebase_conflict(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: re-run apply logic after rebase conflict.
	manifest_path = _write_manifest(tmp_path)
	args = _base_args(tmp_path)
	args.write = True
	args.pr = True
	args.forgejo_token = "t"

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	krr_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	call_state = {"calls": 0}

	def _fake_maybe_create_pr(*_args, **_kwargs):
		call_state["calls"] += 1
		return 3 if call_state["calls"] == 1 else 0

	monkeypatch.setattr(cli, "_parse_args", lambda: args)
	monkeypatch.setattr(cli, "_resolve_env_args", lambda a: a)
	monkeypatch.setattr(cli, "_set_git_verbose", lambda *_: None)
	monkeypatch.setattr(cli, "_prepare_repo", lambda *_: (tmp_path, "main", "branch"))
	monkeypatch.setattr(cli, "_aggregate_krr", lambda *_args, **_kw: (krr_map, {}))
	monkeypatch.setattr(cli, "_git_ls_yaml_files", lambda *_: [manifest_path])
	monkeypatch.setattr(cli, "_write_changes", lambda *_args, **_kw: [manifest_path])
	monkeypatch.setattr(cli, "_maybe_create_pr", _fake_maybe_create_pr)

	assert cli.main() == 0
	assert call_state["calls"] == 2


def test_main_stops_after_second_rebase_conflict(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: stop after retrying once if conflicts persist.
	manifest_path = _write_manifest(tmp_path)
	args = _base_args(tmp_path)
	args.write = True
	args.pr = True
	args.forgejo_token = "t"

	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="main", container="app")
	krr_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	monkeypatch.setattr(cli, "_parse_args", lambda: args)
	monkeypatch.setattr(cli, "_resolve_env_args", lambda a: a)
	monkeypatch.setattr(cli, "_set_git_verbose", lambda *_: None)
	monkeypatch.setattr(cli, "_prepare_repo", lambda *_: (tmp_path, "main", "branch"))
	monkeypatch.setattr(cli, "_aggregate_krr", lambda *_args, **_kw: (krr_map, {}))
	monkeypatch.setattr(cli, "_git_ls_yaml_files", lambda *_: [manifest_path])
	monkeypatch.setattr(cli, "_write_changes", lambda *_args, **_kw: [manifest_path])
	monkeypatch.setattr(cli, "_maybe_create_pr", lambda *_a, **_kw: 3)

	assert cli.main() == 0


def test_maybe_create_pr_updates_when_author_matches(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: update PR body only when author matches current Forgejo user.
	args = _base_args(tmp_path)
	args.pr = True
	args.forgejo_token = "t"
	args.forgejo_url = "https://forgejo.example.com"
	args.forgejo_owner = "o"
	args.forgejo_repo = "r"

	monkeypatch.setattr(cli, "_ensure_git_http_auth", lambda *_args, **_kw: None)
	monkeypatch.setattr(cli, "_run_git", lambda *_args, **_kw: None)
	monkeypatch.setattr(cli, "_git_push_set_upstream", lambda *_args, **_kw: None)
	monkeypatch.setattr(cli, "_forgejo_find_open_pr", lambda *_args, **_kw: "https://pr/1")
	monkeypatch.setattr(cli, "_forgejo_list_open_prs", lambda *_args, **_kw: [])
	monkeypatch.setattr(
		cli,
		"_forgejo_find_open_pr_data",
		lambda *_args, **_kw: {"number": 1, "user": {"login": "me"}},
	)
	monkeypatch.setattr(cli, "_forgejo_get_user", lambda *_args, **_kw: {"login": "me"})

	updated = {"called": False}

	def _update(*_args, **_kwargs):
		updated["called"] = True
		return "https://pr/1"

	monkeypatch.setattr(cli, "_forgejo_update_pr", _update)

	assert (
		cli._maybe_create_pr(
			args,
			tmp_path,
			base_branch="main",
			head_branch="branch",
			had_changes=True,
			summary={"updated": [], "skipped": []},
			unmatched=[],
		)
		== 0
	)
	assert updated["called"] is True
