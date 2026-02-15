from pathlib import Path

import auto_krr.cli as cli
from auto_krr.cli import _maybe_create_pr


def test_pr_selection_closes_older_prs(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: pick most recent PR and close older ones.
	args = cli.argparse.Namespace(
		pr=True,
		forgejo_token="t",
		forgejo_url="https://forgejo.example.com",
		forgejo_owner="o",
		forgejo_repo="r",
		forgejo_api_prefix="/api/v1",
		forgejo_auth_scheme="token",
		insecure_tls=False,
		remote="origin",
		pr_branch="",
	)

	monkeypatch.setattr("auto_krr.cli._ensure_git_http_auth", lambda *_args, **_kw: None)
	monkeypatch.setattr("auto_krr.cli._run_git", lambda *_args, **_kw: None)
	monkeypatch.setattr("auto_krr.cli._git_push_set_upstream", lambda *_args, **_kw: None)
	monkeypatch.setattr("auto_krr.cli._forgejo_get_user", lambda *_args, **_kw: {"login": "me"})

	closed = []

	def _update(*_args, **_kwargs):
		if _kwargs.get("state") == "closed":
			closed.append(_kwargs.get("pr_number"))
		return "url"

	monkeypatch.setattr("auto_krr.cli._forgejo_update_pr", _update)
	monkeypatch.setattr(
		"auto_krr.cli._forgejo_list_open_prs",
		lambda *_args, **_kw: [
			{"number": 1, "updated_at": "2026-02-15T10:00:00Z", "head": {"ref": "old"}},
			{"number": 2, "updated_at": "2026-02-15T12:00:00Z", "head": {"ref": "new"}},
		],
	)
	monkeypatch.setattr("auto_krr.cli._forgejo_find_open_pr", lambda *_args, **_kw: "url")
	monkeypatch.setattr("auto_krr.cli._forgejo_find_open_pr_data", lambda *_args, **_kw: {"number": 2})

	status = _maybe_create_pr(
		args,
		tmp_path,
		base_branch="master",
		head_branch="master",
		had_changes=True,
		summary={"updated": [], "skipped": []},
		unmatched=[],
	)

	assert status == 0
	assert closed == [1]
