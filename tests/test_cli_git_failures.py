from pathlib import Path

from auto_krr.cli import _copy_changed_paths, _git_ref_exists
from auto_krr.git_utils import _run_git


def _init_git_repo(repo: Path) -> None:
	_run_git(repo, ["init"])
	_run_git(repo, ["config", "user.email", "test@example.com"])
	_run_git(repo, ["config", "user.name", "Test"])
	_run_git(repo, ["config", "commit.gpgsign", "false"])


def _commit(repo: Path, message: str) -> None:
	_run_git(repo, ["add", "--all"])
	_run_git(repo, ["commit", "-m", message])


def test_copy_changed_paths_handles_missing_src_and_dest(tmp_path: Path) -> None:
	base = tmp_path / "base"
	head = tmp_path / "head"
	base.mkdir()
	head.mkdir()

	# src exists, dest missing -> create dest
	src = base / "a.yaml"
	src.write_text("a: 1\n", encoding="utf-8")
	changed = _copy_changed_paths(src_root=base, dest_root=head, changed_paths={src})
	assert (head / "a.yaml").exists()
	assert [p.name for p in changed] == ["a.yaml"]

	# src missing, dest exists -> delete dest
	dest = head / "b.yaml"
	dest.write_text("b: 1\n", encoding="utf-8")
	missing_src = base / "b.yaml"
	changed = _copy_changed_paths(src_root=base, dest_root=head, changed_paths={missing_src})
	assert not dest.exists()
	assert [p.name for p in changed] == ["b.yaml"]


def test_merge_abort_clears_merge_head(tmp_path: Path) -> None:
	repo = tmp_path / "repo"
	repo.mkdir()
	_init_git_repo(repo)

	(repo / "file.txt").write_text("base\n", encoding="utf-8")
	_commit(repo, "base")

	_run_git(repo, ["checkout", "-b", "head"])
	(repo / "file.txt").write_text("head-change\n", encoding="utf-8")
	_commit(repo, "head")

	_run_git(repo, ["checkout", "master"])
	(repo / "file.txt").write_text("base-change\n", encoding="utf-8")
	_commit(repo, "base-change")

	_run_git(repo, ["checkout", "head"])
	_run_git(repo, ["fetch", ".", "master"])
	merge = _run_git(repo, ["merge", "--no-edit", "--autostash", "FETCH_HEAD"], check=False)
	assert merge.returncode != 0
	assert _git_ref_exists(repo, "MERGE_HEAD")

	_run_git(repo, ["merge", "--abort"], check=False)
	assert not _git_ref_exists(repo, "MERGE_HEAD")


def test_merge_autostash_leaves_no_stash(tmp_path: Path) -> None:
	repo = tmp_path / "repo"
	repo.mkdir()
	_init_git_repo(repo)

	(repo / "file.txt").write_text("base\n", encoding="utf-8")
	_commit(repo, "base")

	_run_git(repo, ["checkout", "-b", "head"])
	(repo / "file.txt").write_text("head-change\n", encoding="utf-8")
	_commit(repo, "head")

	_run_git(repo, ["checkout", "master"])
	(repo / "base.txt").write_text("base-change\n", encoding="utf-8")
	_commit(repo, "base-change")

	_run_git(repo, ["checkout", "head"])
	(repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")

	_run_git(repo, ["fetch", ".", "master"])
	merge = _run_git(repo, ["merge", "--no-edit", "--autostash", "FETCH_HEAD"], check=False)
	assert merge.returncode == 0

	stash = _run_git(repo, ["stash", "list"])
	assert stash.stdout.strip() == ""
