from __future__ import annotations

import os
import re
import subprocess
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple


def _run(cmd: List[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
	return subprocess.run(
		cmd,
		cwd=str(cwd),
		check=check,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		text=True,
	)


def _run_git(repo_root: Path, args: List[str], *, check: bool = True) -> subprocess.CompletedProcess:
	return _run(["git", "-C", str(repo_root), "-c", f"safe.directory={repo_root}", *args], cwd=repo_root, check=check)


def _git_root(repo: Path) -> Path:
	p = _run(["git", "-C", str(repo), "rev-parse", "--show-toplevel"], cwd=repo)
	return Path(p.stdout.strip())


def _is_git_repo(path: Path) -> bool:
	p = _run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"], cwd=path, check=False)
	return p.returncode == 0 and p.stdout.strip().lower() == "true"


def _dir_is_empty(path: Path) -> bool:
	if not path.exists() or not path.is_dir():
		return False
	try:
		return next(path.iterdir(), None) is None
	except Exception:
		return False


def _normalize_repo_url(repo_url: str, *, git_base_url: Optional[str]) -> str:
	u = repo_url.strip()
	if not u:
		return u
	if "://" in u or u.startswith("git@") or u.startswith("ssh://"):
		return u
	m = re.match(r"^([^/]+)/([^/]+)$", u)
	if m:
		owner, repo = m.group(1), m.group(2)
		base = (git_base_url or "").strip() or os.environ.get("GIT_BASE_URL", "").strip() or os.environ.get("FORGEJO_URL", "").strip() or "https://github.com"
		base = base.rstrip("/")
		repo_name = repo[:-4] if repo.endswith(".git") else repo
		return f"{base}/{owner}/{repo_name}.git"
	return u


def _repo_dir_name(repo_url: str) -> str:
	u = repo_url.strip()
	if not u:
		return "repo"
	m = re.match(r"^[^/]+/([^/]+)$", u)
	if m:
		r = m.group(1)
		return r[:-4] if r.endswith(".git") else r
	try:
		pu = urllib.parse.urlparse(u if "://" in u else "https://" + u)
		base = pu.path.rstrip("/").split("/")[-1] or "repo"
		return base[:-4] if base.endswith(".git") else base
	except Exception:
		base = u.rstrip("/").split("/")[-1]
		return base[:-4] if base.endswith(".git") else base


def _git_clone(repo_url: str, dest: Path, *, depth: Optional[int] = None) -> None:
	dest.parent.mkdir(parents=True, exist_ok=True)
	cmd = ["git", "clone"]
	if depth is not None and depth > 0:
		cmd += ["--depth", str(depth)]
	cmd += [repo_url, str(dest)]
	p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
	if p.returncode != 0:
		raise RuntimeError(f"git clone failed for {repo_url} -> {dest}\n{p.stderr}")


def _ensure_repo(path: Path, repo_url: Optional[str], *, git_base_url: Optional[str], clone_depth: Optional[int]) -> Path:
	try:
		return _git_root(path)
	except Exception:
		pass

	if repo_url is None or not repo_url.strip():
		raise RuntimeError("Not inside a git repo, and no REPO_URL provided for cloning.")

	norm = _normalize_repo_url(repo_url, git_base_url=git_base_url)
	dest = path

	if dest.exists() and dest.is_dir() and not _dir_is_empty(dest):
		child = dest / _repo_dir_name(repo_url)
		if _is_git_repo(child) or (child.exists() and (child / ".git").exists()):
			return _git_root(child)
		dest = child

	if dest.exists():
		if dest.is_dir() and _dir_is_empty(dest):
			try:
				dest.rmdir()
			except OSError:
				raise RuntimeError(f"Destination {dest} exists but is not removable.")
		else:
			raise RuntimeError(f"Path {dest} exists but is not a git repo. Point REPO at a repo, or an empty/nonexistent directory.")

	_git_clone(norm, dest, depth=clone_depth)
	return _git_root(dest)


def _git_ls_yaml_files(repo_root: Path) -> List[Path]:
	p = _run_git(repo_root, ["ls-files", "-z", "--", "*.yml", "*.yaml"])
	parts = [x for x in p.stdout.split("\0") if x]
	return [repo_root / x for x in parts]


def _git_current_branch(repo_root: Path) -> str:
	p = _run_git(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"])
	return p.stdout.strip()


def _git_is_dirty(repo_root: Path) -> bool:
	p = _run_git(repo_root, ["status", "--porcelain"])
	return bool(p.stdout.strip())


def _git_checkout(repo_root: Path, branch: str) -> None:
	_run_git(repo_root, ["checkout", branch])


def _git_checkout_new(repo_root: Path, branch: str, base: str) -> None:
	_run_git(repo_root, ["checkout", base])
	_run_git(repo_root, ["checkout", "-b", branch])


def _git_push_set_upstream(repo_root: Path, remote: str, branch: str) -> None:
	_run_git(repo_root, ["push", "-u", remote, branch])


def _remote_url(repo_root: Path, remote: str) -> Optional[str]:
	p = _run_git(repo_root, ["remote", "get-url", remote], check=False)
	if p.returncode != 0:
		return None
	return p.stdout.strip()


def _git_config_get(repo_root: Path, key: str) -> Optional[str]:
	p = _run_git(repo_root, ["config", "--get", key], check=False)
	if p.returncode != 0:
		return None
	v = p.stdout.strip()
	return v or None


def _host_from_url(url: str) -> Optional[str]:
	u = (url or "").strip()
	if not u:
		return None
	if "://" not in u:
		u = "https://" + u
	try:
		pu = urllib.parse.urlparse(u)
		if pu.netloc:
			return pu.netloc
	except Exception:
		return None
	return None


def _default_git_email(repo_root: Path, forgejo_url: Optional[str]) -> str:
	host = _host_from_url(forgejo_url or "")
	if not host:
		host = _host_from_url(os.environ.get("FORGEJO_URL", "") or os.environ.get("GIT_BASE_URL", ""))
	if not host:
		remote = _remote_url(repo_root, "origin")
		if remote:
			base, _, _ = _detect_forgejo_from_remote(remote)
			host = _host_from_url(base or "")
	if host:
		return f"krr@{host}"
	return "auto-krr@localhost"


def _ensure_git_identity(repo_root: Path, *, forgejo_url: Optional[str] = None) -> None:
	name = _git_config_get(repo_root, "user.name")
	email = _git_config_get(repo_root, "user.email")
	if name and email:
		return

	fallback_name = (
		os.environ.get("GIT_AUTHOR_NAME")
		or os.environ.get("GIT_COMMITTER_NAME")
		or "krr-bot"
	)
	fallback_email = (
		os.environ.get("GIT_AUTHOR_EMAIL")
		or os.environ.get("GIT_COMMITTER_EMAIL")
		or _default_git_email(repo_root, forgejo_url)
	)

	if not name:
		_run_git(repo_root, ["config", "user.name", fallback_name])
	if not email:
		_run_git(repo_root, ["config", "user.email", fallback_email])


def _detect_forgejo_from_remote(remote_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
	u = remote_url.strip()

	m = re.match(r"^git@([^:]+):([^/]+)/(.+?)(?:\.git)?$", u)
	if m:
		host, owner, repo = m.group(1), m.group(2), m.group(3)
		return f"https://{host}", owner, repo

	m = re.match(r"^ssh://(?:.+@)?([^/]+)/([^/]+)/(.+?)(?:\.git)?$", u)
	if m:
		host, owner, repo = m.group(1), m.group(2), m.group(3)
		return f"https://{host}", owner, repo

	try:
		pu = urllib.parse.urlparse(u)
		if pu.scheme in ("http", "https") and pu.netloc:
			parts = [p for p in pu.path.split("/") if p]
			if len(parts) >= 2:
				owner = parts[0]
				repo = parts[1]
				if repo.endswith(".git"):
					repo = repo[:-4]
				base = f"{pu.scheme}://{pu.netloc}"
				return base, owner, repo
	except Exception:
		pass

	return None, None, None
