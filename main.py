#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import json
import math
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap


# -----------------------------
# Env config
# -----------------------------

_ENV_PREFIX = ""


def _env_get(*names: str) -> Optional[str]:
	for n in names:
		v = os.environ.get(n)
		if v is None:
			continue
		v = v.strip()
		if v == "":
			continue
		return v
	return None


def _env_key(name: str) -> str:
	return name


def _env_candidates(name: str) -> List[str]:
	return [name, f"APPLY_KRR_{name}"]


def _env_str(name: str, default: Optional[str] = None) -> Optional[str]:
	return _env_get(*_env_candidates(name)) or default


def _env_path(name: str, default: Optional[Path] = None) -> Optional[Path]:
	v = _env_get(*_env_candidates(name))
	if v is None:
		return default
	return Path(v)


def _env_bool(name: str, default: bool = False) -> bool:
	v = _env_get(*_env_candidates(name))
	if v is None:
		return default
	v = v.strip().lower()
	if v in ("1", "true", "yes", "y", "on"):
		return True
	if v in ("0", "false", "no", "n", "off"):
		return False
	return default


# -----------------------------
# Data types
# -----------------------------

@dataclass(frozen=True)
class HrRef:
	namespace: str
	name: str


@dataclass(frozen=True)
class TargetKey:
	hr: HrRef
	controller: str
	container: str


@dataclass
class RecommendedResources:
	req_cpu_cores: Optional[float] = None
	req_mem_bytes: Optional[float] = None
	lim_cpu_cores: Optional[float] = None
	lim_mem_bytes: Optional[float] = None


@dataclass
class HrDocLoc:
	path: Path
	doc_index: int
	doc: CommentedMap


# -----------------------------
# Process helpers
# -----------------------------


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
	# owner/repo shorthand
	m = re.match(r"^[^/]+/([^/]+)$", u)
	if m:
		r = m.group(1)
		return r[:-4] if r.endswith(".git") else r
	# URL forms
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
	# If already in/under a repo, use it.
	try:
		return _git_root(path)
	except Exception:
		pass

	if repo_url is None or not repo_url.strip():
		raise RuntimeError("Not inside a git repo, and no REPO_URL provided for cloning.")

	norm = _normalize_repo_url(repo_url, git_base_url=git_base_url)
	dest = path

	# If path is a non-repo directory that already exists and isn't empty, avoid nuking it.
	# Instead, clone into a child directory named after the repo.
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
	return _run(["git", "-C", str(repo_root), *args], cwd=repo_root, check=check)


def _git_root(repo: Path) -> Path:
	p = _run(["git", "-C", str(repo), "rev-parse", "--show-toplevel"], cwd=repo)
	return Path(p.stdout.strip())


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


# -----------------------------
# YAML helpers
# -----------------------------

def _mk_yaml(explicit_start: bool) -> YAML:
	yaml = YAML(typ="rt")
	yaml.preserve_quotes = True
	yaml.width = 4096
	yaml.explicit_start = explicit_start
	yaml.indent(mapping=2, sequence=4, offset=2)
	return yaml


def _read_all_yaml_docs(path: Path) -> Tuple[str, List[Any], YAML]:
	raw = path.read_text(encoding="utf-8")
	explicit_start = raw.lstrip().startswith("---")
	yaml = _mk_yaml(explicit_start=explicit_start)
	docs = list(yaml.load_all(raw))
	return raw, docs, yaml


def _dump_all_yaml_docs(yaml: YAML, docs: List[Any]) -> str:
	from io import StringIO
	buf = StringIO()
	yaml.dump_all(docs, buf)
	return buf.getvalue()


def _insert_if_missing(m: CommentedMap, key: str, value: Any, *, after_keys: List[str]) -> None:
	if key in m:
		return
	insert_at = len(m)
	for ak in after_keys:
		if ak in m:
			insert_at = list(m.keys()).index(ak) + 1
	m.insert(insert_at, key, value)


# -----------------------------
# KRR parsing
# -----------------------------

def _safe_float(v: Any) -> Optional[float]:
	if v is None:
		return None
	if isinstance(v, str):
		s = v.strip()
		if s in ("", "?"):
			return None
		try:
			return float(s)
		except ValueError:
			return None
	try:
		return float(v)
	except (TypeError, ValueError):
		return None


def _extract_rec(scan: Dict[str, Any]) -> RecommendedResources:
	rec = scan.get("recommended") or {}
	out = RecommendedResources()

	def _num(section: str, resource: str) -> Optional[float]:
		if not isinstance(rec, dict):
			return None
		sec = rec.get(section)
		if not isinstance(sec, dict):
			return None
		res = sec.get(resource)
		if not isinstance(res, dict):
			return None
		return _safe_float(res.get("value"))

	out.req_cpu_cores = _num("requests", "cpu")
	out.req_mem_bytes = _num("requests", "memory")
	out.lim_cpu_cores = _num("limits", "cpu")
	out.lim_mem_bytes = _num("limits", "memory")
	return out


def _merge_max(a: Optional[float], b: Optional[float]) -> Optional[float]:
	if a is None:
		return b
	if b is None:
		return a
	return max(a, b)


def _aggregate_krr(json_path: Path, *, min_severity: str) -> Dict[TargetKey, RecommendedResources]:
	data = json.loads(json_path.read_text(encoding="utf-8"))
	scans = data.get("scans") or []
	out: Dict[TargetKey, RecommendedResources] = {}

	severity_rank = {
		"UNKNOWN": -1,
		"OK": 0,
		"GOOD": 0,
		"WARNING": 1,
		"CRITICAL": 2,
	}
	min_rank = severity_rank.get(min_severity.upper(), 1)

	for scan in scans:
		if not isinstance(scan, dict):
			continue
		sev = str(scan.get("severity") or "UNKNOWN").upper()
		if severity_rank.get(sev, -1) < min_rank:
			continue

		obj = scan.get("object") or {}
		labels = obj.get("labels") or {}
		if not isinstance(labels, dict):
			labels = {}

		hr_name = labels.get("helm.toolkit.fluxcd.io/name")
		hr_ns = labels.get("helm.toolkit.fluxcd.io/namespace")
		if not hr_name or not hr_ns:
			continue

		controller = (
			labels.get("app.kubernetes.io/controller")
			or labels.get("app.kubernetes.io/name")
			or labels.get("app.kubernetes.io/instance")
			or obj.get("name")
			or ""
		)
		controller = str(controller)

		container = scan.get("container") or obj.get("container") or ""
		container = str(container)

		if not controller or not container:
			continue

		rec = _extract_rec(scan)
		if (
			rec.req_cpu_cores is None
			and rec.req_mem_bytes is None
			and rec.lim_cpu_cores is None
			and rec.lim_mem_bytes is None
		):
			continue

		key = TargetKey(
			hr=HrRef(namespace=str(hr_ns), name=str(hr_name)),
			controller=controller,
			container=container,
		)

		prev = out.get(key)
		if prev is None:
			out[key] = rec
		else:
			prev.req_cpu_cores = _merge_max(prev.req_cpu_cores, rec.req_cpu_cores)
			prev.req_mem_bytes = _merge_max(prev.req_mem_bytes, rec.req_mem_bytes)
			prev.lim_cpu_cores = _merge_max(prev.lim_cpu_cores, rec.lim_cpu_cores)
			prev.lim_mem_bytes = _merge_max(prev.lim_mem_bytes, rec.lim_mem_bytes)

	return out


# -----------------------------
# HelmRelease matching
# -----------------------------

def _is_helmrelease(doc: Any) -> bool:
	if not isinstance(doc, dict):
		return False
	if str(doc.get("kind", "")) != "HelmRelease":
		return False
	api = str(doc.get("apiVersion", ""))
	return api.startswith("helm.toolkit.fluxcd.io/")


def _hr_ref_from_doc(doc: Dict[str, Any]) -> HrRef:
	meta = doc.get("metadata") or {}
	name = str(meta.get("name") or "")
	ns = str(meta.get("namespace") or "")
	if not ns:
		ns = "default"
	return HrRef(namespace=ns, name=name)


def _infer_namespace_from_path(repo_root: Path, file_path: Path) -> Optional[str]:
	try:
		rel = file_path.relative_to(repo_root)
	except Exception:
		rel = file_path

	parts = list(rel.parts)
	for i, p in enumerate(parts):
		if p == "apps" and i + 1 < len(parts):
			ns = parts[i + 1]
			if ns and ns not in ("base", "common", "_templates", "templates"):
				return ns
		if p in ("namespace", "namespaces") and i + 1 < len(parts):
			ns = parts[i + 1]
			if ns:
				return ns
	return None


def _is_app_template_hr(doc: Dict[str, Any], *, chart_name: str, chartref_kind: str) -> bool:
	spec = doc.get("spec") or {}

	chart_ref = spec.get("chartRef") or {}
	if isinstance(chart_ref, dict):
		cr_kind = str(chart_ref.get("kind") or "")
		cr_name = str(chart_ref.get("name") or "")
		if cr_kind == chartref_kind and cr_name == chart_name:
			return True

	chart = spec.get("chart") or {}
	if isinstance(chart, dict):
		chart_spec = chart.get("spec") or {}
		if isinstance(chart_spec, dict):
			ch = str(chart_spec.get("chart") or "")
			if ch == chart_name:
				return True

	return False


# -----------------------------
# app-template patching
# -----------------------------

def _cpu_qty(cores: float) -> str:
	m = int(math.ceil(cores * 1000.0))
	if m <= 0:
		m = 1
	if m % 1000 == 0:
		return str(m // 1000)
	return f"{m}m"


def _mem_qty(bytes_val: float) -> str:
	mib = int(math.ceil(bytes_val / (1024.0 * 1024.0)))
	if mib <= 0:
		mib = 1
	if mib % 1024 == 0:
		return f"{mib // 1024}Gi"
	return f"{mib}Mi"


def _find_key_by_str(m: CommentedMap, wanted: str) -> Optional[Any]:
	for k in m.keys():
		if str(k) == wanted:
			return k
	return None


def _pick_controller_key(controllers: CommentedMap, wanted: str, hr_name: str) -> Optional[Any]:
	k = _find_key_by_str(controllers, wanted)
	if k is not None:
		return k
	k = _find_key_by_str(controllers, "main")
	if k is not None:
		return k
	k = _find_key_by_str(controllers, hr_name)
	if k is not None:
		return k
	if len(controllers.keys()) == 1:
		return next(iter(controllers.keys()))
	return None


def _pick_container_key(containers: CommentedMap, wanted: str) -> Optional[Any]:
	k = _find_key_by_str(containers, wanted)
	if k is not None:
		return k
	for fb in ("app", "main"):
		k = _find_key_by_str(containers, fb)
		if k is not None:
			return k
	if len(containers.keys()) == 1:
		return next(iter(containers.keys()))
	return None


def _apply_to_hr_doc(
	doc: CommentedMap,
	*,
	target: TargetKey,
	rec: RecommendedResources,
	only_missing: bool,
) -> Tuple[bool, List[str]]:
	changed = False
	notes: List[str] = []

	spec = doc.get("spec")
	if not isinstance(spec, CommentedMap):
		spec = CommentedMap()
		doc["spec"] = spec
		changed = True

	values = spec.get("values")
	if not isinstance(values, CommentedMap):
		values = CommentedMap()
		spec["values"] = values
		changed = True

	controllers = values.get("controllers")
	if not isinstance(controllers, CommentedMap):
		controllers = CommentedMap()
		values["controllers"] = controllers
		changed = True

	ctrl_key = _pick_controller_key(controllers, target.controller, target.hr.name)
	if ctrl_key is None:
		notes.append(f"SKIP: controller {target.controller!r} not found (controllers: {[str(k) for k in controllers.keys()]})")
		return False, notes

	ctrl_def = controllers.get(ctrl_key)
	if not isinstance(ctrl_def, CommentedMap):
		ctrl_def = CommentedMap()
		controllers[ctrl_key] = ctrl_def
		changed = True

	containers = ctrl_def.get("containers")
	if not isinstance(containers, CommentedMap):
		containers = CommentedMap()
		_insert_if_missing(ctrl_def, "containers", containers, after_keys=["pod", "cronjob", "statefulset", "deployment", "type"])
		changed = True

	ctr_key = _pick_container_key(containers, target.container)
	if ctr_key is None:
		notes.append(f"SKIP: container {target.container!r} not found (containers: {[str(k) for k in containers.keys()]})")
		return False, notes

	ctr_def = containers.get(ctr_key)
	if not isinstance(ctr_def, CommentedMap):
		ctr_def = CommentedMap()
		containers[ctr_key] = ctr_def
		changed = True

	resources = ctr_def.get("resources")
	if not isinstance(resources, CommentedMap):
		resources = CommentedMap()
		_insert_if_missing(ctr_def, "resources", resources, after_keys=["securityContext", "probes", "envFrom", "env", "args", "command", "image"])
		changed = True

	def _set(section: str, field: str, new_val: str) -> None:
		nonlocal changed
		sec = resources.get(section)
		if not isinstance(sec, CommentedMap):
			sec = CommentedMap()
			_insert_if_missing(resources, section, sec, after_keys=["requests" if section == "limits" else ""])
			changed = True

		old = sec.get(field)
		if only_missing and old is not None:
			notes.append(f"SKIP: {section}.{field} already set ({old!r})")
			return

		if old != new_val:
			sec[field] = new_val
			changed = True
			notes.append(f"{section}.{field}: {old!r} -> {new_val!r}")

	if rec.req_cpu_cores is not None:
		_set("requests", "cpu", _cpu_qty(rec.req_cpu_cores))
	if rec.req_mem_bytes is not None:
		_set("requests", "memory", _mem_qty(rec.req_mem_bytes))
	if rec.lim_cpu_cores is not None:
		_set("limits", "cpu", _cpu_qty(rec.lim_cpu_cores))
	if rec.lim_mem_bytes is not None:
		_set("limits", "memory", _mem_qty(rec.lim_mem_bytes))

	return changed, notes


# -----------------------------
# Forgejo PR helpers (Gitea-compatible)
# -----------------------------

@dataclass
class ForgejoRepo:
	base_url: str
	owner: str
	repo: str
	api_prefix: str


def _remote_url(repo_root: Path, remote: str) -> Optional[str]:
	p = _run_git(repo_root, ["remote", "get-url", remote], check=False)
	if p.returncode != 0:
		return None
	return p.stdout.strip()


def _detect_forgejo_from_remote(remote_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
	"""
	Supports:
	- https://host/owner/repo(.git)
	- ssh://git@host/owner/repo(.git)
	- git@host:owner/repo(.git)
	Returns (base_url, owner, repo)
	"""
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


def _http_json(
	method: str,
	url: str,
	*,
	token: str,
	auth_scheme: str,
	payload: Optional[Dict[str, Any]] = None,
	insecure_tls: bool = False,
) -> Dict[str, Any]:
	data = None
	scheme = (auth_scheme or "token").strip()
	if not scheme:
		scheme = "token"

	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json",
		"Authorization": f"{scheme} {token}",
		"User-Agent": "apply-krr.py",
	}

	if payload is not None:
		data = json.dumps(payload).encode("utf-8")

	req = urllib.request.Request(url, data=data, method=method, headers=headers)

	ctx = None
	if insecure_tls:
		ctx = ssl._create_unverified_context()

	try:
		with urllib.request.urlopen(req, context=ctx) as resp:
			body = resp.read().decode("utf-8")
			if not body:
				return {}
			return json.loads(body)
	except urllib.error.HTTPError as e:
		body = ""
		try:
			body = e.read().decode("utf-8")
		except Exception:
			pass
		raise RuntimeError(f"HTTP {e.code} {e.reason} for {url}\n{body}") from e
	except urllib.error.URLError as e:
		raise RuntimeError(f"Network error for {url}: {e}") from e


def _forgejo_create_pr(
	repo: ForgejoRepo,
	*,
	token: str,
	auth_scheme: str,
	base_branch: str,
	head_branch: str,
	title: str,
	body: str,
	insecure_tls: bool,
) -> str:
	api_prefix = repo.api_prefix.strip() or "/api/v1"
	if not api_prefix.startswith("/"):
		api_prefix = "/" + api_prefix

	api = repo.base_url.rstrip("/") + api_prefix + f"/repos/{repo.owner}/{repo.repo}/pulls"
	payload = {
		"base": base_branch,
		"head": head_branch,
		"title": title,
		"body": body,
	}
	resp = _http_json("POST", api, token=token, auth_scheme=auth_scheme, payload=payload, insecure_tls=insecure_tls)

	for k in ("html_url", "url"):
		if isinstance(resp, dict) and k in resp and isinstance(resp[k], str):
			return resp[k]
	return api


# -----------------------------
# Main
# -----------------------------

def main() -> int:
	ap = argparse.ArgumentParser(
		description="Apply KRR resource recommendations to Flux HelmReleases using bjw-s app-template (git-aware).",
	)
	ap.add_argument("--krr-json", type=Path, default=None, help=f"Path to krr.json (env: {_env_key('KRR_JSON')})")
	ap.add_argument("--repo", type=Path, default=None, help=f"Path inside repo OR clone destination dir (env: {_env_key('REPO')})")
	ap.add_argument("--repo-url", default=None, help=f"Git repo URL or owner/repo shorthand to clone if REPO isn't present (env: {_env_key('REPO_URL')})")
	ap.add_argument("--git-base-url", default=None, help=f"Base URL for owner/repo shorthand (env: {_env_key('GIT_BASE_URL')}; falls back to FORGEJO_URL or https://github.com)")
	ap.add_argument("--clone-depth", type=int, default=None, help=f"Optional git clone --depth N (env: {_env_key('CLONE_DEPTH')})")
	ap.add_argument("--chart-name", default=None, help=f"Chart name to match (env: {_env_key('CHART_NAME')})")
	ap.add_argument("--chartref-kind", default=None, help=f"chartRef.kind to match (env: {_env_key('CHARTREF_KIND')})")
	ap.add_argument("--min-severity", default=None, help=f"Min severity: OK/GOOD/WARNING/CRITICAL (env: {_env_key('MIN_SEVERITY')})")
	ap.add_argument("--only-missing", action="store_true", default=None, help=f"Only set fields that are currently missing (env: {_env_key('ONLY_MISSING')})")
	ap.add_argument("--no-name-fallback", action="store_true", default=None, help=f"Disable unique name-only matching fallback (env: {_env_key('NO_NAME_FALLBACK')})")
	ap.add_argument("--write", action="store_true", default=None, help=f"Write changes (default: dry-run) (env: {_env_key('WRITE')})")
	ap.add_argument("--stage", action="store_true", default=None, help=f"git add changed files (env: {_env_key('STAGE')})")
	ap.add_argument("--commit", action="store_true", default=None, help=f"git commit changed files (env: {_env_key('COMMIT')})")
	ap.add_argument("--commit-message", default=None, help=f"Commit message (env: {_env_key('COMMIT_MESSAGE')})")

	ap.add_argument("--pr", action="store_true", default=None, help=f"Create a Forgejo PR (env: {_env_key('PR')})")
	ap.add_argument("--remote", default=None, help=f"Git remote to push to (env: {_env_key('REMOTE')})")
	ap.add_argument("--pr-base", default=None, help=f"Base branch for PR (env: {_env_key('PR_BASE')})")
	ap.add_argument("--pr-branch", default=None, help=f"Branch to create/push (env: {_env_key('PR_BRANCH')})")
	ap.add_argument("--pr-title", default=None, help=f"PR title (env: {_env_key('PR_TITLE')})")
	ap.add_argument("--pr-body", default=None, help=f"PR body (env: {_env_key('PR_BODY')})")
	ap.add_argument("--forgejo-url", default=None, help=f"Forgejo base URL (env: {_env_key('FORGEJO_URL')})")
	ap.add_argument("--forgejo-owner", default=None, help=f"Forgejo repo owner (env: {_env_key('FORGEJO_OWNER')})")
	ap.add_argument("--forgejo-repo", default=None, help=f"Forgejo repo name (env: {_env_key('FORGEJO_REPO')})")
	ap.add_argument("--forgejo-token", default=None, help=f"Forgejo API token (env: {_env_key('FORGEJO_TOKEN')} or FORGEJO_TOKEN)")
	ap.add_argument("--forgejo-api-prefix", default=None, help=f"Forgejo API prefix (default /api/v1) (env: {_env_key('FORGEJO_API_PREFIX')})")
	ap.add_argument("--forgejo-auth-scheme", default=None, help=f"Authorization scheme (default 'token') (env: {_env_key('FORGEJO_AUTH_SCHEME')})")
	ap.add_argument("--insecure-tls", action="store_true", default=None, help=f"Disable TLS verification for Forgejo API (env: {_env_key('INSECURE_TLS')})")
	ap.add_argument("--allow-dirty", action="store_true", default=None, help=f"Allow running with dirty git tree (env: {_env_key('ALLOW_DIRTY')})")

	args = ap.parse_args()

	# ---- resolve from env (CLI wins) ----
	args.krr_json = args.krr_json or _env_path("KRR_JSON")
	args.repo = args.repo or _env_path("REPO", Path("."))
	args.repo_url = args.repo_url or _env_str("REPO_URL", "")
	args.git_base_url = args.git_base_url or _env_str("GIT_BASE_URL", "")
	clone_depth_s = _env_str("CLONE_DEPTH", "")
	args.clone_depth = args.clone_depth if args.clone_depth is not None else (int(clone_depth_s) if clone_depth_s.strip().isdigit() else None)

	args.chart_name = args.chart_name or _env_str("CHART_NAME", "app-template")
	args.chartref_kind = args.chartref_kind or _env_str("CHARTREF_KIND", "OCIRepository")
	args.min_severity = args.min_severity or _env_str("MIN_SEVERITY", "WARNING")

	args.only_missing = args.only_missing if args.only_missing is not None else _env_bool("ONLY_MISSING", False)
	args.no_name_fallback = args.no_name_fallback if args.no_name_fallback is not None else _env_bool("NO_NAME_FALLBACK", False)

	args.write = args.write if args.write is not None else _env_bool("WRITE", False)
	args.stage = args.stage if args.stage is not None else _env_bool("STAGE", False)
	args.commit = args.commit if args.commit is not None else _env_bool("COMMIT", False)
	args.commit_message = args.commit_message or _env_str("COMMIT_MESSAGE", "chore: apply krr resource recommendations")

	args.pr = args.pr if args.pr is not None else _env_bool("PR", False)
	args.remote = args.remote or _env_str("REMOTE", "origin")
	args.pr_base = args.pr_base or _env_str("PR_BASE", "")
	args.pr_branch = args.pr_branch or _env_str("PR_BRANCH", "")
	args.pr_title = args.pr_title or _env_str("PR_TITLE", "chore: apply krr resource recommendations")
	args.pr_body = args.pr_body or _env_str("PR_BODY", "Automated resource recommendation update from KRR.")

	args.forgejo_url = args.forgejo_url or _env_str("FORGEJO_URL", "")
	args.forgejo_owner = args.forgejo_owner or _env_str("FORGEJO_OWNER", "")
	args.forgejo_repo = args.forgejo_repo or _env_str("FORGEJO_REPO", "")
	args.forgejo_token = args.forgejo_token or _env_get("FORGEJO_TOKEN", "APPLY_KRR_FORGEJO_TOKEN")
	args.forgejo_api_prefix = args.forgejo_api_prefix or _env_str("FORGEJO_API_PREFIX", "/api/v1")
	args.forgejo_auth_scheme = args.forgejo_auth_scheme or _env_str("FORGEJO_AUTH_SCHEME", "token")

	args.insecure_tls = args.insecure_tls if args.insecure_tls is not None else _env_bool("INSECURE_TLS", False)
	args.allow_dirty = args.allow_dirty if args.allow_dirty is not None else _env_bool("ALLOW_DIRTY", False)

	if args.krr_json is None:
		print(f"ERROR: missing krr.json path. Provide --krr-json or set {_env_key('KRR_JSON')}", file=sys.stderr)
		return 2

	# ---- implied flags ----
	if args.pr:
		args.write = True
		args.stage = True
		args.commit = True
	if args.commit:
		args.stage = True
	if args.stage:
		args.write = True

	try:
		repo_root = _ensure_repo(
			args.repo,
			repo_url=(args.repo_url or None),
			git_base_url=(args.git_base_url or None),
			clone_depth=args.clone_depth,
		)
	except Exception as e:
		print(f"ERROR: {e}", file=sys.stderr)
		return 2

	if _git_is_dirty(repo_root) and not args.allow_dirty:
		print(
			f"ERROR: working tree is dirty. Commit/stash first, or pass --allow-dirty / set {_env_key('ALLOW_DIRTY')}=1.",
			file=sys.stderr,
		)
		return 2

	base_branch = args.pr_base.strip() or _git_current_branch(repo_root)
	head_branch = args.pr_branch.strip()
	if args.pr and not head_branch:
		ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
		head_branch = f"krr-resources-{ts}"

	if args.pr:
		_git_checkout_new(repo_root, head_branch, base_branch)

	krr_map = _aggregate_krr(args.krr_json, min_severity=args.min_severity)
	if not krr_map:
		print("No applicable KRR entries found (after severity filter, or missing Flux labels).", file=sys.stderr)
		return 2

	yaml_files = _git_ls_yaml_files(repo_root)
	if not yaml_files:
		print("No tracked YAML files found in repo.", file=sys.stderr)
		return 2

	hr_index: Dict[HrRef, List[HrDocLoc]] = {}
	hr_index_by_name: Dict[str, List[HrDocLoc]] = {}

	for fp in yaml_files:
		try:
			_, docs, _ = _read_all_yaml_docs(fp)
		except Exception:
			continue

		for i, doc in enumerate(docs):
			if not _is_helmrelease(doc):
				continue
			if not _is_app_template_hr(doc, chart_name=args.chart_name, chartref_kind=args.chartref_kind):
				continue

			ref = _hr_ref_from_doc(doc)
			if not ref.name:
				continue

			meta = doc.get("metadata") or {}
			if (not meta.get("namespace")) and ref.namespace == "default":
				guess = _infer_namespace_from_path(repo_root, fp)
				if guess:
					ref = HrRef(namespace=guess, name=ref.name)

			loc = HrDocLoc(path=fp, doc_index=i, doc=doc)
			hr_index.setdefault(ref, []).append(loc)
			hr_index_by_name.setdefault(ref.name, []).append(loc)

	if not hr_index:
		print("No app-template HelmReleases found in repo (matching chartRef/chart name).", file=sys.stderr)
		return 2

	changed_files: Dict[Path, Tuple[str, List[Any], YAML]] = {}
	total_changed_targets = 0
	unmatched: List[TargetKey] = []

	def _ensure_loaded(fp: Path) -> Tuple[str, List[Any], YAML]:
		if fp in changed_files:
			return changed_files[fp]
		raw, docs, yaml = _read_all_yaml_docs(fp)
		changed_files[fp] = (raw, docs, yaml)
		return raw, docs, yaml

	for target, rec in krr_map.items():
		locs = hr_index.get(target.hr)

		if not locs and not args.no_name_fallback:
			cands = hr_index_by_name.get(target.hr.name, [])
			if len(cands) == 1:
				locs = cands
				print(f"NOTE: matched {target.hr.namespace}/{target.hr.name} by name-only (manifest likely missing metadata.namespace).")
			else:
				locs = None

		if not locs:
			unmatched.append(target)
			continue

		for loc in locs:
			raw, docs, yaml = _ensure_loaded(loc.path)
			doc = docs[loc.doc_index]
			if not isinstance(doc, CommentedMap):
				continue

			changed, notes = _apply_to_hr_doc(
				doc,
				target=target,
				rec=rec,
				only_missing=args.only_missing,
			)

			if notes:
				print(f"- {target.hr.namespace}/{target.hr.name} controller={target.controller} container={target.container} @ {loc.path.relative_to(repo_root)}")
				for n in notes:
					print(f"	{n}")

			if changed:
				total_changed_targets += 1

	if unmatched:
		print("\nUnmatched KRR targets:", file=sys.stderr)
		for t in unmatched[:200]:
			print(f"	- {t.hr.namespace}/{t.hr.name} controller={t.controller} container={t.container}", file=sys.stderr)

	if total_changed_targets == 0:
		print("\nNo changes needed.")
		return 0

	if not args.write:
		print(f"\nDRY-RUN: would update {len(changed_files)} file(s), {total_changed_targets} target(s). Use --write or set {_env_key('WRITE')}=1.")
		return 0

	actually_changed: List[Path] = []
	for fp, (raw, docs, yaml) in changed_files.items():
		new_txt = _dump_all_yaml_docs(yaml, docs)
		if new_txt != raw:
			fp.write_text(new_txt, encoding="utf-8")
			actually_changed.append(fp)

	print(f"\nWROTE: updated {len(actually_changed)} file(s).")

	if args.stage and actually_changed:
		rel_paths = [str(p.relative_to(repo_root)) for p in actually_changed]
		_run_git(repo_root, ["add", "--", *rel_paths])
		print("STAGED: git add on changed files.")

	if args.commit and actually_changed:
		_run_git(repo_root, ["commit", "-m", args.commit_message])
		print("COMMITTED.")

	if args.pr:
		_git_push_set_upstream(repo_root, args.remote, head_branch)
		print(f"PUSHED: {args.remote}/{head_branch}")

		token = (args.forgejo_token or "").strip()
		if not token:
			print(f"ERROR: missing Forgejo token. Set {_env_key('FORGEJO_TOKEN')} or FORGEJO_TOKEN.", file=sys.stderr)
			return 2

		base_url = (args.forgejo_url or "").strip()
		owner = (args.forgejo_owner or "").strip()
		repo_name = (args.forgejo_repo or "").strip()

		if not (base_url and owner and repo_name):
			remote_url = _remote_url(repo_root, args.remote)
			if not remote_url:
				print("ERROR: could not read remote URL to infer Forgejo repo.", file=sys.stderr)
				return 2
			d_base, d_owner, d_repo = _detect_forgejo_from_remote(remote_url)
			base_url = base_url or (d_base or "")
			owner = owner or (d_owner or "")
			repo_name = repo_name or (d_repo or "")

		if not (base_url and owner and repo_name):
			print(
				"ERROR: could not infer Forgejo repo from remote. Provide --forgejo-url/--forgejo-owner/--forgejo-repo "
				f"or set {_env_key('FORGEJO_URL')}/{_env_key('FORGEJO_OWNER')}/{_env_key('FORGEJO_REPO')}",
				file=sys.stderr,
			)
			return 2

		repo = ForgejoRepo(
			base_url=base_url,
			owner=owner,
			repo=repo_name,
			api_prefix=args.forgejo_api_prefix,
		)

		try:
			pr_url = _forgejo_create_pr(
				repo,
				token=token,
				auth_scheme=args.forgejo_auth_scheme,
				base_branch=base_branch,
				head_branch=head_branch,
				title=args.pr_title,
				body=args.pr_body,
				insecure_tls=args.insecure_tls,
			)
		except Exception as e:
			print(f"ERROR: failed to create PR: {e}", file=sys.stderr)
			return 2

		print(f"PR CREATED: {pr_url}")

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
