from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from ruamel.yaml.comments import CommentedMap

from .env import _env_bool, _env_get, _env_key, _env_path, _env_str
from .forgejo import _forgejo_create_pr, _forgejo_find_open_pr
from .git_utils import (
	_detect_forgejo_from_remote,
	_ensure_git_identity,
	_ensure_repo,
	_git_checkout_new,
	_git_current_branch,
	_git_is_dirty,
	_git_ls_yaml_files,
	_git_push_set_upstream,
	_remote_url,
	_run_git,
)
from .hr import _hr_ref_from_doc, _infer_namespace_from_path, _is_app_template_hr, _is_helmrelease
from .krr import _aggregate_krr
from .patching import _apply_to_hr_doc
from .types import ForgejoRepo, HrDocLoc, HrRef, RecommendedResources, TargetKey, YamlDocBundle
from .yaml_utils import _dump_all_yaml_docs, _read_all_yaml_docs


def _parse_args() -> argparse.Namespace:
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
	ap.add_argument("--forgejo-url", default=None, help=f"Forgejo base URL (env: {_env_key('FORGEJO_URL')})")
	ap.add_argument("--forgejo-owner", default=None, help=f"Forgejo repo owner (env: {_env_key('FORGEJO_OWNER')})")
	ap.add_argument("--forgejo-repo", default=None, help=f"Forgejo repo name (env: {_env_key('FORGEJO_REPO')})")
	ap.add_argument("--forgejo-token", default=None, help=f"Forgejo API token (env: {_env_key('FORGEJO_TOKEN')} or FORGEJO_TOKEN)")
	ap.add_argument("--forgejo-api-prefix", default=None, help=f"Forgejo API prefix (default /api/v1) (env: {_env_key('FORGEJO_API_PREFIX')})")
	ap.add_argument("--forgejo-auth-scheme", default=None, help=f"Authorization scheme (default 'token') (env: {_env_key('FORGEJO_AUTH_SCHEME')})")
	ap.add_argument("--insecure-tls", action="store_true", default=None, help=f"Disable TLS verification for Forgejo API (env: {_env_key('INSECURE_TLS')})")
	ap.add_argument("--allow-dirty", action="store_true", default=None, help=f"Allow running with dirty git tree (env: {_env_key('ALLOW_DIRTY')})")
	return ap.parse_args()


def _resolve_env_args(args: argparse.Namespace) -> argparse.Namespace:
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
	args.commit_message = args.commit_message or _env_str("COMMIT_MESSAGE", "chore(krr): apply resource recommendations")

	args.pr = args.pr if args.pr is not None else _env_bool("PR", False)
	args.remote = args.remote or _env_str("REMOTE", "origin")
	args.pr_base = args.pr_base or _env_str("PR_BASE", "")
	args.pr_branch = args.pr_branch or _env_str("PR_BRANCH", "")
	pr_title_env = _env_get("PR_TITLE", "APPLY_KRR_PR_TITLE")
	args.pr_title = args.pr_title or pr_title_env or "chore(krr): apply resource recommendations"

	args.forgejo_url = args.forgejo_url or _env_str("FORGEJO_URL", "")
	args.forgejo_owner = args.forgejo_owner or _env_str("FORGEJO_OWNER", "")
	args.forgejo_repo = args.forgejo_repo or _env_str("FORGEJO_REPO", "")
	args.forgejo_token = args.forgejo_token or _env_get("FORGEJO_TOKEN", "APPLY_KRR_FORGEJO_TOKEN")
	args.forgejo_api_prefix = args.forgejo_api_prefix or _env_str("FORGEJO_API_PREFIX", "/api/v1")
	args.forgejo_auth_scheme = args.forgejo_auth_scheme or _env_str("FORGEJO_AUTH_SCHEME", "token")

	args.insecure_tls = args.insecure_tls if args.insecure_tls is not None else _env_bool("INSECURE_TLS", False)
	args.allow_dirty = args.allow_dirty if args.allow_dirty is not None else _env_bool("ALLOW_DIRTY", False)
	return args


def _apply_implied_flags(args: argparse.Namespace) -> None:
	if args.pr:
		args.write = True
		args.stage = True
		args.commit = True
	if args.commit:
		args.stage = True
	if args.stage:
		args.write = True


def _prepare_repo(args: argparse.Namespace) -> Tuple[Path, str, str]:
	repo_root = _ensure_repo(
		args.repo,
		repo_url=(args.repo_url or None),
		git_base_url=(args.git_base_url or None),
		clone_depth=args.clone_depth,
	)

	if _git_is_dirty(repo_root) and not args.allow_dirty:
		raise RuntimeError(
			f"working tree is dirty. Commit/stash first, or pass --allow-dirty / set {_env_key('ALLOW_DIRTY')}=1."
		)

	base_branch = args.pr_base.strip() or _git_current_branch(repo_root)
	head_branch = args.pr_branch.strip()
	if args.pr and not head_branch:
		ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
		head_branch = f"krr-resources-{ts}"

	if args.pr:
		_git_checkout_new(repo_root, head_branch, base_branch)

	return repo_root, base_branch, head_branch


def _build_hr_index(
	repo_root: Path,
	yaml_files: List[Path],
	*,
	chart_name: str,
	chartref_kind: str,
) -> Tuple[Dict[HrRef, List[HrDocLoc]], Dict[str, List[HrDocLoc]]]:
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
			if not _is_app_template_hr(doc, chart_name=chart_name, chartref_kind=chartref_kind):
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

	return hr_index, hr_index_by_name


def _apply_krr_to_repo(
	repo_root: Path,
	krr_map: Dict[TargetKey, RecommendedResources],
	hr_index: Dict[HrRef, List[HrDocLoc]],
	hr_index_by_name: Dict[str, List[HrDocLoc]],
	*,
	only_missing: bool,
	no_name_fallback: bool,
) -> Tuple[Dict[Path, YamlDocBundle], int, List[TargetKey], Dict[str, List[str]]]:
	changed_files: Dict[Path, YamlDocBundle] = {}
	total_changed_targets = 0
	unmatched: List[TargetKey] = []
	updated: List[str] = []
	skipped: List[str] = []

	def _ensure_loaded(fp: Path) -> YamlDocBundle:
		if fp in changed_files:
			return changed_files[fp]
		raw, docs, yaml = _read_all_yaml_docs(fp)
		changed_files[fp] = (raw, docs, yaml)
		return raw, docs, yaml

	for target, rec in krr_map.items():
		locs = hr_index.get(target.hr)

		if not locs and not no_name_fallback:
			cands = hr_index_by_name.get(target.hr.name, [])
			if len(cands) == 1:
				locs = cands
				print(f"NOTE: matched {target.hr.namespace}/{target.hr.name} by name-only (manifest likely missing metadata.namespace).")
			else:
				locs = None

		if not locs:
			unmatched.append(target)
			continue

		target_changed = False
		target_notes: List[str] = []
		for loc in locs:
			raw, docs, yaml = _ensure_loaded(loc.path)
			doc = docs[loc.doc_index]
			if not isinstance(doc, CommentedMap):
				continue

			changed, notes = _apply_to_hr_doc(
				doc,
				target=target,
				rec=rec,
				only_missing=only_missing,
			)

			if notes:
				print(f"- {target.hr.namespace}/{target.hr.name} controller={target.controller} container={target.container} @ {loc.path.relative_to(repo_root)}")
				for n in notes:
					print(f"	{n}")
				target_notes.extend(notes)

			if changed:
				total_changed_targets += 1
				target_changed = True
		target_id = f"{target.hr.namespace}/{target.hr.name} controller={target.controller} container={target.container}"
		if target_changed:
			updated.append(target_id)
		elif target_notes:
			reason = "; ".join(target_notes)
			skipped.append(f"{target_id} — {reason}")
		else:
			skipped.append(f"{target_id} — no changes needed")

	return changed_files, total_changed_targets, unmatched, {"updated": updated, "skipped": skipped}


def _format_pr_body(summary: Dict[str, List[str]], unmatched: List[TargetKey]) -> str:
	updated = summary.get("updated", [])
	skipped = summary.get("skipped", [])
	unmatched_items = [
		f"{t.hr.namespace}/{t.hr.name} controller={t.controller} container={t.container}"
		for t in unmatched
	]

	def _section(title: str, items: List[str], *, limit: int = 50) -> List[str]:
		if not items:
			return [f"### {title}", "_none_"]
		lines = [f"### {title}"]
		for item in items[:limit]:
			lines.append(f"- {item}")
		if len(items) > limit:
			lines.append(f"- … and {len(items) - limit} more")
		return lines

	lines = [
		"Automated update of Kubernetes resource requests/limits based on KRR output.",
		"",
		"## Summary",
		f"- Updated targets: {len(updated)}",
		f"- Skipped targets: {len(skipped)}",
		f"- Unmatched targets: {len(unmatched_items)}",
		"",
	]
	lines.extend(_section("Updated targets", updated))
	lines.append("")
	lines.extend(_section("Skipped targets", skipped))
	lines.append("")
	lines.extend(_section("Unmatched targets", unmatched_items))
	return "\n".join(lines)


def _format_cli_summary(summary: Dict[str, List[str]], unmatched: List[TargetKey]) -> str:
	updated = summary.get("updated", [])
	skipped = summary.get("skipped", [])
	unmatched_items = [
		f"{t.hr.namespace}/{t.hr.name} controller={t.controller} container={t.container}"
		for t in unmatched
	]

	def _section(title: str, items: List[str], *, limit: int = 50) -> List[str]:
		if not items:
			return [f"{title}: none"]
		lines = [f"{title}:"]
		for item in items[:limit]:
			lines.append(f"- {item}")
		if len(items) > limit:
			lines.append(f"- ... and {len(items) - limit} more")
		return lines

	lines = [
		"Summary:",
		f"- Updated targets: {len(updated)}",
		f"- Skipped targets: {len(skipped)}",
		f"- Unmatched targets: {len(unmatched_items)}",
		"",
	]
	lines.extend(_section("Updated targets", updated))
	lines.append("")
	lines.extend(_section("Skipped targets", skipped))
	lines.append("")
	lines.extend(_section("Unmatched targets", unmatched_items))
	return "\n".join(lines)


def _write_changes(
	repo_root: Path,
	changed_files: Dict[Path, YamlDocBundle],
	*,
	stage: bool,
	commit: bool,
	commit_message: str,
	forgejo_url: str,
) -> List[Path]:
	actually_changed: List[Path] = []
	for fp, (raw, docs, yaml) in changed_files.items():
		new_txt = _dump_all_yaml_docs(yaml, docs)
		if new_txt != raw:
			fp.write_text(new_txt, encoding="utf-8")
			actually_changed.append(fp)

	print(f"\nWROTE: updated {len(actually_changed)} file(s).")

	if stage and actually_changed:
		rel_paths = [str(p.relative_to(repo_root)) for p in actually_changed]
		_run_git(repo_root, ["add", "--", *rel_paths])
		print("STAGED: git add on changed files.")

	if commit and actually_changed:
		_ensure_git_identity(repo_root, forgejo_url=forgejo_url)
		_run_git(repo_root, ["commit", "-m", commit_message])
		print("COMMITTED.")

	return actually_changed


def _maybe_create_pr(
	args: argparse.Namespace,
	repo_root: Path,
	*,
	base_branch: str,
	head_branch: str,
	had_changes: bool,
	summary: Dict[str, List[str]],
	unmatched: List[TargetKey],
) -> int:
	if not args.pr:
		return 0
	if not had_changes:
		print("PR SKIPPED: no changes written.")
		return 0

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
		existing = _forgejo_find_open_pr(
			repo,
			token=token,
			auth_scheme=args.forgejo_auth_scheme,
			base_branch=base_branch,
			head_branch=head_branch,
			insecure_tls=args.insecure_tls,
		)
		if existing:
			print(f"PR EXISTS: {existing}")
			return 0

		body = _format_pr_body(summary, unmatched)
		pr_url = _forgejo_create_pr(
			repo,
			token=token,
			auth_scheme=args.forgejo_auth_scheme,
			base_branch=base_branch,
			head_branch=head_branch,
			title=args.pr_title,
			body=body,
			insecure_tls=args.insecure_tls,
		)
	except Exception as e:
		print(f"ERROR: failed to create PR: {e}", file=sys.stderr)
		return 2

	print(f"PR CREATED: {pr_url}")
	return 0


def main() -> int:
	args = _parse_args()
	args = _resolve_env_args(args)

	if args.krr_json is None:
		print(f"ERROR: missing krr.json path. Provide --krr-json or set {_env_key('KRR_JSON')}", file=sys.stderr)
		return 2

	_apply_implied_flags(args)

	try:
		repo_root, base_branch, head_branch = _prepare_repo(args)
	except Exception as e:
		print(f"ERROR: {e}", file=sys.stderr)
		return 2

	krr_map = _aggregate_krr(args.krr_json, min_severity=args.min_severity)
	if not krr_map:
		print("No applicable KRR entries found (after severity filter, or missing Flux labels).", file=sys.stderr)
		return 2

	yaml_files = _git_ls_yaml_files(repo_root)
	if not yaml_files:
		print("No tracked YAML files found in repo.", file=sys.stderr)
		return 2

	hr_index, hr_index_by_name = _build_hr_index(
		repo_root,
		yaml_files,
		chart_name=args.chart_name,
		chartref_kind=args.chartref_kind,
	)

	if not hr_index:
		print("No app-template HelmReleases found in repo (matching chartRef/chart name).", file=sys.stderr)
		return 2

	changed_files, total_changed_targets, unmatched, summary = _apply_krr_to_repo(
		repo_root,
		krr_map,
		hr_index,
		hr_index_by_name,
		only_missing=args.only_missing,
		no_name_fallback=args.no_name_fallback,
	)

	if unmatched:
		print("\nUnmatched KRR targets:", file=sys.stderr)
		for t in unmatched[:200]:
			print(f"	- {t.hr.namespace}/{t.hr.name} controller={t.controller} container={t.container}", file=sys.stderr)

	print("\n" + _format_cli_summary(summary, unmatched))

	if total_changed_targets == 0:
		print("\nNo changes needed.")
		return 0

	if not args.write:
		print(f"\nDRY-RUN: would update {len(changed_files)} file(s), {total_changed_targets} target(s). Use --write or set {_env_key('WRITE')}=1.")
		return 0

	actually_changed = _write_changes(
		repo_root,
		changed_files,
		stage=args.stage,
		commit=args.commit,
		commit_message=args.commit_message,
		forgejo_url=args.forgejo_url,
	)
	if not actually_changed and args.pr:
		print("No changes written; skipping PR.")
		return 0

	pr_status = _maybe_create_pr(
		args,
		repo_root,
		base_branch=base_branch,
		head_branch=head_branch,
		had_changes=bool(actually_changed),
		summary=summary,
		unmatched=unmatched,
	)
	if pr_status != 0:
		return pr_status

	return 0
