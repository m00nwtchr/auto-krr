from __future__ import annotations

import argparse
import datetime
import os
import sys
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ruamel.yaml.comments import CommentedMap

from .env import _env_bool, _env_get, _env_key, _env_path, _env_str
from .forgejo import (
	_forgejo_create_pr,
	_forgejo_find_open_pr,
	_forgejo_find_open_pr_data,
	_forgejo_get_user,
	_forgejo_update_pr,
)
from .git_utils import (
	_detect_forgejo_from_remote,
	_ensure_git_http_auth,
	_ensure_git_identity,
	_ensure_repo,
	_git_checkout_new,
	_git_current_branch,
	_git_is_dirty,
	_git_ls_yaml_files,
	_git_push_set_upstream,
	_remote_url,
	_run_git,
	_set_git_verbose,
)
from .comment_targets import _find_krr_comment_targets
from .hr import _hr_ref_from_doc, _infer_namespace_from_path, _is_app_template_hr, _is_helmrelease
from .krr import _aggregate_krr
from .patching import HELM_VALUES_CONFIGS, _apply_to_resources_map
from .resources_matchers import CommentResourcesMatcher, HeuristicResourcesMatcher, HelmValuesResourcesMatcher, ResourcesMatcher, TargetMatch
from .types import CommentTargetKey, CommentTargetLoc, ForgejoRepo, HrDocLoc, HrRef, RecommendedResources, TargetKey, YamlDocBundle
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
	ap.add_argument("--verbose-git", action="store_true", default=None, help=f"Verbose git output (env: {_env_key('GIT_VERBOSE')})")
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
	args.verbose_git = args.verbose_git if args.verbose_git is not None else _env_bool("GIT_VERBOSE", False)
	return args


def _fmt_rel_path(repo_root: Path, fp: Path) -> str:
	try:
		return str(fp.relative_to(repo_root))
	except Exception:
		return str(fp)


def _record_yaml_warnings(
	repo_root: Path,
	fp: Path,
	op: str,
	caught: List[warnings.WarningMessage],
	yaml_issues: Dict[str, List[str]],
) -> None:
	if not caught:
		return
	items = yaml_issues.setdefault("warnings", [])
	path = _fmt_rel_path(repo_root, fp)
	for w in caught:
		category = getattr(w, "category", None)
		cat_name = category.__name__ if category else "Warning"
		items.append(f"{path}: {op}: {cat_name}: {w.message}")


def _record_yaml_error(
	repo_root: Path,
	fp: Path,
	op: str,
	err: Exception,
	yaml_issues: Dict[str, List[str]],
) -> None:
	items = yaml_issues.setdefault("errors", [])
	path = _fmt_rel_path(repo_root, fp)
	items.append(f"{path}: {op}: {type(err).__name__}: {err}")


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
	yaml_issues: Dict[str, List[str]],
) -> Tuple[Dict[HrRef, List[HrDocLoc]], Dict[str, List[HrDocLoc]], Dict[CommentTargetKey, List[CommentTargetLoc]]]:
	hr_index: Dict[HrRef, List[HrDocLoc]] = {}
	hr_index_by_name: Dict[str, List[HrDocLoc]] = {}
	comment_index: Dict[CommentTargetKey, List[CommentTargetLoc]] = {}

	for fp in yaml_files:
		try:
			with warnings.catch_warnings(record=True) as caught:
				warnings.simplefilter("always")
				_, docs, _ = _read_all_yaml_docs(fp)
			_record_yaml_warnings(repo_root, fp, "read", caught, yaml_issues)
		except Exception as e:
			_record_yaml_error(repo_root, fp, "read", e, yaml_issues)
			continue

		for i, doc in enumerate(docs):
			for match in _find_krr_comment_targets(doc):
				key = CommentTargetKey(controller=match.controller, container=match.container)
				loc = CommentTargetLoc(path=fp, doc_index=i, resources_path=match.resources_path)
				comment_index.setdefault(key, []).append(loc)

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

	return hr_index, hr_index_by_name, comment_index


def _apply_krr_to_repo(
	repo_root: Path,
	krr_map: Dict[TargetKey, RecommendedResources],
	comment_map: Dict[CommentTargetKey, RecommendedResources],
	hr_index: Dict[HrRef, List[HrDocLoc]],
	hr_index_by_name: Dict[str, List[HrDocLoc]],
	comment_index: Dict[CommentTargetKey, List[CommentTargetLoc]],
	*,
	chart_name: str,
	only_missing: bool,
	no_name_fallback: bool,
	yaml_issues: Dict[str, List[str]],
) -> Tuple[Dict[Path, YamlDocBundle], int, List[str], Dict[str, List[str]]]:
	changed_files: Dict[Path, YamlDocBundle] = {}
	total_changed_targets = 0
	unmatched: List[str] = []
	updated: List[str] = []
	skipped: List[str] = []

	def _ensure_loaded(fp: Path) -> Optional[YamlDocBundle]:
		if fp in changed_files:
			return changed_files[fp]
		try:
			with warnings.catch_warnings(record=True) as caught:
				warnings.simplefilter("always")
				raw, docs, yaml = _read_all_yaml_docs(fp)
			_record_yaml_warnings(repo_root, fp, "read", caught, yaml_issues)
		except Exception as e:
			_record_yaml_error(repo_root, fp, "read", e, yaml_issues)
			return None
		changed_files[fp] = (raw, docs, yaml)
		return raw, docs, yaml

	config = HELM_VALUES_CONFIGS.get(chart_name)
	if config:
		helm_values_matcher: ResourcesMatcher = HelmValuesResourcesMatcher(
			hr_index=hr_index,
			hr_index_by_name=hr_index_by_name,
			no_name_fallback=no_name_fallback,
			config=config,
		)
	else:
		helm_values_matcher = HeuristicResourcesMatcher(
			hr_index=hr_index,
			hr_index_by_name=hr_index_by_name,
			no_name_fallback=no_name_fallback,
		)
	comment_matcher = CommentResourcesMatcher(comment_index=comment_index, repo_root=repo_root)

	matched_targets: set[str] = set()
	seen_resources: set[tuple[str, int, int]] = set()
	total_changed_targets += _apply_with_matcher(
		matcher=helm_values_matcher,
		rec_map=krr_map,
		ensure_loaded=_ensure_loaded,
		only_missing=only_missing,
		repo_root=repo_root,
		matched_targets=matched_targets,
		seen_resources=seen_resources,
		updated=updated,
		skipped=skipped,
	)

	total_changed_targets += _apply_with_matcher(
		matcher=comment_matcher,
		rec_map=comment_map,
		ensure_loaded=_ensure_loaded,
		only_missing=only_missing,
		repo_root=repo_root,
		matched_targets=None,
		seen_resources=seen_resources,
		updated=updated,
		skipped=skipped,
	)

	unmatched = [
		helm_values_matcher.describe_target(target)
		for target in krr_map.keys()
		if helm_values_matcher.describe_target(target) not in matched_targets
	]

	return changed_files, total_changed_targets, unmatched, {"updated": updated, "skipped": skipped}


def _apply_with_matcher(
	*,
	matcher: ResourcesMatcher,
	rec_map: Dict[object, RecommendedResources],
	ensure_loaded,
	only_missing: bool,
	repo_root: Path,
	matched_targets: Optional[set[str]],
	seen_resources: set[tuple[str, int, int]],
	updated: List[str],
	skipped: List[str],
) -> int:
	changed_targets = 0

	for target_match in matcher.iter_targets(rec_map):
		target = target_match.target_key
		target_id = matcher.describe_target(target)

		if target_match.rec is None:
			skipped.append(f"{target_id} — no KRR match")
			continue

		if not target_match.match or not target_match.match.locs:
			if matched_targets is None:
				skipped.append(f"{target_id} — no matching resources")
			continue

		if matched_targets is not None:
			matched_targets.add(target_id)

		for note in target_match.match.info_notes:
			print(note)

		outcomes = _apply_to_target_matches(
			matcher=matcher,
			target_match=target_match,
			target_id=target_id,
			ensure_loaded=ensure_loaded,
			only_missing=only_missing,
			repo_root=repo_root,
			seen_resources=seen_resources,
		)

		if matcher.summarize_per_match:
			for outcome in outcomes:
				if outcome.changed:
					updated.append(outcome.label)
					changed_targets += 1
				elif outcome.notes:
					reason = "; ".join(outcome.notes)
					skipped.append(f"{outcome.label} — {reason}")
				else:
					skipped.append(f"{outcome.label} — no changes needed")
		else:
			target_changed = any(outcome.changed for outcome in outcomes)
			target_notes = []
			for outcome in outcomes:
				target_notes.extend(outcome.notes)
			if target_changed:
				updated.append(target_id)
				changed_targets += 1
			elif target_notes:
				reason = "; ".join(target_notes)
				skipped.append(f"{target_id} — {reason}")
			else:
				skipped.append(f"{target_id} — no changes needed")

	return changed_targets


class _MatchOutcome:
	def __init__(self, label: str, changed: bool, notes: List[str]) -> None:
		self.label = label
		self.changed = changed
		self.notes = notes


def _apply_to_target_matches(
	*,
	matcher: ResourcesMatcher,
	target_match: TargetMatch,
	target_id: str,
	ensure_loaded,
	only_missing: bool,
	repo_root: Path,
	seen_resources: set[tuple[str, int, int]],
) -> List[_MatchOutcome]:
	outcomes: List[_MatchOutcome] = []

	for loc in target_match.match.locs:
		loaded = ensure_loaded(loc.path)
		if loaded is None:
			label = target_id
			notes = [f"yaml read failed @ {loc.path.relative_to(repo_root)}"]
			outcomes.append(_MatchOutcome(label, False, notes))
			continue
		raw, docs, yaml = loaded
		doc = docs[loc.doc_index]
		if not isinstance(doc, CommentedMap):
			label = target_id
			notes = [f"SKIP: document is not a mapping @ {loc.path.relative_to(repo_root)}"]
			outcomes.append(_MatchOutcome(label, False, notes))
			continue

		label = matcher.describe_match(target_match.target_key, doc)
		resources, _, resolver_notes = matcher.resolve_resources(doc, target_match.target_key, loc)
		if resolver_notes:
			print(f"- {label} @ {loc.path.relative_to(repo_root)}")
			for n in resolver_notes:
				print(f"\t{n}")
		combined_notes = list(resolver_notes)

		if resources is None:
			if not combined_notes:
				combined_notes.append("SKIP: matched workload but no resources block found")
			outcomes.append(_MatchOutcome(label, False, combined_notes))
			continue
		res_key = (str(loc.path), loc.doc_index, id(resources))
		if res_key in seen_resources:
			combined_notes.append("SKIP: resources block already matched")
			outcomes.append(_MatchOutcome(label, False, combined_notes))
			continue
		seen_resources.add(res_key)

		changed, res_notes = _apply_to_resources_map(
			resources,
			rec=target_match.rec,
			only_missing=only_missing,
		)

		if res_notes:
			print(f"- {label} @ {loc.path.relative_to(repo_root)}")
			for n in res_notes:
				print(f"\t{n}")
			combined_notes.extend(res_notes)

		outcomes.append(_MatchOutcome(label, changed, combined_notes))

	return outcomes


def _format_pr_body(summary: Dict[str, List[str]], unmatched: List[str]) -> str:
	updated = summary.get("updated", [])
	skipped = summary.get("skipped", [])
	yaml_warnings = summary.get("yaml_warnings", [])
	yaml_errors = summary.get("yaml_errors", [])
	unmatched_items = list(unmatched)

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
	lines.append("")
	lines.extend(_section("YAML warnings", yaml_warnings))
	lines.append("")
	lines.extend(_section("YAML errors", yaml_errors))
	return "\n".join(lines)


def _expected_pr_authors(*, forgejo_user: Optional[Dict[str, object]] = None) -> set[str]:
	authors: set[str] = set()
	if forgejo_user:
		for key in ("login", "username"):
			val = forgejo_user.get(key)
			if isinstance(val, str) and val.strip():
				authors.add(val.strip().lower())
	for key in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
		val = (os.environ.get(key) or "").strip()
		if val:
			authors.add(val.lower())
	for key in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
		email = (os.environ.get(key) or "").strip()
		if email and "@" in email:
			authors.add(email.split("@", 1)[0].lower())
	return authors


def _format_cli_summary(summary: Dict[str, List[str]], unmatched: List[str]) -> str:
	updated = summary.get("updated", [])
	skipped = summary.get("skipped", [])
	yaml_warnings = summary.get("yaml_warnings", [])
	yaml_errors = summary.get("yaml_errors", [])
	unmatched_items = list(unmatched)

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
	lines.append("")
	lines.extend(_section("YAML warnings", yaml_warnings))
	lines.append("")
	lines.extend(_section("YAML errors", yaml_errors))
	return "\n".join(lines)


def _write_changes(
	repo_root: Path,
	changed_files: Dict[Path, YamlDocBundle],
	*,
	stage: bool,
	commit: bool,
	commit_message: str,
	forgejo_url: str,
	yaml_issues: Dict[str, List[str]],
) -> List[Path]:
	actually_changed: List[Path] = []
	for fp, (raw, docs, yaml) in changed_files.items():
		try:
			with warnings.catch_warnings(record=True) as caught:
				warnings.simplefilter("always")
				new_txt = _dump_all_yaml_docs(yaml, docs)
			_record_yaml_warnings(repo_root, fp, "dump", caught, yaml_issues)
		except Exception as e:
			_record_yaml_error(repo_root, fp, "dump", e, yaml_issues)
			raise
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

	if token:
		_ensure_git_http_auth(repo_root, args.remote, token=token, auth_scheme=args.forgejo_auth_scheme)

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
			_run_git(repo_root, ["checkout", head_branch])
			_run_git(repo_root, ["fetch", args.remote, base_branch])
			try:
				_run_git(repo_root, ["rebase", f"{args.remote}/{base_branch}"])
			except Exception:
				_run_git(repo_root, ["rebase", "--abort"], check=False)
				_run_git(repo_root, ["reset", "--hard", f"{args.remote}/{base_branch}"])
				print("REBASE CONFLICT: discarded local changes, will re-apply.")
				return 3
			_git_push_set_upstream(repo_root, args.remote, head_branch)
			print(f"PUSHED: {args.remote}/{head_branch}")
			body = _format_pr_body(summary, unmatched)
			pr_data = _forgejo_find_open_pr_data(
				repo,
				token=token,
				auth_scheme=args.forgejo_auth_scheme,
				base_branch=base_branch,
				head_branch=head_branch,
				insecure_tls=args.insecure_tls,
			)
			if pr_data and isinstance(pr_data.get("number"), int):
				author = ""
				user = pr_data.get("user") or {}
				if isinstance(user, dict):
					author = str(user.get("login") or user.get("username") or "")
				forgejo_user = _forgejo_get_user(
					repo,
					token=token,
					auth_scheme=args.forgejo_auth_scheme,
					insecure_tls=args.insecure_tls,
				)
				allowed = _expected_pr_authors(forgejo_user=forgejo_user)
				if author and author.lower() in allowed:
					pr_url = _forgejo_update_pr(
						repo,
						token=token,
						auth_scheme=args.forgejo_auth_scheme,
						pr_number=pr_data["number"],
						body=body,
						insecure_tls=args.insecure_tls,
					)
					print(f"PR UPDATED: {pr_url}")
				else:
					print("PR EXISTS: not updating (author mismatch).")
			print(f"PR EXISTS: {existing}")
			return 0

		_git_push_set_upstream(repo_root, args.remote, head_branch)
		print(f"PUSHED: {args.remote}/{head_branch}")

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
	_set_git_verbose(args.verbose_git)

	if args.krr_json is None:
		print(f"ERROR: missing krr.json path. Provide --krr-json or set {_env_key('KRR_JSON')}", file=sys.stderr)
		return 2

	_apply_implied_flags(args)

	try:
		repo_root, base_branch, head_branch = _prepare_repo(args)
	except Exception as e:
		print(f"ERROR: {e}", file=sys.stderr)
		return 2

	krr_map, comment_map = _aggregate_krr(args.krr_json, min_severity=args.min_severity)
	if not krr_map and not comment_map:
		print("No applicable KRR entries found (after severity filter).", file=sys.stderr)
		return 2

	yaml_files = _git_ls_yaml_files(repo_root)
	if not yaml_files:
		print("No tracked YAML files found in repo.", file=sys.stderr)
		return 2

	def _run_apply_and_pr() -> int:
		yaml_issues: Dict[str, List[str]] = {"warnings": [], "errors": []}

		hr_index, hr_index_by_name, comment_index = _build_hr_index(
			repo_root,
			yaml_files,
			chart_name=args.chart_name,
			chartref_kind=args.chartref_kind,
			yaml_issues=yaml_issues,
		)

		changed_files, total_changed_targets, unmatched, summary = _apply_krr_to_repo(
			repo_root,
			krr_map,
			comment_map,
			hr_index,
			hr_index_by_name,
			comment_index,
			chart_name=args.chart_name,
			only_missing=args.only_missing,
			no_name_fallback=args.no_name_fallback,
			yaml_issues=yaml_issues,
		)
		summary["yaml_warnings"] = yaml_issues.get("warnings", [])
		summary["yaml_errors"] = yaml_issues.get("errors", [])

		if unmatched:
			print("\nUnmatched KRR targets:", file=sys.stderr)
			for t in unmatched[:200]:
				print(f"	- {t}", file=sys.stderr)

		if total_changed_targets == 0:
			print("\n" + _format_cli_summary(summary, unmatched))
			print("\nNo changes needed.")
			return 0

		if not args.write:
			print("\n" + _format_cli_summary(summary, unmatched))
			print(f"\nDRY-RUN: would update {len(changed_files)} file(s), {total_changed_targets} target(s). Use --write or set {_env_key('WRITE')}=1.")
			return 0

		actually_changed = _write_changes(
			repo_root,
			changed_files,
			stage=args.stage,
			commit=args.commit,
			commit_message=args.commit_message,
			forgejo_url=args.forgejo_url,
			yaml_issues=yaml_issues,
		)
		summary["yaml_warnings"] = yaml_issues.get("warnings", [])
		summary["yaml_errors"] = yaml_issues.get("errors", [])
		print("\n" + _format_cli_summary(summary, unmatched))
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
		return pr_status

	for _ in range(2):
		pr_status = _run_apply_and_pr()
		if pr_status != 3:
			return pr_status

	return 0
