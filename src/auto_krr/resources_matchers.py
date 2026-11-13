from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Protocol, Tuple

from ruamel.yaml.comments import CommentedMap

from .flate_discovery import FlateDiscovery
from .patching import _resolve_resources_path
from .types import CommentTargetLoc, HrDocLoc, RecommendedResources, ResourceRef, TargetKey


@dataclass(frozen=True)
class ResourcesMatch:
	path: Path
	doc_index: int
	resources_path: Optional[List[object]] = None


@dataclass(frozen=True)
class MatchResult:
	locs: List[ResourcesMatch]
	info_notes: List[str]


@dataclass(frozen=True)
class TargetMatch:
	target_key: object
	rec: Optional[RecommendedResources]
	match: Optional[MatchResult]
	matched_targets: Optional[List[TargetKey]] = None


class ResourcesMatcher(Protocol):
	name: str
	summarize_per_match: bool

	def iter_targets(self, rec_map: Dict[object, RecommendedResources]) -> Iterable[TargetMatch]:
		...

	def describe_target(self, target_key: object) -> str:
		...

	def describe_match(self, target_key: object, doc: CommentedMap) -> str:
		...

	def resolve_resources(
		self,
		doc: CommentedMap,
		target_key: object,
		match: ResourcesMatch,
	) -> Tuple[Optional[CommentedMap], bool, List[str]]:
		...


class HelmReleaseMatcher:
	name = "helmrelease"
	summarize_per_match = False

	def __init__(
		self,
		*,
		repo_root: Path,
		hr_index: Dict[ResourceRef, List[HrDocLoc]],
		hr_index_by_name: Dict[str, List[HrDocLoc]],
		no_name_fallback: bool,
		discovery: Optional[FlateDiscovery] = None,
		flate_bin: str = "flate",
		helm_bin: str = "helm",
	) -> None:
		self._repo_root = repo_root
		self._hr_index = hr_index
		self._hr_index_by_name = hr_index_by_name
		self._no_name_fallback = no_name_fallback
		self._discovery = discovery or FlateDiscovery(repo_root, flate_bin=flate_bin, helm_bin=helm_bin)
		self._discovery_results: Dict[Tuple[str, int], object] = {}

	def iter_targets(self, rec_map: Dict[object, RecommendedResources]) -> Iterable[TargetMatch]:
		for target, rec in rec_map.items():
			if not isinstance(target, TargetKey) or target.resource is None:
				continue
			if target.resource.kind != "HelmRelease":
				continue
			locs = self._hr_index.get(target.resource)
			info_notes: List[str] = []

			if not locs and not self._no_name_fallback:
				cands = self._hr_index_by_name.get(target.resource.name, [])
				if len(cands) == 1:
					locs = cands
					info_notes.append(
						f"NOTE: matched {target.resource.namespace}/{target.resource.name} by name-only (manifest likely missing metadata.namespace)."
					)
				else:
					locs = None

			match = None
			if locs:
				match = MatchResult(
					locs=[ResourcesMatch(path=loc.path, doc_index=loc.doc_index) for loc in locs],
					info_notes=info_notes,
				)
			yield TargetMatch(target_key=target, rec=rec, match=match)

	def describe_target(self, target_key: object) -> str:
		target = target_key
		if not isinstance(target, TargetKey) or target.resource is None:
			raise ValueError("helmrelease matcher requires TargetKey with resource set")
		if target.resource.kind != "HelmRelease":
			raise ValueError("helmrelease matcher requires HelmRelease targets")
		return _format_match_label(
			kind=target.resource.kind,
			namespace=target.resource.namespace,
			name=target.resource.name,
			controller=target.controller,
			container=target.container,
			matcher=self.name,
		)

	def describe_match(self, target_key: object, doc: CommentedMap) -> str:
		target = target_key
		if not isinstance(target, TargetKey) or target.resource is None:
			raise ValueError("helmrelease matcher requires TargetKey with resource set")
		if target.resource.kind != "HelmRelease":
			raise ValueError("helmrelease matcher requires HelmRelease targets")
		return _format_match_label(
			kind=target.resource.kind,
			namespace=target.resource.namespace,
			name=target.resource.name,
			controller=target.controller,
			container=target.container,
			matcher=self.name,
		)

	def resolve_resources(
		self,
		doc: CommentedMap,
		target_key: object,
		match: ResourcesMatch,
	) -> Tuple[Optional[CommentedMap], bool, List[str]]:
		target = target_key
		if not isinstance(target, TargetKey) or target.resource is None:
			raise ValueError("helmrelease matcher requires TargetKey with resource set")
		if target.resource.kind != "HelmRelease":
			raise ValueError("helmrelease matcher requires HelmRelease targets")
		cache_key = (str(match.path.resolve()), match.doc_index)
		result = self._discovery_results.get(cache_key)
		if result is None:
			result = self._discovery.discover(HrDocLoc(path=match.path, doc_index=match.doc_index, doc=doc))
			self._discovery_results[cache_key] = result
		path_for = getattr(result, "path_for")
		resources_path = path_for(target.controller, target.container)
		if resources_path is None:
			notes = list(getattr(result, "notes", []))
			if not notes:
				notes.append(
					f"SKIP: flate did not map workload/container {target.controller}/{target.container}"
			)
			return None, False, notes
		resources, changed, path_notes = _resolve_resources_path(doc, resources_path, create_missing=True)
		return resources, changed, list(getattr(result, "notes", [])) + path_notes


class CommentResourcesMatcher:
	name = "comment"
	summarize_per_match = True

	def __init__(self, *, comment_index: Dict[TargetKey, List[CommentTargetLoc]], repo_root: Path) -> None:
		self._comment_index = comment_index
		self._repo_root = repo_root

	def iter_targets(self, rec_map: Dict[object, RecommendedResources]) -> Iterable[TargetMatch]:
		rec_index: Dict[Tuple[str, str], List[TargetKey]] = {}
		rec_bucket: Dict[Tuple[str, str], List[RecommendedResources]] = {}
		for key, rec in rec_map.items():
			if not isinstance(key, TargetKey):
				continue
			bucket_key = (key.controller, key.container)
			rec_index.setdefault(bucket_key, []).append(key)
			rec_bucket.setdefault(bucket_key, []).append(rec)

		for target, locs in self._comment_index.items():
			if not isinstance(target, TargetKey):
				continue
			bucket_key = (target.controller, target.container)
			recs = rec_bucket.get(bucket_key, [])
			rec = _merge_recs(recs) if recs else None
			matched_targets = rec_index.get(bucket_key, [])
			match = MatchResult(
				locs=[
					ResourcesMatch(path=loc.path, doc_index=loc.doc_index, resources_path=loc.resources_path)
					for loc in locs
				],
				info_notes=[],
			)
			yield TargetMatch(target_key=target, rec=rec, match=match, matched_targets=matched_targets)

	def describe_target(self, target_key: object) -> str:
		target = target_key
		if not isinstance(target, TargetKey):
			raise ValueError("comment matcher requires TargetKey")
		if target.resource:
			return _format_match_label(
				kind=target.resource.kind,
				namespace=target.resource.namespace,
				name=target.resource.name,
				controller=target.controller,
				container=target.container,
				matcher=self.name,
			)
		return _format_match_label(
			kind="resource",
			namespace="unknown",
			name="unknown",
			controller=target.controller,
			container=target.container,
			matcher=self.name,
		)

	def describe_match(self, target_key: object, doc: CommentedMap) -> str:
		target = target_key
		kind = namespace = name = None
		if isinstance(target, TargetKey) and target.resource is not None:
			kind = target.resource.kind
			namespace = target.resource.namespace
			name = target.resource.name
		return _format_match_label(
			kind=kind or "resource",
			namespace=namespace or "default",
			name=name or "unknown",
			controller=target.controller,
			container=target.container,
			matcher=self.name,
		)

	def resolve_resources(
		self,
		doc: CommentedMap,
		target_key: object,
		match: ResourcesMatch,
	) -> Tuple[Optional[CommentedMap], bool, List[str]]:
		if not match.resources_path:
			return None, False, ["SKIP: resources path missing"]
		resources = _get_by_path(doc, match.resources_path)
		if not isinstance(resources, CommentedMap):
			rel = _fmt_rel_path(self._repo_root, match.path)
			return None, False, [f"SKIP: resources is not a mapping @ {rel}"]
		return resources, False, []


def _get_by_path(doc: object, path: List[object]) -> Optional[object]:
	cur: object = doc
	for part in path:
		if isinstance(part, int):
			if not isinstance(cur, list) or part >= len(cur):
				return None
			cur = cur[part]
		else:
			if not isinstance(cur, CommentedMap) or part not in cur:
				return None
			cur = cur[part]
	return cur


def _fmt_rel_path(repo_root: Path, fp: Path) -> str:
	try:
		return str(fp.relative_to(repo_root))
	except Exception:
		return str(fp)


def _resource_identity(doc: CommentedMap) -> Tuple[str, str, str]:
	kind = str(doc.get("kind") or "")
	meta = doc.get("metadata") or {}
	name = str(meta.get("name") or "")
	namespace = str(meta.get("namespace") or "")
	return kind, namespace, name


def _merge_max(a: Optional[float], b: Optional[float]) -> Optional[float]:
	if a is None:
		return b
	if b is None:
		return a
	return max(a, b)


def _merge_recs(recs: List[RecommendedResources]) -> RecommendedResources:
	out = RecommendedResources()
	for rec in recs:
		out.req_cpu_cores = _merge_max(out.req_cpu_cores, rec.req_cpu_cores)
		out.req_mem_bytes = _merge_max(out.req_mem_bytes, rec.req_mem_bytes)
		out.lim_cpu_cores = _merge_max(out.lim_cpu_cores, rec.lim_cpu_cores)
		out.lim_mem_bytes = _merge_max(out.lim_mem_bytes, rec.lim_mem_bytes)
		out.cur_req_cpu_cores = _merge_max(out.cur_req_cpu_cores, rec.cur_req_cpu_cores)
		out.cur_req_mem_bytes = _merge_max(out.cur_req_mem_bytes, rec.cur_req_mem_bytes)
		out.cur_lim_cpu_cores = _merge_max(out.cur_lim_cpu_cores, rec.cur_lim_cpu_cores)
		out.cur_lim_mem_bytes = _merge_max(out.cur_lim_mem_bytes, rec.cur_lim_mem_bytes)
	return out


def _format_match_label(
	*,
	kind: str,
	namespace: str,
	name: str,
	controller: str,
	container: str,
	matcher: str,
) -> str:
	kind_label = kind or "resource"
	ns_label = namespace or "default"
	name_label = name or "unknown"
	controller_label = ""
	if controller and controller != name_label:
		controller_label = f" controller={controller}"
	return f"{kind_label} {ns_label}/{name_label}{controller_label} container={container} ({matcher})"
