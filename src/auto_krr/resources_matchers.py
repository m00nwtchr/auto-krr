from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Protocol, Tuple

from ruamel.yaml.comments import CommentedMap

from .patching import HelmValuesConfig, _resolve_helm_values_resources
from .types import CommentTargetKey, CommentTargetLoc, HrDocLoc, HrRef, RecommendedResources


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


class HelmValuesResourcesMatcher:
	name = "helm-values"
	summarize_per_match = False

	def __init__(
		self,
		*,
		hr_index: Dict[HrRef, List[HrDocLoc]],
		hr_index_by_name: Dict[str, List[HrDocLoc]],
		no_name_fallback: bool,
		config: HelmValuesConfig,
	) -> None:
		self._hr_index = hr_index
		self._hr_index_by_name = hr_index_by_name
		self._no_name_fallback = no_name_fallback
		self._config = config

	def iter_targets(self, rec_map: Dict[object, RecommendedResources]) -> Iterable[TargetMatch]:
		for target, rec in rec_map.items():
			locs = self._hr_index.get(target.hr)
			info_notes: List[str] = []

			if not locs and not self._no_name_fallback:
				cands = self._hr_index_by_name.get(target.hr.name, [])
				if len(cands) == 1:
					locs = cands
					info_notes.append(
						f"NOTE: matched {target.hr.namespace}/{target.hr.name} by name-only (manifest likely missing metadata.namespace)."
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
		return _format_match_label(
			kind="HelmRelease",
			namespace=target.hr.namespace,
			name=target.hr.name,
			controller=target.controller,
			container=target.container,
			matcher=self.name,
		)

	def describe_match(self, target_key: object, doc: CommentedMap) -> str:
		target = target_key
		kind, namespace, name = _resource_identity(doc)
		return _format_match_label(
			kind=kind or "HelmRelease",
			namespace=namespace or target.hr.namespace,
			name=name or target.hr.name,
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
		return _resolve_helm_values_resources(doc, target=target, create_missing=True, config=self._config)


class HeuristicResourcesMatcher:
	name = "helm-values-heuristic"
	summarize_per_match = False

	def __init__(
		self,
		*,
		hr_index: Dict[HrRef, List[HrDocLoc]],
		hr_index_by_name: Dict[str, List[HrDocLoc]],
		no_name_fallback: bool,
	) -> None:
		self._hr_index = hr_index
		self._hr_index_by_name = hr_index_by_name
		self._no_name_fallback = no_name_fallback
		self._target_counts_by_hr: Dict[HrRef, int] = {}

	def iter_targets(self, rec_map: Dict[object, RecommendedResources]) -> Iterable[TargetMatch]:
		# TODO: heuristic matching for resources blocks when no chart config is available.
		self._target_counts_by_hr = {}
		for target in rec_map.keys():
			self._target_counts_by_hr[target.hr] = self._target_counts_by_hr.get(target.hr, 0) + 1

		for target, rec in rec_map.items():
			locs = self._hr_index.get(target.hr)
			info_notes: List[str] = []

			if not locs and not self._no_name_fallback:
				cands = self._hr_index_by_name.get(target.hr.name, [])
				if len(cands) == 1:
					locs = cands
					info_notes.append(
						f"NOTE: matched {target.hr.namespace}/{target.hr.name} by name-only (manifest likely missing metadata.namespace)."
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
		return _format_match_label(
			kind="HelmRelease",
			namespace=target.hr.namespace,
			name=target.hr.name,
			controller=target.controller,
			container=target.container,
			matcher=self.name,
		)

	def describe_match(self, target_key: object, doc: CommentedMap) -> str:
		target = target_key
		kind, namespace, name = _resource_identity(doc)
		return _format_match_label(
			kind=kind or "HelmRelease",
			namespace=namespace or target.hr.namespace,
			name=name or target.hr.name,
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
		count = self._target_counts_by_hr.get(target.hr, 0)
		if count != 1:
			return None, False, ["SKIP: heuristic requires a single workload for this HelmRelease"]

		spec = doc.get("spec")
		if not isinstance(spec, CommentedMap):
			return None, False, ["SKIP: spec is not a mapping"]

		values = spec.get("values")
		if not isinstance(values, CommentedMap):
			return None, False, ["SKIP: spec.values is not a mapping"]

		resources = values.get("resources")
		if not isinstance(resources, CommentedMap):
			return None, False, ["SKIP: spec.values.resources is not a mapping"]

		return resources, False, []


class CommentResourcesMatcher:
	name = "comment"
	summarize_per_match = True

	def __init__(self, *, comment_index: Dict[CommentTargetKey, List[CommentTargetLoc]], repo_root: Path) -> None:
		self._comment_index = comment_index
		self._repo_root = repo_root

	def iter_targets(self, rec_map: Dict[object, RecommendedResources]) -> Iterable[TargetMatch]:
		for target, locs in self._comment_index.items():
			rec = rec_map.get(target)
			match = MatchResult(
				locs=[
					ResourcesMatch(path=loc.path, doc_index=loc.doc_index, resources_path=loc.resources_path)
					for loc in locs
				],
				info_notes=[],
			)
			yield TargetMatch(target_key=target, rec=rec, match=match)

	def describe_target(self, target_key: object) -> str:
		target = target_key
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
		kind, namespace, name = _resource_identity(doc)
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
	return f"{kind_label} {ns_label}/{name_label} controller={controller} container={container} ({matcher})"
