from __future__ import annotations

import math
from collections.abc import MutableMapping
from typing import List, Optional, Tuple

from ruamel.yaml.comments import CommentedMap

from .types import RecommendedResources
from .yaml_utils import _insert_alpha_if_missing, _insert_if_missing


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


def _resolve_resources_path(
	doc: CommentedMap,
	path: List[object],
	create_missing: bool,
) -> Tuple[Optional[CommentedMap], bool, List[str]]:
	if not path:
		return None, False, ["SKIP: resources path is empty"]
	changed = False
	cur: object = doc
	for idx, part in enumerate(path):
		last = idx == len(path) - 1
		label = ".".join(str(item) for item in path[: idx + 1])
		if isinstance(part, int):
			if not isinstance(cur, list) or part < 0 or part >= len(cur):
				return None, changed, [f"SKIP: {label} is not an existing list item"]
			cur = cur[part]
			continue
		if not isinstance(cur, MutableMapping):
			return None, changed, [f"SKIP: {label} parent is not a mapping"]

		if part not in cur or cur[part] is None:
			if not create_missing:
				return None, changed, [f"SKIP: {label} is missing"]
			new_value = CommentedMap()
			if isinstance(cur, CommentedMap):
				if part in cur:
					cur[part] = new_value
				else:
					_insert_alpha_if_missing(cur, str(part), new_value)
			else:
				cur[part] = new_value
			cur = new_value
			changed = True
			continue

		value = cur[part]
		if last:
			if not isinstance(value, MutableMapping):
				return None, changed, [f"SKIP: {label} is not a mapping"]
			cur = value
			continue
		if not isinstance(value, (MutableMapping, list)):
			return None, changed, [f"SKIP: {label} is not a mapping"]
		cur = value

	if isinstance(cur, CommentedMap):
		return cur, changed, []
	if isinstance(cur, MutableMapping):
		return CommentedMap(cur), changed, []
	return None, changed, ["SKIP: resources path does not resolve to a mapping"]


def _apply_to_hr_doc(
	doc: CommentedMap,
	*,
	resources_path: List[object],
	rec: RecommendedResources,
	only_missing: bool,
) -> Tuple[bool, List[str]]:
	resources, changed, notes = _resolve_resources_path(doc, resources_path, create_missing=True)
	if resources is None:
		return False, notes
	resource_changed, resource_notes = _apply_to_resources_map(resources, rec=rec, only_missing=only_missing)
	return changed or resource_changed, notes + resource_notes


def _apply_to_resources_map(
	resources: CommentedMap,
	*,
	rec: RecommendedResources,
	only_missing: bool,
) -> Tuple[bool, List[str]]:
	changed = False
	notes: List[str] = []

	def _set(section: str, field: str, new_val: str) -> None:
		nonlocal changed
		sec = resources.get(section)
		if not isinstance(sec, CommentedMap):
			sec = CommentedMap()
			if section in resources:
				resources[section] = sec
			else:
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
