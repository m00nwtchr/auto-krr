from __future__ import annotations

import math
from typing import List, Optional, Tuple

from ruamel.yaml.comments import CommentedMap

from .types import RecommendedResources, TargetKey
from .yaml_utils import _insert_if_missing


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


def _find_key_by_str(m: CommentedMap, wanted: str) -> Optional[object]:
	for k in m.keys():
		if str(k) == wanted:
			return k
	return None


def _pick_controller_key(controllers: CommentedMap, wanted: str, hr_name: str) -> Optional[object]:
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


def _pick_container_key(containers: CommentedMap, wanted: str) -> Optional[object]:
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
	resource_changed, resource_notes = _apply_to_resources_map(
		resources,
		rec=rec,
		only_missing=only_missing,
	)
	if resource_changed:
		changed = True
	if resource_notes:
		notes.extend(resource_notes)

	return changed, notes


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
