from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ruamel.yaml.comments import CommentedMap

from .types import RecommendedResources, TargetKey
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


def _find_key_by_str(m: CommentedMap, wanted: str) -> Optional[object]:
	for k in m.keys():
		if str(k) == wanted:
			return k
	return None


def _pick_controller_key(controllers: CommentedMap, wanted: str, hr_name: str, config: HelmValuesConfig) -> Optional[object]:
	k = _find_key_by_str(controllers, wanted)
	if k is not None:
		return k
	for fb in config.controller_fallbacks:
		k = _find_key_by_str(controllers, fb)
		if k is not None:
			return k
	if config.allow_controller_name:
		k = _find_key_by_str(controllers, hr_name)
		if k is not None:
			return k
	if config.allow_single_controller and len(controllers.keys()) == 1:
		return next(iter(controllers.keys()))
	return None


def _pick_container_key(containers: CommentedMap, wanted: str, config: HelmValuesConfig) -> Optional[object]:
	k = _find_key_by_str(containers, wanted)
	if k is not None:
		return k
	for fb in config.container_fallbacks:
		k = _find_key_by_str(containers, fb)
		if k is not None:
			return k
	if config.allow_single_container and len(containers.keys()) == 1:
		return next(iter(containers.keys()))
	return None


def _apply_to_hr_doc(
	doc: CommentedMap,
	*,
	target: TargetKey,
	rec: RecommendedResources,
	only_missing: bool,
) -> Tuple[bool, List[str]]:
	resources, changed, notes = _resolve_helm_values_resources(
		doc,
		target=target,
		create_missing=True,
		config=HELM_VALUES_CONFIGS["app-template"],
	)
	if resources is None:
		return False, notes

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


@dataclass(frozen=True)
class HelmValuesConfig:
	"""Describe how to locate and update resources within a chart's Helm values."""
	# chart_name: name used in HelmRelease chartRef/spec to select this config.
	chart_name: str
	# controllers_path: path to the controllers map (e.g. spec.values.controllers).
	controllers_path: List[str]
	# containers_key: key holding containers under a controller.
	containers_key: str
	# resources_key: key to update under a container.
	resources_key: str
	# containers_after_keys: ordering hints when inserting resources.
	containers_after_keys: List[str]
	# controller_fallbacks: fallback controller names to try in order.
	controller_fallbacks: List[str]
	# container_fallbacks: fallback container names to try in order.
	container_fallbacks: List[str]
	# allow_controller_name: allow using the HelmRelease name as a controller fallback.
	allow_controller_name: bool
	# allow_single_controller: allow the only controller when there is a single entry.
	allow_single_controller: bool
	# allow_single_container: allow the only container when there is a single entry.
	allow_single_container: bool


HELM_VALUES_CONFIGS = {
	"app-template": HelmValuesConfig(
		chart_name="app-template",
		controllers_path=["spec", "values", "controllers"],
		containers_key="containers",
		resources_key="resources",
		containers_after_keys=["pod", "cronjob", "statefulset", "deployment", "type"],
		controller_fallbacks=["main"],
		container_fallbacks=["app", "main"],
		allow_controller_name=True,
		allow_single_controller=True,
		allow_single_container=True,
	),
}


def _resolve_helm_values_resources(
	doc: CommentedMap,
	*,
	target: TargetKey,
	create_missing: bool,
	config: HelmValuesConfig,
) -> Tuple[Optional[CommentedMap], bool, List[str]]:
	changed = False
	notes: List[str] = []

	controllers, path_changed, path_notes = _resolve_map_path(
		doc,
		path=config.controllers_path,
		create_missing=create_missing,
	)
	if path_notes:
		return None, changed or path_changed, path_notes
	changed = changed or path_changed
	if controllers is None:
		return None, changed, ["SKIP: spec.values.controllers is not a mapping"]

	resource_name = target.resource.name if target.resource else ""
	ctrl_key = _pick_controller_key(controllers, target.controller, resource_name, config)
	if ctrl_key is None:
		notes.append(f"SKIP: controller {target.controller!r} not found (controllers: {[str(k) for k in controllers.keys()]})")
		return None, changed, notes

	ctrl_def = controllers.get(ctrl_key)
	if not isinstance(ctrl_def, CommentedMap):
		if not create_missing:
			return None, changed, ["SKIP: controller definition is not a mapping"]
		ctrl_def = CommentedMap()
		controllers[ctrl_key] = ctrl_def
		changed = True

	containers = ctrl_def.get(config.containers_key)
	if not isinstance(containers, CommentedMap):
		return None, changed, [f"SKIP: {config.containers_key} is not a mapping"]

	ctr_key = _pick_container_key(containers, target.container, config)
	if ctr_key is None:
		notes.append(f"SKIP: container {target.container!r} not found (containers: {[str(k) for k in containers.keys()]})")
		return None, changed, notes

	ctr_def = containers.get(ctr_key)
	if not isinstance(ctr_def, CommentedMap):
		if not create_missing:
			return None, changed, ["SKIP: container definition is not a mapping"]
		ctr_def = CommentedMap()
		containers[ctr_key] = ctr_def
		changed = True

	resources = ctr_def.get(config.resources_key)
	if not isinstance(resources, CommentedMap):
		if not create_missing:
			return None, changed, [f"SKIP: {config.resources_key} is not a mapping"]
		resources = CommentedMap()
		_insert_alpha_if_missing(ctr_def, config.resources_key, resources)
		changed = True

	return resources, changed, notes


def _resolve_map_path(
	doc: CommentedMap,
	*,
	path: List[str],
	create_missing: bool,
) -> Tuple[Optional[CommentedMap], bool, List[str]]:
	changed = False
	cur: CommentedMap = doc
	for idx, key in enumerate(path):
		label = ".".join(path[: idx + 1])
		next_val = cur.get(key)
		if not isinstance(next_val, CommentedMap):
			if not create_missing:
				return None, changed, [f"SKIP: {label} is not a mapping"]
			next_val = CommentedMap()
			cur[key] = next_val
			changed = True
		cur = next_val
	return cur, changed, []


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
