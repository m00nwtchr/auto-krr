from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .types import KrrTargetHint, RecommendedResources, ResourceRef, TargetKey


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
	alloc = (scan.get("object") or {}).get("allocations") or {}
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

	def _alloc(section: str, resource: str) -> Optional[float]:
		if not isinstance(alloc, dict):
			return None
		sec = alloc.get(section)
		if not isinstance(sec, dict):
			return None
		return _safe_float(sec.get(resource))

	out.req_cpu_cores = _num("requests", "cpu")
	out.req_mem_bytes = _num("requests", "memory")
	out.lim_cpu_cores = _num("limits", "cpu")
	out.lim_mem_bytes = _num("limits", "memory")
	out.cur_req_cpu_cores = _alloc("requests", "cpu")
	out.cur_req_mem_bytes = _alloc("requests", "memory")
	out.cur_lim_cpu_cores = _alloc("limits", "cpu")
	out.cur_lim_mem_bytes = _alloc("limits", "memory")
	return out


def _merge_max(a: Optional[float], b: Optional[float]) -> Optional[float]:
	if a is None:
		return b
	if b is None:
		return a
	return max(a, b)


def _aggregate_krr(
	json_path: Path,
	*,
	min_severity: str,
) -> Tuple[Dict[TargetKey, RecommendedResources], Dict[TargetKey, KrrTargetHint]]:
	data = json.loads(json_path.read_text(encoding="utf-8"))
	scans = data.get("scans") or []
	out: Dict[TargetKey, RecommendedResources] = {}
	hints: Dict[TargetKey, KrrTargetHint] = {}

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

		controller = obj.get("name") or (
			labels.get("app.kubernetes.io/controller")
			or labels.get("app.kubernetes.io/name")
			or labels.get("app.kubernetes.io/instance")
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

		res_ref = (
			ResourceRef(kind="HelmRelease", namespace=str(hr_ns), name=str(hr_name)) if hr_name and hr_ns else None
		)
		target_key = TargetKey(resource=res_ref, controller=controller, container=container)
		prev = out.get(target_key)
		if prev is None:
			out[target_key] = rec
		else:
			prev.req_cpu_cores = _merge_max(prev.req_cpu_cores, rec.req_cpu_cores)
			prev.req_mem_bytes = _merge_max(prev.req_mem_bytes, rec.req_mem_bytes)
			prev.lim_cpu_cores = _merge_max(prev.lim_cpu_cores, rec.lim_cpu_cores)
			prev.lim_mem_bytes = _merge_max(prev.lim_mem_bytes, rec.lim_mem_bytes)
			prev.cur_req_cpu_cores = _merge_max(prev.cur_req_cpu_cores, rec.cur_req_cpu_cores)
			prev.cur_req_mem_bytes = _merge_max(prev.cur_req_mem_bytes, rec.cur_req_mem_bytes)
			prev.cur_lim_cpu_cores = _merge_max(prev.cur_lim_cpu_cores, rec.cur_lim_cpu_cores)
			prev.cur_lim_mem_bytes = _merge_max(prev.cur_lim_mem_bytes, rec.cur_lim_mem_bytes)

		kind = str(obj.get("kind") or "") or None
		namespace = str(obj.get("namespace") or "") or None
		name = str(obj.get("name") or "") or None
		hints[target_key] = _merge_hint(hints.get(target_key), kind=kind, namespace=namespace, name=name)

	return out, hints


def _merge_hint(
	current: Optional[KrrTargetHint],
	*,
	kind: Optional[str],
	namespace: Optional[str],
	name: Optional[str],
) -> KrrTargetHint:
	if current is None:
		return KrrTargetHint(kind=kind, namespace=namespace, name=name)
	return KrrTargetHint(
		kind=_merge_hint_value(current.kind, kind),
		namespace=_merge_hint_value(current.namespace, namespace),
		name=_merge_hint_value(current.name, name),
	)


def _merge_hint_value(current: Optional[str], new: Optional[str]) -> Optional[str]:
	if current is None:
		return new
	if new is None:
		return current
	if current == new:
		return current
	return None
