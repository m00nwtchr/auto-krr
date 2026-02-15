from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from .types import ResourceRef


def _is_helmrelease(doc: Any) -> bool:
	if not isinstance(doc, dict):
		return False
	if str(doc.get("kind", "")) != "HelmRelease":
		return False
	api = str(doc.get("apiVersion", ""))
	return api.startswith("helm.toolkit.fluxcd.io/")


def _resource_ref_from_doc(doc: Dict[str, Any]) -> ResourceRef:
	meta = doc.get("metadata") or {}
	name = str(meta.get("name") or "")
	ns = str(meta.get("namespace") or "")
	if not ns:
		ns = "default"
	kind = str(doc.get("kind") or "")
	return ResourceRef(kind=kind, namespace=ns, name=name)


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


def _chart_name_from_hr(doc: Dict[str, Any]) -> Optional[str]:
	spec = doc.get("spec") or {}

	chart_ref = spec.get("chartRef") or {}
	if isinstance(chart_ref, dict):
		cr_name = str(chart_ref.get("name") or "")
		if cr_name:
			return cr_name

	chart = spec.get("chart") or {}
	if isinstance(chart, dict):
		chart_spec = chart.get("spec") or {}
		if isinstance(chart_spec, dict):
			ch = str(chart_spec.get("chart") or "")
			if ch:
				return ch

	return None
