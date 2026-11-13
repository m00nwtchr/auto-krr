from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from .helm_values import (
	ChartRef,
	ChartCandidate,
	_enumerate_resource_candidates,
	_load_chart_values,
	_resolve_chart_ref,
)
from .hr import _infer_namespace_from_path
from .types import HrDocLoc
from .yaml_utils import _dump_all_yaml_docs, _read_all_yaml_docs


@dataclass
class DiscoveryResult:
	paths: Dict[Tuple[str, str], List[object]] = field(default_factory=dict)
	ambiguous: Dict[Tuple[str, str], List[List[object]]] = field(default_factory=dict)
	notes: List[str] = field(default_factory=list)

	def path_for(self, controller: str, container: str) -> Optional[List[object]]:
		path = self.paths.get((controller, container))
		return list(path) if path is not None else None


@dataclass(frozen=True)
class _Sentinel:
	path: List[object]
	values: Dict[str, str]


class FlateDiscovery:
	def __init__(self, repo_root: Path, flate_bin: str = "flate", helm_bin: str = "helm") -> None:
		self._repo_root = repo_root
		self._flate_bin = flate_bin
		self._helm_bin = helm_bin
		self._results: Dict[Tuple[str, int], DiscoveryResult] = {}
		self._cache_temp = tempfile.TemporaryDirectory(prefix="auto-krr-flate-")
		self._cache_dir = Path(self._cache_temp.name) / "charts"

	def discover(self, hr_loc: HrDocLoc) -> DiscoveryResult:
		key = (str(hr_loc.path.resolve()), hr_loc.doc_index)
		cached = self._results.get(key)
		if cached is not None:
			return cached

		result = DiscoveryResult()
		self._results[key] = result
		chart_ref = _resolve_chart_ref(self._repo_root, hr_loc.doc)
		if chart_ref is None:
			result.notes.append("SKIP: HelmRelease chart reference could not be resolved")
			return result
		try:
			chart_values = _load_chart_values(chart_ref, self._helm_bin, self._cache_dir)
			release_values = _release_values(hr_loc.doc)
			candidates = _enumerate_resource_candidates(chart_values, release_values)
		except Exception as exc:
			result.notes.append(f"SKIP: Helm chart values discovery failed: {exc}")
			return result
		if not candidates:
			result.notes.append("SKIP: Helm chart has no resource value candidates")
			return result

		sentinels = [_make_sentinel(candidate, index) for index, candidate in enumerate(candidates, start=1)]
		try:
			rendered = self._render_probe(hr_loc, chart_ref, sentinels)
		except Exception as exc:
			result.notes.append(f"SKIP: flate render failed: {exc}")
			return result

		matched_any = False
		for controller, container, resources in _rendered_containers(rendered):
			observed = _resource_scalars(resources)
			matched = [sentinel for sentinel in sentinels if observed.intersection(sentinel.values.values())]
			if len(matched) == 1:
				matched_any = True
				result.paths[(controller, container)] = ["spec", "values", *matched[0].path]
			elif len(matched) > 1:
				key = (controller, container)
				result.ambiguous[key] = [["spec", "values", *sentinel.path] for sentinel in matched]
				result.notes.append(
					f"SKIP: flate mapping is ambiguous for {controller}/{container} ({len(matched)} resource paths)"
				)

		if not matched_any and not result.ambiguous:
			result.notes.append("SKIP: flate rendered no resource sentinel for a workload container")
		return result

	def _render_probe(self, hr_loc: HrDocLoc, chart_ref: ChartRef, sentinels: List[_Sentinel]) -> List[object]:
		with tempfile.TemporaryDirectory(prefix="probe-", dir=self._cache_temp.name) as temp_name:
			probe_root = Path(temp_name)
			shutil.copytree(
				self._repo_root,
				probe_root,
				dirs_exist_ok=True,
				ignore=shutil.ignore_patterns(".venv", "__pycache__"),
			)
			relative_path = hr_loc.path.resolve().relative_to(self._repo_root.resolve())
			probe_file = probe_root / relative_path
			if not probe_file.is_file():
				raise RuntimeError(f"probe manifest is missing: {relative_path}")
			_, docs, yaml = _read_all_yaml_docs(probe_file)
			if hr_loc.doc_index >= len(docs) or not isinstance(docs[hr_loc.doc_index], CommentedMap):
				raise RuntimeError("probe HelmRelease document is missing")
			probe_doc = docs[hr_loc.doc_index]
			for sentinel in sentinels:
				if not _set_mapping(probe_doc, ["spec", "values", *sentinel.path], _resource_map(sentinel.values)):
					raise RuntimeError(f"probe path could not be created: {sentinel.path}")
			probe_file.write_text(_dump_all_yaml_docs(yaml, docs), encoding="utf-8")

			metadata = hr_loc.doc.get("metadata") or {}
			name = str(metadata.get("name") or "")
			namespace = str(
				metadata.get("namespace")
				or _infer_namespace_from_path(self._repo_root, hr_loc.path)
				or "default"
			)
			render_path = str(relative_path.parent) or "."
			supply_file = probe_root / ".auto-krr-chart-source.yaml"
			supply_file.write_text(_dump_supply_yaml(_chart_source_doc(hr_loc.doc, chart_ref)), encoding="utf-8")
			cmd = [
				self._flate_bin,
				"build",
				"hr",
				name,
				"-n",
				namespace,
				"-p",
				render_path,
				"--supply",
				str(supply_file),
				"--allow-missing-kinds",
				"Secret,ConfigMap",
				"--no-progress",
				"-o",
				"yaml",
			]
			try:
				completed = subprocess.run(
					cmd,
					cwd=str(probe_root),
					check=False,
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE,
					text=True,
				)
			except OSError as exc:
				raise RuntimeError(f"unable to execute flate: {exc}") from exc
			if completed.returncode != 0:
				detail = (completed.stderr or completed.stdout or "").strip().splitlines()
				raise RuntimeError(detail[-1] if detail else f"exit status {completed.returncode}")
			try:
				yaml_safe = YAML(typ="safe")
				return list(yaml_safe.load_all(StringIO(completed.stdout)))
			except Exception as exc:
				raise RuntimeError(f"could not parse flate output: {exc}") from exc


def _release_values(doc: CommentedMap) -> CommentedMap:
	spec = doc.get("spec")
	if isinstance(spec, Mapping) and isinstance(spec.get("values"), CommentedMap):
		return spec["values"]
	return CommentedMap()


def _chart_source_doc(hr_doc: CommentedMap, chart_ref: ChartRef) -> CommentedMap:
	spec = hr_doc.get("spec") or {}
	metadata = hr_doc.get("metadata") or {}
	effective_namespace = str(metadata.get("namespace") or "default") if isinstance(metadata, Mapping) else "default"
	chart_reference = spec.get("chartRef") if isinstance(spec, Mapping) else None
	if isinstance(chart_reference, Mapping):
		kind = str(chart_reference.get("kind") or chart_ref.source_kind)
		name = str(chart_reference.get("name") or chart_ref.source_name or Path(chart_ref.chart).name)
		namespace = str(chart_reference.get("namespace") or chart_ref.source_namespace or effective_namespace)
	else:
		chart_spec = spec.get("chart", {}).get("spec", {}) if isinstance(spec, Mapping) else {}
		source_reference = chart_spec.get("sourceRef", {}) if isinstance(chart_spec, Mapping) else {}
		kind = str(source_reference.get("kind") or chart_ref.source_kind)
		name = str(source_reference.get("name") or chart_ref.source_name or Path(chart_ref.chart).name)
		namespace = str(source_reference.get("namespace") or chart_ref.source_namespace or effective_namespace)

	source_spec: CommentedMap = CommentedMap(
		{
			"interval": "5m",
			"url": chart_ref.source_url or chart_ref.chart,
		}
	)
	if kind == "OCIRepository" and chart_ref.version:
		ref_key = "digest" if chart_ref.version.startswith("sha256:") else "tag"
		source_spec["ref"] = CommentedMap({ref_key: chart_ref.version})
	return CommentedMap(
		{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind": kind,
			"metadata": CommentedMap({"name": name, "namespace": namespace}),
			"spec": source_spec,
		}
	)


def _dump_supply_yaml(doc: CommentedMap) -> str:
	yaml = YAML()
	yaml.explicit_start = True
	buf = StringIO()
	yaml.dump(doc, buf)
	return buf.getvalue()


def _make_sentinel(candidate: ChartCandidate, index: int) -> _Sentinel:
	return _Sentinel(
		path=list(candidate.path),
		values={
			"requests.cpu": f"100000{index}m",
			"requests.memory": f"200000{index}Mi",
			"limits.cpu": f"300000{index}m",
			"limits.memory": f"400000{index}Mi",
		},
	)


def _resource_map(values: Dict[str, str]) -> CommentedMap:
	resources = CommentedMap()
	for section in ("requests", "limits"):
		part = CommentedMap()
		for field in ("cpu", "memory"):
			part[field] = values[f"{section}.{field}"]
		resources[section] = part
	return resources


def _set_mapping(root: CommentedMap, path: List[object], value: CommentedMap) -> bool:
	cur: object = root
	for part in path[:-1]:
		if isinstance(part, int):
			if not isinstance(cur, list) or part < 0 or part >= len(cur):
				return False
			cur = cur[part]
			continue
		if not isinstance(cur, CommentedMap):
			return False
		next_value = cur.get(part)
		if next_value is None:
			next_value = CommentedMap()
			cur[part] = next_value
		if not isinstance(next_value, (CommentedMap, list)):
			return False
		cur = next_value
	last = path[-1]
	if isinstance(last, int):
		if not isinstance(cur, list) or last < 0 or last >= len(cur):
			return False
		cur[last] = value
		return True
	if not isinstance(cur, CommentedMap):
		return False
	cur[last] = value
	return True


def _rendered_containers(rendered: List[object]):
	for doc in rendered:
		if not isinstance(doc, Mapping):
			continue
		metadata = doc.get("metadata")
		controller = str(metadata.get("name") or "") if isinstance(metadata, Mapping) else ""
		if not controller:
			continue
		pod_spec = _pod_spec(doc)
		if not isinstance(pod_spec, Mapping):
			continue
		for key in ("containers", "initContainers"):
			containers = pod_spec.get(key)
			if not isinstance(containers, list):
				continue
			for container in containers:
				if not isinstance(container, Mapping) or not container.get("name"):
					continue
				resources = container.get("resources")
				if isinstance(resources, Mapping):
					yield controller, str(container["name"]), resources


def _pod_spec(doc: Mapping[str, object]) -> Optional[Mapping[str, object]]:
	kind = str(doc.get("kind") or "")
	spec = doc.get("spec")
	if not isinstance(spec, Mapping):
		return None
	if kind == "Pod":
		return spec
	if kind == "CronJob":
		job_template = spec.get("jobTemplate")
		if not isinstance(job_template, Mapping):
			return None
		job_spec = job_template.get("spec")
		if not isinstance(job_spec, Mapping):
			return None
		template = job_spec.get("template")
	else:
		template = spec.get("template")
	if not isinstance(template, Mapping):
		return None
	return template.get("spec") if isinstance(template.get("spec"), Mapping) else None


def _resource_scalars(resources: Mapping[str, object]) -> set[str]:
	values: set[str] = set()
	for section in ("requests", "limits"):
		part = resources.get(section)
		if isinstance(part, Mapping):
			values.update(str(value) for value in part.values())
	return values
