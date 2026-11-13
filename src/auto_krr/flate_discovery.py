from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from .helm_values import (
	ChartCandidate,
	ChartRef,
	_enumerate_resource_candidates,
	_load_chart_values,
	_resolve_chart_ref,
)
from .hr import _infer_namespace_from_path
from .sentinels import ProbeCandidate, SentinelValues, allocate_sentinels, sentinel_values
from .types import HrDocLoc
from .yaml_utils import _dump_all_yaml_docs, _read_all_yaml_docs


@dataclass(frozen=True)
class ReleaseIdentity:
	namespace: str
	name: str
	manifest_path: Path
	doc_index: int


@dataclass
class DiscoveryResult:
	identity: Optional[ReleaseIdentity] = None
	paths: Dict[Tuple[str, str], List[object]] = field(default_factory=dict)
	ambiguous: Dict[Tuple[str, str], List[List[object]]] = field(default_factory=dict)
	unmapped: List[List[object]] = field(default_factory=list)
	failed: List[str] = field(default_factory=list)
	notes: List[str] = field(default_factory=list)

	def path_for(self, identity_or_controller, controller_or_container, container: Optional[str] = None) -> Optional[List[object]]:
		if container is None:
			key = (str(identity_or_controller), str(controller_or_container))
		else:
			key = (str(controller_or_container), str(container))
		path = self.paths.get(key)
		return list(path) if path is not None else None


@dataclass
class DiscoveryBatch:
	results: Dict[ReleaseIdentity, DiscoveryResult] = field(default_factory=dict)
	render_invocations: int = 0
	command: Optional[List[str]] = None
	notes: List[str] = field(default_factory=list)

	def path_for(self, identity: ReleaseIdentity, controller: str, container: str) -> Optional[List[object]]:
		result = self.results.get(identity)
		return result.path_for(identity, controller, container) if result is not None else None


@dataclass(frozen=True)
class _CandidateBinding:
	candidate: ProbeCandidate
	result: DiscoveryResult
	chart_ref: ChartRef


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
		batch = self.discover_many([hr_loc])
		identity = _release_identity(self._repo_root, hr_loc)
		result = batch.results[identity]
		self._results[key] = result
		return result

	def discover_many(self, hr_locs: Sequence[HrDocLoc]) -> DiscoveryBatch:
		batch = DiscoveryBatch()
		if not hr_locs:
			return batch

		bindings: List[_CandidateBinding] = []
		all_candidates: List[ProbeCandidate] = []
		identity_by_key: Dict[Tuple[str, int], ReleaseIdentity] = {}
		for hr_loc in hr_locs:
			identity = _release_identity(self._repo_root, hr_loc)
			result = DiscoveryResult(identity=identity)
			batch.results[identity] = result
			identity_by_key[(str(hr_loc.path.resolve()), hr_loc.doc_index)] = identity
			try:
				chart_ref = _resolve_chart_ref(self._repo_root, hr_loc.doc)
				if chart_ref is None:
					raise RuntimeError("HelmRelease chart reference could not be resolved")
				chart_values = _load_chart_values(chart_ref, self._helm_bin, self._cache_dir)
				candidates = _enumerate_resource_candidates(chart_values, _release_values(hr_loc.doc))
			except Exception as exc:
				_note_failure(result, str(exc))
				continue
			if not candidates:
				_note_failure(result, "Helm chart has no resource value candidates")
				continue
			for candidate in candidates:
				probe_candidate = ProbeCandidate(
					manifest_path=hr_loc.path.resolve().relative_to(self._repo_root.resolve()),
					doc_index=hr_loc.doc_index,
					namespace=identity.namespace,
					release_name=identity.name,
					value_path=tuple(candidate.path),
				)
				binding = _CandidateBinding(candidate=probe_candidate, result=result, chart_ref=chart_ref)
				bindings.append(binding)
				all_candidates.append(probe_candidate)

		if not bindings:
			return batch

		occupied = _scalar_values(doc for hr_loc in hr_locs for doc in [hr_loc.doc])
		allocated = allocate_sentinels(all_candidates, occupied)
		try:
			probe_root = self._make_probe_copy()
			self._inject_probe_values(probe_root, bindings, allocated)
			rendered, command, returncode, detail = self._render_repository(probe_root)
			batch.render_invocations = 1
			batch.command = command
		except Exception as exc:
			for result in batch.results.values():
				_note_failure(result, str(exc))
			return batch

		matched_candidates: Set[ProbeCandidate] = set()
		by_value: Dict[str, List[_CandidateBinding]] = {}
		for binding in bindings:
			for value in sentinel_values(allocated[binding.candidate]):
				by_value.setdefault(value, []).append(binding)

		for namespace, controller, container, resources in _rendered_containers(rendered):
			observed = _resource_scalars(resources)
			matched_bindings: List[_CandidateBinding] = []
			seen_candidates: Set[ProbeCandidate] = set()
			for value in observed:
				for binding in by_value.get(value, []):
					if binding.candidate not in seen_candidates:
						seen_candidates.add(binding.candidate)
						matched_bindings.append(binding)
			if not matched_bindings:
				continue

			owners = {
				binding.result.identity
				for binding in matched_bindings
				if binding.result.identity is not None
			}
			if len(owners) > 1:
				options = [
					["spec", "values", *binding.candidate.value_path]
					for binding in matched_bindings
				]
				for binding in matched_bindings:
					matched_candidates.add(binding.candidate)
					key = (controller, container)
					binding.result.ambiguous[key] = options
					binding.result.notes.append(
						f"SKIP: flate mapping is ambiguous for {controller}/{container} ({len(owners)} releases consumed sentinels)"
					)
				continue

			if namespace:
				matched_bindings = [
					binding for binding in matched_bindings if binding.result.identity is None or binding.result.identity.namespace == namespace
				]
			if not matched_bindings:
				continue

			for binding in matched_bindings:
				matched_candidates.add(binding.candidate)
			if len(matched_bindings) != 1:
				options = [
					["spec", "values", *binding.candidate.value_path]
					for binding in matched_bindings
				]
				for binding in matched_bindings:
					key = (controller, container)
					binding.result.ambiguous[key] = options
					binding.result.notes.append(
						f"SKIP: flate mapping is ambiguous for {controller}/{container} ({len(options)} resource paths)"
					)
				continue

			binding = matched_bindings[0]
			key = (controller, container)
			path = ["spec", "values", *binding.candidate.value_path]
			previous = binding.result.paths.get(key)
			if previous is not None and previous != path:
				binding.result.ambiguous[key] = [previous, path]
				binding.result.paths.pop(key, None)
				binding.result.notes.append(f"SKIP: flate mapping is ambiguous for {controller}/{container}")
			else:
				binding.result.paths[key] = path

		for binding in bindings:
			if binding.candidate not in matched_candidates:
				path = ["spec", "values", *binding.candidate.value_path]
				if path not in binding.result.unmapped:
					binding.result.unmapped.append(path)
				if not any("no resource sentinel" in note for note in binding.result.notes):
					binding.result.notes.append(
						f"SKIP: no resource sentinel matched candidate path {'/'.join(map(str, path))}"
					)

		if returncode != 0:
			for result in batch.results.values():
				if not result.paths and not result.ambiguous:
					_note_failure(result, detail or f"flate exited with status {returncode}")
		return batch

	def _make_probe_copy(self) -> Path:
		probe_root = Path(tempfile.mkdtemp(prefix="probe-", dir=self._cache_temp.name))
		if (self._repo_root / ".git").exists():
			shutil.rmtree(probe_root)
			try:
				subprocess.run(
					["git", "clone", "--no-local", "--no-hardlinks", str(self._repo_root), str(probe_root)],
					check=True,
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE,
					text=True,
				)
			except (OSError, subprocess.CalledProcessError) as exc:
				raise RuntimeError(f"unable to create independent probe repository: {exc}") from exc
		shutil.copytree(
			self._repo_root,
			probe_root,
			dirs_exist_ok=True,
			ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"),
		)
		return probe_root

	def _inject_probe_values(
		self,
		probe_root: Path,
		bindings: Sequence[_CandidateBinding],
		allocated: Dict[ProbeCandidate, SentinelValues],
	) -> None:
		states: Dict[Path, Tuple[List[Any], YAML]] = {}
		for binding in bindings:
			relative_path = binding.candidate.manifest_path
			if relative_path not in states:
				probe_file = probe_root / relative_path
				_, docs, yaml = _read_all_yaml_docs(probe_file)
				states[relative_path] = (docs, yaml)
			docs, _ = states[relative_path]
			if binding.candidate.doc_index >= len(docs) or not isinstance(docs[binding.candidate.doc_index], CommentedMap):
				raise RuntimeError(f"probe HelmRelease document is missing: {relative_path}")
			if not _set_mapping(
				docs[binding.candidate.doc_index],
				["spec", "values", *binding.candidate.value_path],
				_resource_map(allocated[binding.candidate]),
			):
				raise RuntimeError(f"probe path could not be created: {binding.candidate.value_path}")

		for relative_path, (docs, yaml) in states.items():
			(probe_root / relative_path).write_text(_dump_all_yaml_docs(yaml, docs), encoding="utf-8")

	def _render_repository(self, probe_root: Path) -> Tuple[List[object], List[str], int, str]:
		render_path = "kubernetes" if (probe_root / "kubernetes").is_dir() else "."
		cmd = [
			self._flate_bin,
			"build",
			"-p",
			render_path,
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
		try:
			yaml_safe = YAML(typ="safe")
			rendered = list(yaml_safe.load_all(StringIO(completed.stdout))) if completed.stdout.strip() else []
		except Exception as exc:
			if completed.returncode != 0:
				raise RuntimeError(_bounded_detail(completed.stderr) or f"flate exited with status {completed.returncode}") from exc
			raise RuntimeError(f"could not parse flate output: {exc}") from exc
		return rendered, cmd, completed.returncode, _bounded_detail(completed.stderr)


def _release_identity(repo_root: Path, hr_loc: HrDocLoc) -> ReleaseIdentity:
	metadata = hr_loc.doc.get("metadata") or {}
	name = str(metadata.get("name") or "") if isinstance(metadata, Mapping) else ""
	namespace = str(metadata.get("namespace") or "") if isinstance(metadata, Mapping) else ""
	if not namespace:
		namespace = _infer_namespace_from_path(repo_root, hr_loc.path) or "default"
	return ReleaseIdentity(
		namespace=namespace,
		name=name,
		manifest_path=hr_loc.path.resolve().relative_to(repo_root.resolve()),
		doc_index=hr_loc.doc_index,
	)


def _note_failure(result: DiscoveryResult, detail: str) -> None:
	note = f"SKIP: flate discovery failed: {detail}"
	result.failed.append(detail)
	if note not in result.notes:
		result.notes.append(note)


def _bounded_detail(text: str) -> str:
	lines = [line.strip() for line in text.splitlines() if line.strip()]
	return " | ".join(lines[-3:])[:1000]


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

	source_spec: CommentedMap = CommentedMap({"interval": "5m", "url": chart_ref.source_url or chart_ref.chart})
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


def _resource_map(values: SentinelValues) -> CommentedMap:
	resources = CommentedMap()
	resources["requests"] = CommentedMap({"cpu": values.requests_cpu, "memory": values.requests_memory})
	resources["limits"] = CommentedMap({"cpu": values.limits_cpu, "memory": values.limits_memory})
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
		if not isinstance(metadata, Mapping) or not metadata.get("name"):
			continue
		namespace = str(metadata.get("namespace") or "")
		controller = str(metadata["name"])
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
					yield namespace, controller, str(container["name"]), resources


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


def _resource_scalars(resources: Mapping[str, object]) -> Set[str]:
	values: Set[str] = set()
	for section in ("requests", "limits"):
		part = resources.get(section)
		if isinstance(part, Mapping):
			values.update(str(value) for value in part.values())
	return values


def _scalar_values(nodes: Sequence[object]) -> Set[str]:
	values: Set[str] = set()

	def visit(node: object) -> None:
		if isinstance(node, Mapping):
			for value in node.values():
				visit(value)
		elif isinstance(node, list):
			for value in node:
				visit(value)
		elif node is not None:
			values.add(str(node))

	for node in nodes:
		visit(node)
	return values
