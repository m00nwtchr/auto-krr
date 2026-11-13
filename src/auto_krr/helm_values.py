from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from ruamel.yaml.comments import CommentedMap

from .yaml_utils import _read_all_yaml_docs


@dataclass(frozen=True)
class ChartRef:
	chart: str
	version: Optional[str]
	source_kind: str
	source_url: Optional[str] = None


@dataclass(frozen=True)
class ChartValues:
	defaults: CommentedMap
	schema: Optional[Dict[str, Any]]


@dataclass(frozen=True)
class ChartCandidate:
	path: List[object]


def _resolve_chart_ref(repo_root: Path, hr_doc: CommentedMap) -> Optional[ChartRef]:
	spec = hr_doc.get("spec")
	if not isinstance(spec, Mapping):
		return None

	chart_ref = spec.get("chartRef")
	if isinstance(chart_ref, Mapping):
		kind = str(chart_ref.get("kind") or "OCIRepository")
		name = str(chart_ref.get("name") or "")
		namespace = str(chart_ref.get("namespace") or _metadata_namespace(hr_doc))
		source = _find_source(repo_root, kind=kind, name=name, namespace=namespace)
		if source is None:
			return None
		return _chart_ref_from_source(chart_ref, source, kind=kind)

	chart = spec.get("chart")
	if not isinstance(chart, Mapping):
		return None
	chart_spec = chart.get("spec")
	if not isinstance(chart_spec, Mapping):
		return None
	source_ref = chart_spec.get("sourceRef")
	if not isinstance(source_ref, Mapping):
		return None
	kind = str(source_ref.get("kind") or "HelmRepository")
	name = str(source_ref.get("name") or "")
	namespace = str(source_ref.get("namespace") or _metadata_namespace(hr_doc))
	source = _find_source(repo_root, kind=kind, name=name, namespace=namespace)
	if source is None:
		return None
	return _chart_ref_from_source(
		{
			"chart": chart_spec.get("chart"),
			"version": chart_spec.get("version"),
		},
		source,
		kind=kind,
	)


def _metadata_namespace(doc: Mapping[str, Any]) -> str:
	metadata = doc.get("metadata")
	if isinstance(metadata, Mapping) and metadata.get("namespace"):
		return str(metadata["namespace"])
	return "default"


def _find_source(repo_root: Path, *, kind: str, name: str, namespace: str) -> Optional[CommentedMap]:
	unnamespaced: Optional[CommentedMap] = None
	for path in _yaml_files(repo_root):
		try:
			_, docs, _ = _read_all_yaml_docs(path)
		except Exception:
			continue
		for doc in docs:
			if not isinstance(doc, CommentedMap) or str(doc.get("kind") or "") != kind:
				continue
			metadata = doc.get("metadata")
			if not isinstance(metadata, Mapping) or str(metadata.get("name") or "") != name:
				continue
			source_namespace = metadata.get("namespace")
			if source_namespace is None:
				if unnamespaced is None:
					unnamespaced = doc
				continue
			if str(source_namespace) != namespace:
				continue
			return doc
	return unnamespaced


def _yaml_files(repo_root: Path) -> Iterable[Path]:
	for pattern in ("*.yaml", "*.yml"):
		for path in repo_root.rglob(pattern):
			if any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
				continue
			yield path


def _chart_ref_from_source(chart_ref: Mapping[str, Any], source: Mapping[str, Any], *, kind: str) -> Optional[ChartRef]:
	spec = source.get("spec")
	if not isinstance(spec, Mapping):
		return None

	if kind == "OCIRepository":
		url = str(spec.get("url") or "")
		if not url:
			return None
		ref = spec.get("ref")
		version = chart_ref.get("version")
		if not version and isinstance(ref, Mapping):
			version = ref.get("tag") or ref.get("semver") or ref.get("digest")
		return ChartRef(chart=url, version=str(version) if version else None, source_kind=kind, source_url=url)

	if kind == "HelmRepository":
		chart = chart_ref.get("chart")
		url = str(spec.get("url") or "")
		if not chart or not url:
			return None
		version = chart_ref.get("version")
		return ChartRef(
			chart=str(chart),
			version=str(version) if version else None,
			source_kind=kind,
			source_url=url,
		)

	return None


def _load_chart_values(chart_ref: ChartRef, helm_bin: str, cache_dir: Path) -> ChartValues:
	identity = "|".join(
		[
			chart_ref.source_kind,
			chart_ref.chart,
			chart_ref.source_url or "",
			chart_ref.version or "",
		]
	)
	digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
	cache_dir.mkdir(parents=True, exist_ok=True)
	chart_dir = cache_dir / digest
	if not (chart_dir / "Chart.yaml").is_file():
		work_dir = cache_dir / f".{digest}.tmp"
		shutil.rmtree(work_dir, ignore_errors=True)
		work_dir.mkdir(parents=True)
		cmd = [helm_bin, "pull"]
		if chart_ref.source_kind == "HelmRepository":
			cmd.extend([chart_ref.chart, "--repo", str(chart_ref.source_url)])
		else:
			cmd.append(chart_ref.chart)
		if chart_ref.version:
			cmd.extend(["--version", chart_ref.version])
		cmd.extend(["--untar", "--untardir", str(work_dir)])
		try:
			completed = subprocess.run(
				cmd,
				check=False,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				text=True,
			)
		except OSError as exc:
			shutil.rmtree(work_dir, ignore_errors=True)
			raise RuntimeError(f"helm chart fetch failed: {exc}") from exc
		if completed.returncode != 0:
			shutil.rmtree(work_dir, ignore_errors=True)
			detail = (completed.stderr or completed.stdout or "").strip().splitlines()
			raise RuntimeError(f"helm chart fetch failed: {detail[-1] if detail else 'unknown error'}")
		found = [path for path in work_dir.iterdir() if (path / "Chart.yaml").is_file()]
		if len(found) != 1:
			shutil.rmtree(work_dir, ignore_errors=True)
			raise RuntimeError(f"helm chart fetch returned {len(found)} charts")
		shutil.rmtree(chart_dir, ignore_errors=True)
		shutil.move(str(found[0]), str(chart_dir))
		shutil.rmtree(work_dir, ignore_errors=True)

	defaults = CommentedMap()
	values_file = chart_dir / "values.yaml"
	if values_file.is_file():
		_, docs, _ = _read_all_yaml_docs(values_file)
		if docs and isinstance(docs[0], CommentedMap):
			defaults = docs[0]

	schema: Optional[Dict[str, Any]] = None
	schema_file = chart_dir / "values.schema.json"
	if schema_file.is_file():
		parsed = json.loads(schema_file.read_text(encoding="utf-8"))
		if isinstance(parsed, dict):
			schema = parsed
	return ChartValues(defaults=defaults, schema=schema)


def _enumerate_resource_candidates(chart_values: ChartValues, release_values: CommentedMap) -> List[ChartCandidate]:
	merged = _merge_values(chart_values.defaults, release_values)
	paths: set[Tuple[object, ...]] = set()
	root_schema = chart_values.schema or {}

	def visit(value: object, schema: Optional[Mapping[str, Any]], path: List[object]) -> None:
		resolved = _resolve_schema(schema, root_schema)
		if isinstance(value, Mapping):
			if isinstance(value.get("resources"), Mapping):
				paths.add(tuple(path + ["resources"]))

			resource_schema = _schema_property(resolved, "resources", root_schema)
			if _looks_like_resource_schema(resource_schema, root_schema):
				paths.add(tuple(path + ["resources"]))

			keys = set(value.keys())
			if isinstance(resolved, Mapping):
				properties = resolved.get("properties")
				if isinstance(properties, Mapping):
					keys.update(properties.keys())
			for key in sorted(keys, key=str):
				if key == "resources":
					continue
				child_schema = _schema_property(resolved, str(key), root_schema)
				if key in value:
					child_value = value[key]
				elif child_schema is not None:
					child_value = CommentedMap()
				else:
					continue
				if isinstance(child_value, (Mapping, list)):
					visit(child_value, child_schema, path + [key])
		elif isinstance(value, list):
				items_schema = resolved.get("items") if isinstance(resolved, Mapping) else None
				for idx, child_value in enumerate(value):
					if isinstance(child_value, (Mapping, list)):
						visit(child_value, items_schema if isinstance(items_schema, Mapping) else None, path + [idx])

	visit(merged, root_schema, [])
	return [ChartCandidate(path=list(path)) for path in sorted(paths, key=lambda item: tuple(str(part) for part in item))]


def _merge_values(defaults: object, overrides: object) -> object:
	if isinstance(defaults, Mapping) and isinstance(overrides, Mapping):
		merged: Dict[object, object] = {key: value for key, value in defaults.items()}
		for key, value in overrides.items():
			merged[key] = _merge_values(merged[key], value) if key in merged else value
		return merged
	return overrides if overrides is not None else defaults


def _resolve_schema(schema: Optional[Mapping[str, Any]], root: Mapping[str, Any]) -> Mapping[str, Any]:
	if not isinstance(schema, Mapping):
		return {}
	ref = schema.get("$ref")
	if isinstance(ref, str) and ref.startswith("#/"):
		cur: Any = root
		for part in ref[2:].split("/"):
			if not isinstance(cur, Mapping):
				return schema
			cur = cur.get(part.replace("~1", "/").replace("~0", "~"))
		if isinstance(cur, Mapping):
			return cur
	return schema


def _schema_property(schema: Mapping[str, Any], key: str, root: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
	resolved = _resolve_schema(schema, root)
	properties = resolved.get("properties")
	if isinstance(properties, Mapping) and isinstance(properties.get(key), Mapping):
		return _resolve_schema(properties[key], root)
	additional = resolved.get("additionalProperties")
	if isinstance(additional, Mapping):
		return _resolve_schema(additional, root)
	all_of = resolved.get("allOf")
	if isinstance(all_of, list):
		for branch in all_of:
			if isinstance(branch, Mapping):
				found = _schema_property(branch, key, root)
				if found is not None:
					return found
	return None


def _looks_like_resource_schema(schema: Optional[Mapping[str, Any]], root: Mapping[str, Any]) -> bool:
	if not isinstance(schema, Mapping):
		return False
	resolved = _resolve_schema(schema, root)
	properties = resolved.get("properties")
	if not isinstance(properties, Mapping):
		return False
	return "requests" in properties or "limits" in properties
