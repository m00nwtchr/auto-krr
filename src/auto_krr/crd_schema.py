from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap


@dataclass(frozen=True)
class YamlDocLoc:
	path: Path
	doc_index: int
	doc: CommentedMap


@dataclass(frozen=True)
class CrdResourceDefinition:
	crd_name: str
	group: str
	kind: str
	version: str
	api_version: str
	schema_path: Tuple[str, ...]
	source: str
	confidence: str
	runtime_mapping: Optional[Tuple[str, str]] = None


@dataclass
class CrdSchemaReport:
	definitions: List[CrdResourceDefinition] = field(default_factory=list)
	notes: List[str] = field(default_factory=list)
	debug: List[Dict[str, object]] = field(default_factory=list)
	failed: List[str] = field(default_factory=list)


class CrdSchemaDetector:
	def __init__(self, repo_root: Path, kubectl_bin: str = "kubectl", timeout: float = 10.0) -> None:
		self._repo_root = repo_root
		self._kubectl_bin = kubectl_bin
		self._timeout = timeout
		self._schema_cache: Dict[str, object] = {}

	def detect(self, yaml_docs: Sequence[YamlDocLoc]) -> CrdSchemaReport:
		report = CrdSchemaReport()
		docs = list(yaml_docs)
		identities = [_resource_identity(location.doc) for location in docs]
		api_definitions, api_failed = self._detect_from_api(identities, report)
		for definition in api_definitions:
			_add_definition(report, definition)

		exact_api_keys = {
			(definition.group, definition.kind, definition.version)
			for definition in api_definitions
			if definition.confidence == "exact"
		}
		for location, identity in zip(docs, identities):
			if identity is None:
				continue
			group, kind, version, api_version = identity
			if (group, kind, version) in exact_api_keys:
				continue
			urls = _schema_urls(location.path)
			for url in urls:
				if not url.lower().startswith("https://"):
					note = f"SKIP: rejected non-HTTPS CRD schema URL: {url}"
					if note not in report.notes:
						report.notes.append(note)
					continue
				try:
					schema = self._fetch_schema(url)
				except Exception as exc:
					detail = f"{url}: {exc}"
					report.failed.append(detail)
					report.notes.append(f"SKIP: CRD schema comment fetch failed: {detail}")
					continue
				paths = _find_resource_paths(schema)
				if not paths:
					report.notes.append(f"SKIP: CRD schema comment has no resources property: {url}")
					continue
				for schema_path in paths:
					definition = CrdResourceDefinition(
						crd_name=f"{kind.lower()}.{group}",
						group=group,
						kind=kind,
						version=version,
						api_version=api_version,
						schema_path=schema_path,
						source="schema-comment",
						confidence="exact" if not api_failed else "fallback",
					)
					_add_definition(report, definition)
					report.debug.append(
						{
							"source": "schema-comment",
							"url": url,
							"api_version": api_version,
							"kind": kind,
							"paths": [list(path) for path in paths],
						}
				)

		if not api_definitions and not any(definition.source == "schema-comment" for definition in report.definitions):
			if api_failed:
				report.notes.append("SKIP: CRD schema discovery unavailable")
		return report

	def _detect_from_api(
		self,
		identities: Sequence[Optional[Tuple[str, str, str, str]]],
		report: CrdSchemaReport,
	) -> Tuple[List[CrdResourceDefinition], bool]:
		try:
			completed = subprocess.run(
				[self._kubectl_bin, "get", "crd", "-o", "json"],
				cwd=str(self._repo_root),
				check=False,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				text=True,
				timeout=self._timeout,
			)
		except (OSError, subprocess.TimeoutExpired) as exc:
			detail = str(exc)
			report.failed.append(detail)
			report.notes.append(f"SKIP: kubectl CRD query failed: {detail}")
			return [], True

		if completed.returncode != 0:
			detail = _bounded_detail(completed.stderr) or f"exit status {completed.returncode}"
			report.failed.append(detail)
			report.notes.append(f"SKIP: kubectl CRD query failed: {detail}")
			return [], True
		try:
			payload = json.loads(completed.stdout)
		except (TypeError, ValueError) as exc:
			detail = str(exc)
			report.failed.append(detail)
			report.notes.append(f"SKIP: kubectl CRD response was malformed: {detail}")
			return [], True

		items = payload.get("items") if isinstance(payload, Mapping) else None
		if not isinstance(items, list):
			report.notes.append("SKIP: kubectl CRD response did not contain items")
			return [], True

		definitions: List[CrdResourceDefinition] = []
		usable_schema = False
		doc_keys = {
			(identity[0], identity[1], identity[2])
			for identity in identities
			if identity is not None
		}
		for crd in items:
			if not isinstance(crd, Mapping):
				continue
			spec = crd.get("spec")
			if not isinstance(spec, Mapping):
				continue
			group = str(spec.get("group") or "")
			names = spec.get("names")
			kind = str(names.get("kind") or "") if isinstance(names, Mapping) else ""
			crd_metadata = crd.get("metadata")
			crd_name = str(crd_metadata.get("name") or f"{kind.lower()}.{group}") if isinstance(crd_metadata, Mapping) else f"{kind.lower()}.{group}"
			versions = spec.get("versions")
			if not isinstance(versions, list):
				versions = []
			for version_info in versions:
				if not isinstance(version_info, Mapping):
					continue
				version = str(version_info.get("name") or "")
				schema_wrapper = version_info.get("schema")
				schema = schema_wrapper.get("openAPIV3Schema") if isinstance(schema_wrapper, Mapping) else None
				if not version or not isinstance(schema, Mapping):
					continue
				paths = _find_resource_paths(schema)
				if not paths:
					continue
				usable_schema = True
				confidence = "exact" if (group, kind, version) in doc_keys else "schema-only"
				for schema_path in paths:
					definition = CrdResourceDefinition(
						crd_name=crd_name,
						group=group,
						kind=kind,
						version=version,
						api_version=f"{group}/{version}",
						schema_path=schema_path,
						source="kube-api",
						confidence=confidence,
					)
					definitions.append(definition)
				report.debug.append(
					{
						"source": "kube-api",
						"crd": crd_name,
						"api_version": f"{group}/{version}",
						"kind": kind,
						"paths": [list(path) for path in paths],
					}
				)
		if not usable_schema:
			report.notes.append("SKIP: kubectl CRD response contained no usable OpenAPI schemas")
		return definitions, not usable_schema

	def _fetch_schema(self, url: str) -> Mapping[str, object]:
		if url in self._schema_cache:
			cached = self._schema_cache[url]
			if isinstance(cached, Exception):
				raise cached
			if not isinstance(cached, Mapping):
				raise ValueError("schema document is not an object")
			return cached
		try:
			with urllib.request.urlopen(url, timeout=self._timeout) as response:
				raw = response.read()
			if isinstance(raw, bytes):
				raw = raw.decode("utf-8")
			try:
				payload = json.loads(raw)
			except (TypeError, ValueError):
				payload = YAML(typ="safe").load(raw)
			if not isinstance(payload, Mapping):
				raise ValueError("schema document is not an object")
		except Exception as exc:
			self._schema_cache[url] = exc
			raise
		self._schema_cache[url] = payload
		return payload


def _resource_identity(doc: Mapping[str, object]) -> Optional[Tuple[str, str, str, str]]:
	api_version = doc.get("apiVersion")
	kind = doc.get("kind")
	if not isinstance(api_version, str) or not isinstance(kind, str) or "/" not in api_version:
		return None
	group, version = api_version.split("/", 1)
	if not group or not version or not kind:
		return None
	return group, kind, version, api_version


def _schema_urls(path: Path) -> List[str]:
	try:
		text = path.read_text(encoding="utf-8")
	except OSError:
		return []
	pattern = re.compile(r"yaml-language-server:\s*\$schema=([^\s#]+)")
	return list(dict.fromkeys(match.group(1) for match in pattern.finditer(text)))


def _find_resource_paths(schema: Mapping[str, object]) -> List[Tuple[str, ...]]:
	paths: Set[Tuple[str, ...]] = set()

	def walk(node: object, path: Tuple[str, ...], active_refs: Set[str]) -> None:
		if not isinstance(node, Mapping):
			if isinstance(node, list):
				for item in node:
					walk(item, path, active_refs)
			return
		ref = node.get("$ref")
		if isinstance(ref, str) and ref.startswith("#/") and ref not in active_refs:
			target = _resolve_local_ref(schema, ref)
			if target is not None:
				walk(target, path, active_refs | {ref})

		properties = node.get("properties")
		if isinstance(properties, Mapping):
			for name, child in properties.items():
				child_path = path + (str(name),)
				if str(name) == "resources":
					paths.add(child_path)
				walk(child, child_path, active_refs)

		for key in ("items", "additionalProperties", "allOf", "anyOf", "oneOf", "not"):
			child = node.get(key)
			if isinstance(child, Mapping):
				walk(child, path, active_refs)
			elif isinstance(child, list):
				for item in child:
					walk(item, path, active_refs)

	walk(schema, (), set())
	return sorted(paths)


def _resolve_local_ref(root: Mapping[str, object], ref: str) -> Optional[object]:
	current: object = root
	for part in ref[2:].split("/"):
		part = part.replace("~1", "/").replace("~0", "~")
		if not isinstance(current, Mapping) or part not in current:
			return None
		current = current[part]
	return current


def _add_definition(report: CrdSchemaReport, definition: CrdResourceDefinition) -> None:
	if definition not in report.definitions:
		report.definitions.append(definition)


def _bounded_detail(text: str) -> str:
	lines = [line.strip() for line in text.splitlines() if line.strip()]
	return " | ".join(lines[-3:])[:1000]
