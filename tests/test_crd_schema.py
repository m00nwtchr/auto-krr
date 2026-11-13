import json
import stat
from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from auto_krr.crd_schema import CrdSchemaDetector, YamlDocLoc


def _write_executable(path: Path, body: str) -> None:
	path.write_text(body, encoding="utf-8")
	path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _custom_resource(tmp_path: Path, *, schema_url: str | None = None, name: str = "demo") -> YamlDocLoc:
	path = tmp_path / f"{name}.yaml"
	prefix = f"# yaml-language-server: $schema={schema_url}\n" if schema_url else ""
	path.write_text(
		prefix
		+ f"""\
apiVersion: example.com/v1
kind: Widget
metadata:
  name: {name}
spec:
  settings: {{}}
""",
		encoding="utf-8",
	)
	return YamlDocLoc(
		path=path,
		doc_index=0,
		doc=CommentedMap(
			{
				"apiVersion": "example.com/v1",
				"kind": "Widget",
				"metadata": CommentedMap({"name": name}),
				"spec": CommentedMap({"settings": CommentedMap()}),
			}
		),
	)


def _kubectl_json(path: Path, payload: object) -> None:
	_write_executable(
		path,
		"#!/usr/bin/env python3\nimport json\n"
		f"print(json.dumps({payload!r}))\n",
	)


def _crd_payload(*, schema_v1: dict, schema_v1beta1: dict | None = None) -> dict:
	versions = [{"name": "v1", "served": True, "storage": True, "schema": {"openAPIV3Schema": schema_v1}}]
	if schema_v1beta1 is not None:
		versions.append(
			{"name": "v1beta1", "served": True, "storage": False, "schema": {"openAPIV3Schema": schema_v1beta1}}
		)
	return {
		"items": [
			{
				"metadata": {"name": "widgets.example.com"},
				"spec": {
					"group": "example.com",
					"names": {"kind": "Widget"},
					"versions": versions,
				},
			}
		]
	}


def test_api_schema_prefers_exact_custom_resource_version(tmp_path: Path) -> None:
	doc = _custom_resource(tmp_path)
	kubectl = tmp_path / "kubectl"
	_kubectl_json(
		kubectl,
		_crd_payload(
			schema_v1={"type": "object", "properties": {"spec": {"properties": {"resources": {}}}}},
			schema_v1beta1={"type": "object", "properties": {"spec": {"properties": {"old": {"properties": {"resources": {}}}}}}},
		),
	)

	report = CrdSchemaDetector(tmp_path, kubectl_bin=str(kubectl)).detect([doc])

	exact = [definition for definition in report.definitions if definition.version == "v1"]
	assert any(definition.schema_path == ("spec", "resources") for definition in exact)
	assert all(definition.source == "kube-api" for definition in exact)
	assert any(definition.version == "v1beta1" and definition.confidence != "exact" for definition in report.definitions)
	assert all(definition.runtime_mapping is None for definition in report.definitions)


def test_recursive_refs_are_cycle_safe_and_paths_are_unique(tmp_path: Path) -> None:
	doc = _custom_resource(tmp_path)
	kubectl = tmp_path / "kubectl"
	_kubectl_json(
		kubectl,
		_crd_payload(
			schema_v1={
				"type": "object",
				"properties": {"spec": {"$ref": "#/definitions/Spec"}},
				"definitions": {
					"Spec": {
						"type": "object",
						"properties": {"resources": {}, "child": {"$ref": "#/definitions/Spec"}},
					}
				},
			}
		),
	)

	report = CrdSchemaDetector(tmp_path, kubectl_bin=str(kubectl)).detect([doc])
	paths = [definition.schema_path for definition in report.definitions]

	assert paths.count(("spec", "resources")) == 1
	assert len(paths) == len(set(paths))


def test_api_failure_falls_back_to_https_schema_comment(tmp_path: Path, monkeypatch) -> None:
	url = "https://schemas.example.test/widget.json"
	doc = _custom_resource(tmp_path, schema_url=url)
	kubectl = tmp_path / "kubectl"
	_write_executable(kubectl, "#!/usr/bin/env python3\nraise SystemExit(2)\n")
	calls: list[str] = []

	class Response:
		def __enter__(self):
			return self

		def __exit__(self, *_args):
			return False

		def read(self):
			return b'{"properties":{"spec":{"properties":{"resources":{}}}}}'

	def fake_urlopen(requested_url, timeout):
		calls.append(str(requested_url))
		assert timeout == 10.0
		return Response()

	monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
	report = CrdSchemaDetector(tmp_path, kubectl_bin=str(kubectl)).detect([doc])

	assert any(definition.source == "schema-comment" for definition in report.definitions)
	assert any(definition.schema_path == ("spec", "resources") for definition in report.definitions)
	assert calls == [url]
	assert any(entry["source"] == "schema-comment" for entry in report.debug)


def test_schema_comment_requires_https_and_is_cached_per_run(tmp_path: Path, monkeypatch) -> None:
	url = "https://schemas.example.test/widget.json"
	first = _custom_resource(tmp_path, schema_url=url, name="first")
	second = _custom_resource(tmp_path, schema_url=url, name="second")
	kubectl = tmp_path / "kubectl"
	_write_executable(kubectl, "#!/usr/bin/env python3\nprint('not-json')\n")
	calls: list[str] = []

	class Response:
		def __enter__(self):
			return self

		def __exit__(self, *_args):
			return False

		def read(self):
			return b'{"properties":{"spec":{"properties":{"resources":{}}}}}'

	monkeypatch.setattr("urllib.request.urlopen", lambda requested_url, timeout: (calls.append(str(requested_url)) or Response()))
	report = CrdSchemaDetector(tmp_path, kubectl_bin=str(kubectl)).detect([first, second])
	assert calls == [url]
	assert len([definition for definition in report.definitions if definition.source == "schema-comment"]) == 1

	http_doc = _custom_resource(tmp_path, schema_url="http://schemas.example.test/widget.json", name="http")
	monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network access")))
	http_report = CrdSchemaDetector(tmp_path, kubectl_bin=str(kubectl)).detect([http_doc])
	assert not http_report.definitions
	assert any("https" in note.lower() for note in http_report.notes)
