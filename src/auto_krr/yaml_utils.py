from __future__ import annotations

from typing import Any, List, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap


def _mk_yaml(explicit_start: bool) -> YAML:
	yaml = YAML(typ="rt")
	yaml.preserve_quotes = True
	yaml.width = 4096
	yaml.explicit_start = explicit_start
	yaml.indent(mapping=2, sequence=4, offset=2)
	return yaml


def _read_all_yaml_docs(path) -> Tuple[str, List[Any], YAML]:
	raw = path.read_text(encoding="utf-8")
	explicit_start = raw.lstrip().startswith("---")
	yaml = _mk_yaml(explicit_start=explicit_start)
	docs = list(yaml.load_all(raw))
	return raw, docs, yaml


def _dump_all_yaml_docs(yaml: YAML, docs: List[Any]) -> str:
	from io import StringIO
	buf = StringIO()
	yaml.dump_all(docs, buf)
	return buf.getvalue()


def _insert_if_missing(m: CommentedMap, key: str, value: Any, *, after_keys: List[str]) -> None:
	if key in m:
		return
	insert_at = len(m)
	for ak in after_keys:
		if ak in m:
			insert_at = list(m.keys()).index(ak) + 1
	m.insert(insert_at, key, value)


def _insert_alpha_if_missing(m: CommentedMap, key: str, value: Any) -> None:
	if key in m:
		return
	keys = list(m.keys())
	insert_at = len(keys)
	key_str = str(key)
	for idx, existing in enumerate(keys):
		if str(existing) > key_str:
			insert_at = idx
			break
	m.insert(insert_at, key, value)
