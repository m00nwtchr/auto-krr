from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from ruamel.yaml.comments import CommentedMap


@dataclass(frozen=True)
class CommentTargetMatch:
	resources_path: List[object]
	controller: str
	container: str


def _find_krr_comment_targets(doc: Any, *, raw_lines: Optional[List[str]] = None) -> List[CommentTargetMatch]:
	matches: List[CommentTargetMatch] = []

	def _walk(node: Any, path: List[object]) -> None:
		if isinstance(node, CommentedMap):
			for key, value in node.items():
				key_str = str(key)
				next_path = [*path, key_str]
				if key_str == "resources":
					texts = _comment_texts_for_key(node, key)
					if not texts and node and list(node.keys())[0] == key:
						texts = _comment_texts_for_map(node)
					if not texts and raw_lines is not None:
						pos = node.lc.key(key)
						line = pos[0] if isinstance(pos, tuple) else pos
						if isinstance(line, int) and line > 0:
							prev = raw_lines[line - 1]
							if prev.lstrip().startswith("#"):
								texts = [prev]
					controller, container = _parse_krr_comment(texts)
					if controller and container:
						matches.append(
							CommentTargetMatch(
								resources_path=next_path,
								controller=controller,
								container=container,
							)
						)
				_walk(value, next_path)
		elif isinstance(node, list):
			for idx, item in enumerate(node):
				_walk(item, [*path, idx])

	_walk(doc, [])
	return matches


def _comment_texts_for_key(m: CommentedMap, key: object) -> List[str]:
	ca = getattr(m, "ca", None)
	items = getattr(ca, "items", None)
	if not items or key not in items:
		return []
	entry = items.get(key)
	return _comment_texts_from_obj(entry)


def _comment_texts_for_map(m: CommentedMap) -> List[str]:
	ca = getattr(m, "ca", None)
	if not ca:
		return []
	comment = getattr(ca, "comment", None)
	if not comment:
		return []
	return _comment_texts_from_obj(comment)


def _trailing_comment_texts(node: Any) -> List[str]:
	if node is None:
		return []
	texts: List[str] = []

	ca = getattr(node, "ca", None)
	if ca:
		end = getattr(ca, "end", None)
		if end:
			for item in end:
				if item is None:
					continue
				texts.extend(_comment_texts_from_obj(item))

	if isinstance(node, CommentedMap) and node:
		last_key = list(node.keys())[-1]
		texts.extend(_comment_texts_for_key(node, last_key))
		texts.extend(_trailing_comment_texts(node.get(last_key)))
	elif isinstance(node, list) and node:
		texts.extend(_trailing_comment_texts(node[-1]))

	return texts


def _comment_texts_from_obj(obj: Any) -> List[str]:
	texts: List[str] = []

	def _collect(item: Any) -> None:
		if item is None:
			return
		if isinstance(item, list):
			for part in item:
				_collect(part)
			return
		value = getattr(item, "value", None)
		if value is None:
			value = str(item)
		texts.append(value)

	_collect(obj)
	return texts


def _parse_krr_comment(texts: List[str]) -> Tuple[Optional[str], Optional[str]]:
	for text in texts:
		for line in text.splitlines():
			if "krr:" not in line:
				continue
			match = re.search(r"krr:\s*(.*)", line)
			if not match:
				continue
			rest = match.group(1)
			rest = rest.replace(",", " ")
			pairs = {}
			for part in rest.split():
				if "=" not in part:
					continue
				key, value = part.split("=", 1)
				pairs[key.strip()] = value.strip().strip("\"'")
			controller = pairs.get("controller")
			container = pairs.get("container")
			if controller and container:
				return controller, container
	return None, None
