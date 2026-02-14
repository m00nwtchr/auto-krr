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


def _find_krr_comment_targets(doc: Any) -> List[CommentTargetMatch]:
    matches: List[CommentTargetMatch] = []

    def _walk(node: Any, path: List[object]) -> None:
        if isinstance(node, CommentedMap):
            for key, value in node.items():
                key_str = str(key)
                next_path = [*path, key_str]
                if key_str == "resources":
                    controller, container = _parse_krr_comment(_comment_texts_for_key(node, key))
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
    texts: List[str] = []

    def _collect(obj: Any) -> None:
        if obj is None:
            return
        if isinstance(obj, list):
            for part in obj:
                _collect(part)
            return
        value = getattr(obj, "value", None)
        if value is None:
            value = str(obj)
        texts.append(value)

    _collect(entry)
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
