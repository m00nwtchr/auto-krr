from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap


@dataclass(frozen=True)
class HrRef:
	namespace: str
	name: str


@dataclass(frozen=True)
class TargetKey:
	hr: HrRef
	controller: str
	container: str


@dataclass
class RecommendedResources:
	req_cpu_cores: Optional[float] = None
	req_mem_bytes: Optional[float] = None
	lim_cpu_cores: Optional[float] = None
	lim_mem_bytes: Optional[float] = None


@dataclass
class HrDocLoc:
	path: Path
	doc_index: int
	doc: CommentedMap


@dataclass
class ForgejoRepo:
	base_url: str
	owner: str
	repo: str
	api_prefix: str


YamlDocBundle = Tuple[str, List[Any], YAML]
