from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Sequence, Set, Tuple


_MIN_QUANTITY = 100_000_000
_QUANTITY_SPAN = 900_000_000
_FIELDS = (
	("requests_cpu", "m"),
	("requests_memory", "Mi"),
	("limits_cpu", "m"),
	("limits_memory", "Mi"),
)


@dataclass(frozen=True)
class ProbeCandidate:
	manifest_path: Path
	doc_index: int
	namespace: str
	release_name: str
	value_path: Tuple[object, ...]


@dataclass(frozen=True)
class SentinelValues:
	requests_cpu: str
	requests_memory: str
	limits_cpu: str
	limits_memory: str


def allocate_sentinels(
	candidates: Sequence[ProbeCandidate],
	occupied_values: Set[str],
) -> Dict[ProbeCandidate, SentinelValues]:
	used = set(occupied_values)
	allocated: Dict[ProbeCandidate, SentinelValues] = {}

	for candidate in sorted(candidates, key=_canonical_key):
		values: Dict[str, str] = {}
		for field, suffix in _FIELDS:
			value = _allocate_value(candidate, field, suffix, used)
			values[field] = value
			used.add(value)
		allocated[candidate] = SentinelValues(**values)
	return allocated


def sentinel_values(values: SentinelValues) -> Set[str]:
	return {
		values.requests_cpu,
		values.requests_memory,
		values.limits_cpu,
		values.limits_memory,
	}


def _allocate_value(
	candidate: ProbeCandidate,
	field: str,
	suffix: str,
	used: Set[str],
) -> str:
	payload = f"auto-krr-sentinel:v1:{field}:".encode("utf-8") + _canonical_key(candidate).encode("utf-8")
	digest = hashlib.sha256(payload).digest()
	base = _MIN_QUANTITY + int.from_bytes(digest[:8], "big") % _QUANTITY_SPAN
	for offset in range(_QUANTITY_SPAN):
		number = _MIN_QUANTITY + (base - _MIN_QUANTITY + offset) % _QUANTITY_SPAN
		value = f"{number}{suffix}"
		if value not in used:
			return value
	raise RuntimeError("sentinel quantity range exhausted")


def _canonical_key(candidate: ProbeCandidate) -> str:
	return json.dumps(
		[
			candidate.manifest_path.as_posix(),
			candidate.doc_index,
			candidate.namespace,
			candidate.release_name,
			list(candidate.value_path),
		],
		ensure_ascii=False,
		separators=(",", ":"),
	)
