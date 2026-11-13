import re
from pathlib import Path

import auto_krr.sentinels as sentinels
from auto_krr.sentinels import ProbeCandidate, SentinelValues, allocate_sentinels, sentinel_values


def _candidate(path: str, *, namespace: str = "media", name: str = "demo") -> ProbeCandidate:
	return ProbeCandidate(
		manifest_path=Path(path),
		doc_index=0,
		namespace=namespace,
		release_name=name,
		value_path=("controllers", name, "containers", "app", "resources"),
	)


def test_sentinel_values_are_stable_and_order_independent() -> None:
	candidates = [_candidate("b.yaml", name="b"), _candidate("a.yaml", name="a")]

	first = allocate_sentinels(candidates, set())
	second = allocate_sentinels(list(reversed(candidates)), set())

	assert first == second


def test_sentinel_identity_includes_release_and_manifest() -> None:
	first = _candidate("a.yaml", name="demo")
	second = _candidate("b.yaml", name="demo")

	allocated = allocate_sentinels([first, second], set())

	assert sentinel_values(allocated[first]).isdisjoint(sentinel_values(allocated[second]))


def test_sentinel_quantities_are_bounded_and_valid() -> None:
	values = allocate_sentinels([_candidate("a.yaml")], set())[_candidate("a.yaml")]

	assert re.fullmatch(r"[0-9]+m", values.requests_cpu)
	assert re.fullmatch(r"[0-9]+Mi", values.requests_memory)
	assert re.fullmatch(r"[0-9]+m", values.limits_cpu)
	assert re.fullmatch(r"[0-9]+Mi", values.limits_memory)
	for value in sentinel_values(values):
		numeric = int(re.match(r"[0-9]+", value).group())
		assert 100_000_000 <= numeric < 1_000_000_000


def test_hash_collision_is_resolved_deterministically(monkeypatch) -> None:
	class SameDigest:
		def digest(self) -> bytes:
			return b"\x01" * 32

	monkeypatch.setattr(sentinels.hashlib, "sha256", lambda _payload: SameDigest())
	candidates = [_candidate("a.yaml", name="a"), _candidate("b.yaml", name="b")]

	first = allocate_sentinels(candidates, set())
	second = allocate_sentinels(list(reversed(candidates)), set())

	assert first == second
	assert sentinel_values(first[candidates[0]]).isdisjoint(sentinel_values(first[candidates[1]]))


def test_sentinels_avoid_existing_resource_values() -> None:
	candidate = _candidate("a.yaml")
	initial = allocate_sentinels([candidate], set())[candidate]

	allocated = allocate_sentinels([candidate], sentinel_values(initial))[candidate]

	assert sentinel_values(allocated).isdisjoint(sentinel_values(initial))
