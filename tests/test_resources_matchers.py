from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from auto_krr.flate_discovery import DiscoveryBatch, DiscoveryResult, ReleaseIdentity
from auto_krr.resources_matchers import HelmReleaseMatcher
from auto_krr.types import HrDocLoc, RecommendedResources, ResourceRef, TargetKey


class _FakeDiscovery:
	def __init__(self, result: DiscoveryResult) -> None:
		self.result = result
		self.calls = 0

	def discover(self, _loc: HrDocLoc) -> DiscoveryResult:
		self.calls += 1
		return self.result


class _BatchOnlyDiscovery:
	def __init__(self, batch: DiscoveryBatch) -> None:
		self.batch = batch
		self.batch_calls = 0

	def discover_many(self, locs: list[HrDocLoc]) -> DiscoveryBatch:
		self.batch_calls += 1
		assert len(locs) == 1
		return self.batch

	def discover(self, _loc: HrDocLoc) -> DiscoveryResult:
		raise AssertionError("individual discovery must not run during target resolution")


def _doc() -> CommentedMap:
	return CommentedMap(
		{
			"kind": "HelmRelease",
			"metadata": CommentedMap({"name": "demo", "namespace": "default"}),
			"spec": CommentedMap(
				{
					"values": CommentedMap(
						{
							"worker": CommentedMap(
								{
									"containers": CommentedMap(
										{"app": CommentedMap({"image": "example/app:1"})}
									)
								}
							)
						}
					)
				}
			)
		}
	)


def _matcher(result: DiscoveryResult, loc: HrDocLoc) -> tuple[HelmReleaseMatcher, TargetKey]:
	resource = ResourceRef(kind="HelmRelease", namespace="default", name="demo")
	target = TargetKey(resource=resource, controller="demo", container="app")
	matcher = HelmReleaseMatcher(
			repo_root=Path("."),
			discovery=_FakeDiscovery(result),
			hr_index={resource: [loc]},
			hr_index_by_name={},
			no_name_fallback=True,
		)
	return matcher, target


def test_helm_values_matcher_name_only_fallback() -> None:
	doc = _doc()
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	resource = ResourceRef(kind="HelmRelease", namespace="default", name="demo")
	target = TargetKey(resource=resource, controller="main", container="app")
	matcher = HelmReleaseMatcher(
		repo_root=Path("."),
		discovery=_FakeDiscovery(DiscoveryResult()),
		hr_index={},
		hr_index_by_name={"demo": [loc]},
		no_name_fallback=False,
	)

	target_match = next(iter(matcher.iter_targets({target: RecommendedResources(req_cpu_cores=0.5)})))

	assert target_match.match is not None
	assert target_match.match.locs[0].path == Path("fake.yaml")
	assert any("matched default/demo by name-only" in note for note in target_match.match.info_notes)


def test_helm_values_matcher_resolves_generic_discovered_path_and_caches() -> None:
	doc = _doc()
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	path = ["spec", "values", "worker", "containers", "app", "resources"]
	fake = _FakeDiscovery(DiscoveryResult(paths={("demo", "app"): path}))
	resource = ResourceRef(kind="HelmRelease", namespace="default", name="demo")
	target = TargetKey(resource=resource, controller="demo", container="app")
	matcher = HelmReleaseMatcher(
		repo_root=Path("."),
		discovery=fake,
		hr_index={resource: [loc]},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	first, changed, notes = matcher.resolve_resources(doc, target, loc)
	second, second_changed, second_notes = matcher.resolve_resources(doc, target, loc)

	assert isinstance(first, CommentedMap)
	assert first is second
	assert changed is True
	assert second_changed is False
	assert notes == []
	assert second_notes == []
	assert fake.calls == 1


def test_helmrelease_matcher_precomputes_one_discovery_batch() -> None:
	doc = _doc()
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	resource = ResourceRef(kind="HelmRelease", namespace="default", name="demo")
	target = TargetKey(resource=resource, controller="demo", container="app")
	identity = ReleaseIdentity("default", "demo", Path("fake.yaml"), 0)
	result = DiscoveryResult(paths={("demo", "app"): ["spec", "values", "worker", "containers", "app", "resources"]})
	fake = _BatchOnlyDiscovery(DiscoveryBatch(results={identity: result}))
	matcher = HelmReleaseMatcher(
		repo_root=Path("."),
		discovery=fake,
		hr_index={resource: [loc]},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	resources, changed, notes = matcher.resolve_resources(doc, target, loc)

	assert isinstance(resources, CommentedMap)
	assert changed is True
	assert notes == []
	assert fake.batch_calls == 1


def test_helmrelease_matcher_skips_ambiguous_discovery() -> None:
	doc = _doc()
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	result = DiscoveryResult(
		ambiguous={("demo", "app"): [["spec", "values", "one"], ["spec", "values", "two"]]},
		notes=["SKIP: flate mapping is ambiguous for demo/app (2 resource paths)"],
	)
	matcher, target = _matcher(result, loc)

	resources, changed, notes = matcher.resolve_resources(doc, target, loc)

	assert resources is None
	assert changed is False
	assert any("ambiguous" in note for note in notes)


def test_helmrelease_matcher_does_not_use_values_resources_heuristic() -> None:
	doc = _doc()
	doc["spec"]["values"]["resources"] = CommentedMap(
		{"requests": CommentedMap({"cpu": "10m"})}
	)
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	matcher, target = _matcher(
		DiscoveryResult(notes=["SKIP: flate rendered no resource sentinel for a workload container"]),
		loc,
	)

	resources, changed, notes = matcher.resolve_resources(doc, target, loc)

	assert resources is None
	assert changed is False
	assert any("no resource sentinel" in note for note in notes)
	assert doc["spec"]["values"]["resources"]["requests"]["cpu"] == "10m"


def test_helm_values_matcher_describe_match_uses_resource_identity() -> None:
	doc = _doc()
	resource = ResourceRef(kind="HelmRelease", namespace="default", name="demo")
	target = TargetKey(resource=resource, controller="demo", container="app")
	matcher = HelmReleaseMatcher(
		repo_root=Path("."),
		discovery=_FakeDiscovery(DiscoveryResult()),
		hr_index={},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	label = matcher.describe_match(target, doc)

	assert label.startswith("HelmRelease default/demo")
	assert label.endswith("(helmrelease)")
