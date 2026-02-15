from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from auto_krr.resources_matchers import HelmReleaseMatcher
from auto_krr.types import HrDocLoc, RecommendedResources, ResourceRef, TargetKey
from auto_krr.yaml_utils import _read_all_yaml_docs


def _load_doc(name: str) -> CommentedMap:
	path = Path(__file__).parent / "fixtures" / "manifests" / name
	_, docs, _ = _read_all_yaml_docs(path)
	assert len(docs) == 1
	doc = docs[0]
	assert isinstance(doc, CommentedMap)
	return doc


def test_helm_values_matcher_name_only_fallback() -> None:
	# Intended behavior: allow a unique name-only match when namespace lookup fails.
	doc = _load_doc("helmrelease_app_template_resources_missing.yaml")
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="chronyd"), controller="main", container="app")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	matcher = HelmReleaseMatcher(
		hr_index={},
		hr_index_by_name={"chronyd": [loc]},
		no_name_fallback=False,
	)

	target_match = next(iter(matcher.iter_targets(rec_map)))
	assert target_match.match is not None
	assert target_match.match.locs[0].path == Path("fake.yaml")
	assert any("matched default/chronyd by name-only" in note for note in target_match.match.info_notes)


def test_helm_values_matcher_resolve_resources_creates_map() -> None:
	# Intended behavior: create the resources map when containers exist.
	doc = _load_doc("helmrelease_app_template_resources_missing.yaml")
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="chronyd"), controller="main", container="app")

	matcher = HelmReleaseMatcher(
		hr_index={},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	resources, changed, notes = matcher.resolve_resources(doc, target, loc)
	assert isinstance(resources, CommentedMap)
	assert changed is True
	assert notes == []


def test_helm_values_matcher_describe_match_uses_resource_identity() -> None:
	# Intended behavior: include resource identity at the start of the label.
	doc = _load_doc("helmrelease_app_template_resources_missing.yaml")
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="chronyd"), controller="main", container="app")

	matcher = HelmReleaseMatcher(
		hr_index={},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	label = matcher.describe_match(target, doc)
	assert label.startswith("HelmRelease default/chronyd")
	assert label.endswith("(helmrelease)")


def test_helmrelease_matcher_uses_values_resources_when_single_workload() -> None:
	# Intended behavior: use spec.values.resources when a single workload is associated.
	doc = _load_doc("helmrelease_trivy_operator_comments.yaml")
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="trivy-system", name="trivy-operator"), controller="main", container="main")
	rec_map = {target: RecommendedResources(req_cpu_cores=0.5)}

	matcher = HelmReleaseMatcher(
		hr_index={target.resource: [loc]},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	target_match = next(iter(matcher.iter_targets(rec_map)))
	assert target_match.match is not None
	resources, changed, notes = matcher.resolve_resources(doc, target, target_match.match.locs[0])
	assert isinstance(resources, CommentedMap)
	assert changed is False
	assert notes == []


def test_helmrelease_matcher_skips_when_multiple_workloads() -> None:
	# Intended behavior: skip heuristic when multiple workloads share a HelmRelease.
	doc = _load_doc("helmrelease_trivy_operator_comments.yaml")
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	resource = ResourceRef(kind="HelmRelease", namespace="trivy-system", name="trivy-operator")
	target_a = TargetKey(resource=resource, controller="a", container="a")
	target_b = TargetKey(resource=resource, controller="b", container="b")
	rec_map = {
		target_a: RecommendedResources(req_cpu_cores=0.5),
		target_b: RecommendedResources(req_cpu_cores=0.6),
	}

	matcher = HelmReleaseMatcher(
		hr_index={resource: [loc]},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	target_match = next(iter(matcher.iter_targets(rec_map)))
	resources, changed, notes = matcher.resolve_resources(doc, target_match.target_key, target_match.match.locs[0])
	assert resources is None
	assert changed is False
	assert any("single workload" in note for note in notes)


def test_helmrelease_matcher_skips_when_resources_missing() -> None:
	# Intended behavior: skip heuristic when spec.values.resources is missing or wrong type.
	doc = _load_doc("helmrelease_custom_chart_missing_resources.yaml")
	loc = HrDocLoc(path=Path("fake.yaml"), doc_index=0, doc=doc)
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="krr"), controller="main", container="app")

	matcher = HelmReleaseMatcher(
		hr_index={target.resource: [loc]},
		hr_index_by_name={},
		no_name_fallback=True,
	)

	_ = next(iter(matcher.iter_targets({target: RecommendedResources(req_cpu_cores=0.5)})))
	resources, changed, notes = matcher.resolve_resources(doc, target, loc)
	assert resources is None
	assert changed is False
	assert any("spec.values.resources" in note for note in notes)
