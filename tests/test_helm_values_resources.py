from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from auto_krr.patching import _apply_to_hr_doc
from auto_krr.types import HrRef, RecommendedResources, TargetKey
from auto_krr.yaml_utils import _read_all_yaml_docs


def _load_doc(name: str) -> CommentedMap:
	path = Path(__file__).parent / "fixtures" / "manifests" / name
	_, docs, _ = _read_all_yaml_docs(path)
	assert len(docs) == 1
	doc = docs[0]
	assert isinstance(doc, CommentedMap)
	return doc


def test_apply_to_hr_doc_skips_when_containers_missing() -> None:
	# Intended behavior: never create containers, only skip when missing.
	doc = _load_doc("helmrelease_app_template_missing_containers.yaml")
	target = TargetKey(hr=HrRef(namespace="default", name="krr"), controller="krr", container="app")
	rec = RecommendedResources(req_cpu_cores=0.5)

	changed, notes = _apply_to_hr_doc(doc, target=target, rec=rec, only_missing=False)
	assert changed is False
	assert any("SKIP: containers is not a mapping" in note for note in notes)


def test_resources_inserted_alphabetically() -> None:
	# Intended behavior: create resources and insert the key alphabetically.
	doc = _load_doc("helmrelease_app_template_resources_missing.yaml")
	target = TargetKey(hr=HrRef(namespace="default", name="chronyd"), controller="main", container="app")
	rec = RecommendedResources(req_cpu_cores=0.5)

	changed, notes = _apply_to_hr_doc(doc, target=target, rec=rec, only_missing=False)
	assert changed is True
	assert any("requests.cpu" in note for note in notes)

	container = doc["spec"]["values"]["controllers"]["main"]["containers"]["app"]
	keys = list(container.keys())
	assert keys == ["env", "image", "resources", "securityContext"]
