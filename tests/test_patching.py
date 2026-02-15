from ruamel.yaml.comments import CommentedMap

from auto_krr.patching import _apply_to_hr_doc, _cpu_qty, _mem_qty, _pick_container_key, _pick_controller_key
from auto_krr.types import RecommendedResources, ResourceRef, TargetKey


def test_cpu_mem_qty_rounding() -> None:
	# Intended behavior: round CPU/memory quantities up to valid units.
	assert _cpu_qty(0.5) == "500m"
	assert _cpu_qty(1.0) == "1"
	assert _cpu_qty(0.0001) == "1m"

	assert _mem_qty(1024 * 1024) == "1Mi"
	assert _mem_qty(1024 * 1024 * 1024) == "1Gi"
	assert _mem_qty(1) == "1Mi"


def test_pick_controller_and_container_keys() -> None:
	# Intended behavior: pick deterministic fallbacks for controller/container selection.
	controllers = CommentedMap()
	controllers["main"] = CommentedMap()
	controllers["worker"] = CommentedMap()
	assert _pick_controller_key(controllers, "missing", "app") == "main"

	controllers = CommentedMap()
	controllers["app"] = CommentedMap()
	assert _pick_controller_key(controllers, "missing", "app") == "app"

	containers = CommentedMap()
	containers["main"] = CommentedMap()
	containers["sidecar"] = CommentedMap()
	assert _pick_container_key(containers, "missing") == "main"

	containers = CommentedMap()
	containers["only"] = CommentedMap()
	assert _pick_container_key(containers, "missing") == "only"


def test_apply_to_hr_doc_only_missing() -> None:
	# Intended behavior: only fill missing values when only_missing=True.
	requests = CommentedMap({"cpu": "250m"})
	resources = CommentedMap({"requests": requests})
	containers = CommentedMap({"app": CommentedMap({"resources": resources})})
	controllers = CommentedMap({"main": CommentedMap({"containers": containers})})
	values = CommentedMap({"controllers": controllers})
	spec = CommentedMap({"values": values})
	doc = CommentedMap({"spec": spec})
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="app"), controller="main", container="app")
	rec = RecommendedResources(req_cpu_cores=0.5, req_mem_bytes=1024 * 1024)

	changed, notes = _apply_to_hr_doc(doc, target=target, rec=rec, only_missing=True)
	assert changed is True
	assert any("SKIP: requests.cpu already set" in n for n in notes)
	assert doc["spec"]["values"]["controllers"]["main"]["containers"]["app"]["resources"]["requests"]["memory"] == "1Mi"


def test_apply_to_hr_doc_overwrite() -> None:
	# Intended behavior: overwrite values when only_missing=False.
	requests = CommentedMap({"cpu": "250m"})
	resources = CommentedMap({"requests": requests})
	containers = CommentedMap({"app": CommentedMap({"resources": resources})})
	controllers = CommentedMap({"main": CommentedMap({"containers": containers})})
	values = CommentedMap({"controllers": controllers})
	spec = CommentedMap({"values": values})
	doc = CommentedMap({"spec": spec})
	target = TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="app"), controller="main", container="app")
	rec = RecommendedResources(req_cpu_cores=0.5)

	changed, notes = _apply_to_hr_doc(doc, target=target, rec=rec, only_missing=False)
	assert changed is True
	assert any("requests.cpu" in n for n in notes)
	assert doc["spec"]["values"]["controllers"]["main"]["containers"]["app"]["resources"]["requests"]["cpu"] == "500m"
