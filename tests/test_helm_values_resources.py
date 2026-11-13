from ruamel.yaml.comments import CommentedMap

from auto_krr.patching import _apply_to_hr_doc, _resolve_resources_path
from auto_krr.types import RecommendedResources


def _doc(values: CommentedMap) -> CommentedMap:
	return CommentedMap({"spec": CommentedMap({"values": values})})


def test_resolve_nested_discovered_path_without_chart_shape() -> None:
	values = CommentedMap(
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
	doc = _doc(values)

	resources, changed, notes = _resolve_resources_path(
		doc,
		["spec", "values", "worker", "containers", "app", "resources"],
		create_missing=True,
	)

	assert isinstance(resources, CommentedMap)
	assert changed is True
	assert notes == []
	assert doc["spec"]["values"]["worker"]["containers"]["app"]["resources"] == {}


def test_resolve_creates_missing_intermediate_maps() -> None:
	doc = CommentedMap()

	resources, changed, notes = _resolve_resources_path(
		doc,
		["spec", "values", "controller", "containers", "app", "resources"],
		create_missing=True,
	)

	assert isinstance(resources, CommentedMap)
	assert changed is True
	assert notes == []
	assert doc["spec"]["values"]["controller"]["containers"]["app"]["resources"] == {}


def test_resolve_skips_non_mapping_component() -> None:
	doc = _doc(CommentedMap({"worker": "not-a-map"}))

	resources, changed, notes = _resolve_resources_path(
		doc,
		["spec", "values", "worker", "resources"],
		create_missing=True,
	)

	assert resources is None
	assert changed is False
	assert any("not a mapping" in note for note in notes)


def test_apply_to_hr_doc_preserves_only_missing_and_converts_quantities() -> None:
	resources = CommentedMap(
		{
			"requests": CommentedMap({"cpu": "10m"}),
			"limits": CommentedMap({}),
		}
	)
	doc = _doc(
		CommentedMap(
			{
				"worker": CommentedMap(
					{
						"resources": resources,
					}
				)
			}
		)
	)

	changed, notes = _apply_to_hr_doc(
		doc,
		resources_path=["spec", "values", "worker", "resources"],
		rec=RecommendedResources(req_cpu_cores=0.5, req_mem_bytes=1024 * 1024, lim_mem_bytes=2 * 1024 * 1024),
		only_missing=True,
	)

	assert changed is True
	assert resources["requests"]["cpu"] == "10m"
	assert resources["requests"]["memory"] == "1Mi"
	assert resources["limits"]["memory"] == "2Mi"
	assert any("already set" in note for note in notes)
