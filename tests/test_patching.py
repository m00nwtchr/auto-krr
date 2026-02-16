from ruamel.yaml.comments import CommentedMap

from auto_krr.patching import _apply_to_resources_map
from auto_krr.types import RecommendedResources


def test_apply_to_resources_map_replaces_null_section() -> None:
	resources = CommentedMap(
		{
			"requests": CommentedMap({"cpu": "10m"}),
			"limits": None,
		}
	)

	rec = RecommendedResources()
	rec.lim_mem_bytes = 492 * 1024 * 1024

	changed, notes = _apply_to_resources_map(resources, rec=rec, only_missing=False)

	assert changed is True
	assert resources["limits"]["memory"] == "492Mi"
	assert any("limits.memory" in note for note in notes)
