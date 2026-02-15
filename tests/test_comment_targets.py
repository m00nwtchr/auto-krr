from pathlib import Path

from ruamel.yaml.comments import CommentedMap

from auto_krr.comment_targets import _find_krr_comment_targets
from auto_krr.yaml_utils import _read_all_yaml_docs


def test_find_krr_comment_targets_trivy_operator() -> None:
	# Intended behavior: only comments attached to the resources key should be matched.
	path = Path(__file__).parent / "fixtures" / "manifests" / "helmrelease_trivy_operator_comments.yaml"
	raw, docs, _ = _read_all_yaml_docs(path)
	assert len(docs) == 1
	doc = docs[0]
	assert isinstance(doc, CommentedMap)

	matches = _find_krr_comment_targets(doc, raw_lines=raw.splitlines())
	assert {(m.controller, m.container) for m in matches} == {
		("trivy-server", "trivy-server"),
		("trivy-operator", "trivy-operator"),
	}
	paths = [m.resources_path for m in matches]
	assert ["spec", "values", "resources"] in paths
	assert ["spec", "values", "trivy", "server", "resources"] in paths


def test_find_krr_comment_targets_trailing_comment() -> None:
	# Intended behavior: trailing comments after the resources block are invalid.
	path = Path(__file__).parent / "fixtures" / "manifests" / "helmrelease_comment_trailing.yaml"
	raw, docs, _ = _read_all_yaml_docs(path)
	assert len(docs) == 1
	doc = docs[0]
	assert isinstance(doc, CommentedMap)

	matches = _find_krr_comment_targets(doc, raw_lines=raw.splitlines())
	assert matches == []


def test_find_krr_comment_targets_above_resources() -> None:
	# Intended behavior: comments directly above the resources key are valid.
	path = Path(__file__).parent / "fixtures" / "manifests" / "helmrelease_comment_above_resources.yaml"
	raw, docs, _ = _read_all_yaml_docs(path)
	assert len(docs) == 1
	doc = docs[0]
	assert isinstance(doc, CommentedMap)

	matches = _find_krr_comment_targets(doc, raw_lines=raw.splitlines())
	assert {(m.controller, m.container) for m in matches} == {("trivy-server", "trivy-server")}


def test_find_krr_comment_targets_prev_key_comment() -> None:
	# Intended behavior: comments on the previous key are invalid.
	path = Path(__file__).parent / "fixtures" / "manifests" / "helmrelease_comment_prev_key.yaml"
	raw, docs, _ = _read_all_yaml_docs(path)
	assert len(docs) == 1
	doc = docs[0]
	assert isinstance(doc, CommentedMap)

	matches = _find_krr_comment_targets(doc, raw_lines=raw.splitlines())
	assert matches == []
