from pathlib import Path

from auto_krr.comment_validation import CommentValidationFinding, validate_comments
from auto_krr.flate_discovery import DiscoveryBatch, DiscoveryResult, ReleaseIdentity
from auto_krr.types import CommentTargetLoc, ResourceRef, TargetKey


def _target() -> TargetKey:
	return TargetKey(resource=ResourceRef(kind="HelmRelease", namespace="default", name="demo"), controller="demo", container="app")


def _location(path: list[object]) -> CommentTargetLoc:
	return CommentTargetLoc(path=Path("demo.yaml"), doc_index=0, resources_path=path)


def _batch(**result_kwargs) -> DiscoveryBatch:
	identity = ReleaseIdentity("default", "demo", Path("demo.yaml"), 0)
	return DiscoveryBatch(results={identity: DiscoveryResult(identity=identity, **result_kwargs)})


def test_sole_matching_comment_is_reported_unnecessary_without_mutation() -> None:
	comment_path = ["spec", "values", "controllers", "demo", "containers", "app", "resources"]
	comments = {_target(): [_location(comment_path)]}

	findings = validate_comments(comments, _batch(paths={("demo", "app"): comment_path}), include_non_krr_targets=True)

	assert len(findings) == 1
	assert findings[0].classification == "unnecessary"
	assert findings[0].current_path == tuple(comment_path)
	assert findings[0].expected_paths == (tuple(comment_path),)


def test_wrong_comment_reports_discovered_path_but_does_not_override_comment() -> None:
	comment_path = ["spec", "values", "workloads", "demo", "containers", "app", "resources"]
	discovered_path = ["spec", "values", "controllers", "demo", "containers", "app", "resources"]
	comments = {_target(): [_location(comment_path)]}

	findings = validate_comments(comments, _batch(paths={("demo", "app"): discovered_path}), include_non_krr_targets=True)

	assert findings[0].classification == "wrong"
	assert findings[0].current_path == tuple(comment_path)
	assert findings[0].expected_paths == (tuple(discovered_path),)
	assert "# krr: controller=demo container=app" in findings[0].suggestion


def test_ambiguous_or_failed_discovery_is_unvalidated() -> None:
	comments = {_target(): [_location(["spec", "values", "controllers", "demo", "containers", "app", "resources"])]}
	ambiguous = validate_comments(
		comments,
		_batch(ambiguous={("demo", "app"): [["spec", "values", "one"], ["spec", "values", "two"]]}),
		include_non_krr_targets=True,
	)
	failed = validate_comments(comments, _batch(failed=["render failed"]), include_non_krr_targets=True)

	assert ambiguous[0].classification == "unvalidated"
	assert failed[0].classification == "unvalidated"


def test_comments_without_current_krr_entry_and_custom_resource_are_inspected() -> None:
	custom_target = TargetKey(resource=ResourceRef(kind="Widget", namespace="default", name="custom"), controller="custom", container="app")
	comments = {custom_target: [_location(["spec", "resources"])]}

	findings = validate_comments(comments, DiscoveryBatch(), include_non_krr_targets=True)

	assert len(findings) == 1
	assert isinstance(findings[0], CommentValidationFinding)
	assert findings[0].classification == "unvalidated"
