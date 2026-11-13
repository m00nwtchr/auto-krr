from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .flate_discovery import DiscoveryBatch, DiscoveryResult, ReleaseIdentity
from .types import CommentTargetLoc, TargetKey


@dataclass(frozen=True)
class CommentValidationFinding:
	location: CommentTargetLoc
	target: TargetKey
	classification: str
	current_path: Tuple[object, ...]
	expected_paths: Tuple[Tuple[object, ...], ...] = ()
	suggestion: str = ""


def validate_comments(
	comment_index: Mapping[TargetKey, Sequence[CommentTargetLoc]],
	batch: DiscoveryBatch,
	*,
	include_non_krr_targets: bool,
) -> List[CommentValidationFinding]:
	findings: List[CommentValidationFinding] = []
	for target, locations in comment_index.items():
		if not include_non_krr_targets and target.resource is None:
			continue
		for location in locations:
			current_path = tuple(location.resources_path)
			matches = _results_for(target, location, batch)
			if len(matches) != 1:
				findings.append(
					CommentValidationFinding(
						location=location,
						target=target,
						classification="unvalidated",
						current_path=current_path,
						suggestion="discovery did not identify exactly one release-scoped result; keep the explicit comment",
					)
				)
				continue

			result = matches[0]
			expected = _expected_paths(result, target)
			if len(expected) == 1 and current_path == expected[0]:
				findings.append(
					CommentValidationFinding(
						location=location,
						target=target,
						classification="unnecessary",
						current_path=current_path,
						expected_paths=expected,
						suggestion="automatic discovery is unambiguous; the explicit comment may be removed",
					)
				)
			elif expected and not result.ambiguous and not result.failed:
				findings.append(
					CommentValidationFinding(
						location=location,
						target=target,
						classification="wrong",
						current_path=current_path,
						expected_paths=expected,
						suggestion=_wrong_comment_suggestion(target, expected),
					)
				)
			else:
				findings.append(
					CommentValidationFinding(
						location=location,
						target=target,
						classification="unvalidated",
						current_path=current_path,
						expected_paths=expected,
						suggestion="automatic discovery is ambiguous, unmapped, or failed; keep the explicit comment",
					)
				)
	return findings


def _results_for(target: TargetKey, location: CommentTargetLoc, batch: DiscoveryBatch) -> List[DiscoveryResult]:
	results: List[DiscoveryResult] = []
	for identity, result in batch.results.items():
		if identity.doc_index != location.doc_index:
			continue
		if target.resource is not None and (
			identity.name != target.resource.name or identity.namespace != target.resource.namespace
		):
			continue
		identity_path = identity.manifest_path.as_posix()
		location_path = location.path.as_posix()
		if identity_path != location_path and not identity_path.endswith("/" + location_path) and not location_path.endswith("/" + identity_path):
			continue
		results.append(result)
	return results


def _expected_paths(result: DiscoveryResult, target: TargetKey) -> Tuple[Tuple[object, ...], ...]:
	paths: List[Tuple[object, ...]] = []
	path = result.paths.get((target.controller, target.container))
	if path is not None:
		paths.append(tuple(path))
	for candidate in result.ambiguous.get((target.controller, target.container), []):
		candidate_path = tuple(candidate)
		if candidate_path not in paths:
			paths.append(candidate_path)
	return tuple(paths)


def _wrong_comment_suggestion(target: TargetKey, expected: Sequence[Tuple[object, ...]]) -> str:
	comment = f"# krr: controller={target.controller} container={target.container}"
	locations = ", ".join(".".join(str(part) for part in path) for path in expected)
	return f"consider relocating the comment to {locations}: {comment}"


def render_comment_finding(finding: CommentValidationFinding) -> str:
	location = f"{finding.location.path}:{finding.location.doc_index}"
	target = f"controller={finding.target.controller} container={finding.target.container}"
	return f"{finding.classification} comment at {location} ({target}): {finding.suggestion}"
