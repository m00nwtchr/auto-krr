from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .crd_schema import CrdSchemaReport
from .flate_discovery import DiscoveryBatch, ReleaseIdentity


@dataclass(frozen=True)
class MatchOption:
	path: Tuple[object, ...]
	comment: str = ""

	@property
	def path_text(self) -> str:
		return ".".join(str(part) for part in self.path)


@dataclass(frozen=True)
class UnambiguousFinding:
	target: str
	path: Tuple[object, ...]
	provenance: str = "auto"
	details: Tuple[str, ...] = ()

	@property
	def path_text(self) -> str:
		return ".".join(str(part) for part in self.path)


@dataclass(frozen=True)
class SuggestedFinding:
	target: str
	reason: str
	provenance: str
	options: Tuple[MatchOption, ...] = ()
	details: Tuple[str, ...] = ()


@dataclass(frozen=True)
class FailedFinding:
	target: str
	reason: str
	provenance: str = "discovery"
	details: Tuple[str, ...] = ()


@dataclass
class DiscoveryReport:
	unambiguous: List[UnambiguousFinding] = field(default_factory=list)
	suggested: List[SuggestedFinding] = field(default_factory=list)
	failed: List[FailedFinding] = field(default_factory=list)
	debug: List[Mapping[str, object]] = field(default_factory=list)

	def legacy_summary(self) -> Dict[str, List[str]]:
		return {
			"unambiguous": [render_unambiguous(finding) for finding in self.unambiguous],
			"suggested": [render_suggested(finding) for finding in self.suggested],
			"failed": [render_failed(finding) for finding in self.failed],
		}


def build_discovery_report(
	batch: DiscoveryBatch,
	crd_report: Optional[CrdSchemaReport],
	rec_map: Dict[object, object],
	comment_index: Optional[Mapping[object, Sequence[object]]] = None,
) -> DiscoveryReport:
	report = DiscoveryReport()
	for identity, result in sorted(batch.results.items(), key=lambda item: _identity_sort_key(item[0])):
		for (controller, container), path in sorted(result.paths.items()):
			report.unambiguous.append(
				UnambiguousFinding(
					target=_target_label(identity, controller, container),
					path=tuple(path),
					provenance="auto",
				)
			)
		for (controller, container), paths in sorted(result.ambiguous.items()):
			options = tuple(
				MatchOption(tuple(path), _comment_template(controller, container))
				for path in sorted((tuple(path) for path in paths), key=_path_sort_key)
			)
			report.suggested.append(
				SuggestedFinding(
					target=_target_label(identity, controller, container),
					reason="automatic mapping is ambiguous; no change was applied",
					provenance="ambiguous",
					options=options,
				)
			)
		for path in sorted((tuple(path) for path in result.unmapped), key=_path_sort_key):
			report.suggested.append(
				SuggestedFinding(
					target=_identity_label(identity),
					reason="candidate path was not consumed by a rendered workload/container",
					provenance="unmapped",
					options=(MatchOption(path),),
				)
			)
		for detail in result.failed:
			report.failed.append(
				FailedFinding(
					target=_identity_label(identity),
					reason=detail,
					provenance="flate",
				)
			)

	if crd_report is not None:
		report.debug.extend(crd_report.debug)
		for definition in crd_report.definitions:
			report.suggested.append(
				SuggestedFinding(
					target=f"{definition.kind} {definition.api_version}",
					reason="CRD schema evidence cannot establish a workload/container mapping",
					provenance=definition.source,
					options=(MatchOption(tuple(definition.schema_path)),),
					details=(f"confidence={definition.confidence}", f"crd={definition.crd_name}"),
				)
			)
		for detail in crd_report.failed:
			report.failed.append(FailedFinding(target="CRD schema discovery", reason=detail, provenance="crd"))

	if comment_index:
		for target, locations in sorted(comment_index.items(), key=lambda item: str(item[0])):
			for location in locations:
				path = getattr(location, "resources_path", None)
				if path is None:
					continue
				report.unambiguous.append(
					UnambiguousFinding(
						target=str(target),
						path=tuple(path),
						provenance="explicit-comment",
					)
				)
	return report


def render_unambiguous(finding: UnambiguousFinding) -> str:
	return f"{finding.target} -> {finding.path_text} ({finding.provenance})"


def render_suggested(finding: SuggestedFinding) -> str:
	lines = [f"Suggested match: {finding.target}", f"Reason: {finding.reason}"]
	if finding.provenance:
		lines.append(f"Provenance: {finding.provenance}")
	if finding.options:
		lines.append("Options:")
		for index, option in enumerate(finding.options, start=1):
			lines.append(f"  {index}. {option.path_text}")
			if option.comment:
				lines.append(f"     {option.comment}")
	lines.extend(f"Detail: {detail}" for detail in finding.details)
	return "\n".join(lines)


def render_failed(finding: FailedFinding) -> str:
	return f"{finding.target}: {finding.reason} ({finding.provenance})"


def _identity_label(identity: ReleaseIdentity) -> str:
	return f"HelmRelease {identity.namespace}/{identity.name}"


def _target_label(identity: ReleaseIdentity, controller: str, container: str) -> str:
	return f"{_identity_label(identity)} controller={controller} container={container}"


def _comment_template(controller: str, container: str) -> str:
	return f"# krr: controller={controller} container={container}"


def _identity_sort_key(identity: ReleaseIdentity) -> Tuple[str, str, str, int]:
	return identity.namespace, identity.name, identity.manifest_path.as_posix(), identity.doc_index


def _path_sort_key(path: Tuple[object, ...]) -> Tuple[str, ...]:
	return tuple(str(part) for part in path)
