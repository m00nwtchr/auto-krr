import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

import auto_krr.flate_discovery as flate_discovery
from auto_krr.flate_discovery import DiscoveryBatch, FlateDiscovery, ReleaseIdentity, _chart_source_doc
from auto_krr.helm_values import ChartCandidate, ChartRef, ChartValues
from auto_krr.sentinels import ProbeCandidate, allocate_sentinels
from auto_krr.types import HrDocLoc
from auto_krr.yaml_utils import _read_all_yaml_docs


def _write_executable(path: Path, body: str) -> None:
	path.write_text(body, encoding="utf-8")
	path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _hr_loc(tmp_path: Path) -> HrDocLoc:
	path = tmp_path / "hr.yaml"
	path.write_text(
		"""\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: default
spec:
  chartRef:
    kind: OCIRepository
    name: chart
  values: {}
""",
		encoding="utf-8",
	)
	_, docs, _ = _read_all_yaml_docs(path)
	assert isinstance(docs[0], CommentedMap)
	return HrDocLoc(path=path, doc_index=0, doc=docs[0])


def _git_repo_with_releases(tmp_path: Path) -> tuple[Path, list[HrDocLoc]]:
	repo = tmp_path / "repo"
	(repo / "one").mkdir(parents=True)
	(repo / "two").mkdir(parents=True)
	for directory, namespace, name in (("one", "one", "release-one"), ("two", "two", "release-two")):
		path = repo / directory / "helmrelease.yaml"
		path.write_text(
			f"""\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: {name}
  namespace: {namespace}
spec:
  chartRef:
    kind: OCIRepository
    name: chart
  values:
    controllers:
      main:
        containers:
          app:
            image: example/app:1
""",
			encoding="utf-8",
		)
	subprocess.run(["git", "init", "-q", str(repo)], check=True)
	subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
	subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
	subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
	subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
	locs = []
	for directory in ("one", "two"):
		path = repo / directory / "helmrelease.yaml"
		_, docs, _ = _read_all_yaml_docs(path)
		assert isinstance(docs[0], CommentedMap)
		locs.append(HrDocLoc(path=path, doc_index=0, doc=docs[0]))
	return repo, locs


def _write_batch_flater(path: Path, count_path: Path) -> None:
	_write_executable(
		path,
		f"""#!{sys.executable}
import json
import os
from pathlib import Path
from ruamel.yaml import YAML

count = Path({str(count_path)!r})
count.write_text(str(int(count.read_text() or '0') + 1) if count.exists() else '1')
yaml = YAML(typ='safe')
mode = os.environ.get('AUTO_KRR_FAKE_FLATE_MODE', 'normal')
hrs = []
for filename in sorted(Path.cwd().rglob('*.yaml')):
    for doc in yaml.load_all(filename.read_text()):
        if isinstance(doc, dict) and doc.get('kind') == 'HelmRelease':
            hrs.append(doc)

def find_resources(node):
    if isinstance(node, dict):
        if isinstance(node.get('resources'), dict):
            return node['resources']
        for value in node.values():
            found = find_resources(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = find_resources(value)
            if found is not None:
                return found
    return None

def workload(hr, resources, container='app'):
    metadata = hr.get('metadata') or {{}}
    return {{
        'apiVersion': 'apps/v1',
        'kind': 'Deployment',
        'metadata': {{'name': metadata.get('name'), 'namespace': metadata.get('namespace')}},
        'spec': {{'template': {{'spec': {{'containers': [{{'name': container, 'resources': resources}}]}}}}}},
    }}

outputs = []
if mode == 'partial':
    outputs.append(workload(hrs[0], find_resources(hrs[0])))
elif mode == 'ambiguous':
    merged = {{'requests': {{}}, 'limits': {{}}}}
    for index, hr in enumerate(hrs):
        resources = find_resources(hr) or {{}}
        for section in ('requests', 'limits'):
            for field, value in (resources.get(section) or {{}}).items():
                merged[section][f'{{field}}-{{index}}'] = value
    outputs.append(workload(hrs[0], merged))
elif mode == 'unmapped':
    outputs.append(workload(hrs[0], {{'requests': {{'cpu': '1m'}}}}))
else:
    for hr in hrs:
        resources = find_resources(hr)
        outputs.append(workload(hr, resources))
        if mode == 'fanout':
            outputs.append(workload(hr, resources, container='sidecar'))

print('\\n---\\n'.join(json.dumps(item) for item in outputs))
if mode == 'partial':
    raise SystemExit(7)
""",
	)


def _patch_chart_loader(monkeypatch) -> None:
	monkeypatch.setattr(
		flate_discovery,
		"_resolve_chart_ref",
		lambda _repo_root, _doc: ChartRef(
			chart="demo",
			version="1.0.0",
			source_kind="OCIRepository",
			source_url="oci://example.test/demo",
		),
	)
	monkeypatch.setattr(
		flate_discovery,
		"_load_chart_values",
		lambda _ref, _helm_bin, _cache_dir: ChartValues(defaults=CommentedMap(), schema={}),
	)
	monkeypatch.setattr(
		flate_discovery,
		"_enumerate_resource_candidates",
		lambda _chart_values, _release_values: [
			ChartCandidate(["controllers", "main", "containers", "app", "resources"]),
			ChartCandidate(["controllers", "worker", "containers", "sidecar", "resources"]),
		],
	)


def _test_sentinels(*paths: tuple[object, ...]):
	candidates = [
		ProbeCandidate(
			manifest_path=Path("hr.yaml"),
			doc_index=0,
			namespace="default",
			release_name="demo",
			value_path=path,
		)
		for path in paths
	]
	return [allocate_sentinels(candidates, set())[candidate] for candidate in candidates]


def test_flate_maps_workloads_and_init_containers_and_caches(tmp_path: Path, monkeypatch) -> None:
	_patch_chart_loader(monkeypatch)
	first_sentinel, second_sentinel = _test_sentinels(
		("controllers", "main", "containers", "app", "resources"),
		("controllers", "worker", "containers", "sidecar", "resources"),
	)
	count_path = tmp_path / "count"
	flate_bin = tmp_path / "fake-flate"
	_write_executable(
		flate_bin,
		f"""#!/usr/bin/env python3
from pathlib import Path

count = Path({str(count_path)!r})
count.write_text(str(int(count.read_text() or '0') + 1) if count.exists() else '1')
print('''---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: app
          resources:
            requests:
              cpu: {first_sentinel.requests_cpu}
            limits:
                  memory: {first_sentinel.limits_memory}
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cron-demo
spec:
  jobTemplate:
    spec:
      template:
        spec:
          initContainers:
            - name: init
              resources:
                requests:
                  cpu: {second_sentinel.requests_cpu}
          containers:
            - name: worker
              resources: {{}}
''')
""",
	)
	loc = _hr_loc(tmp_path)
	discovery = FlateDiscovery(tmp_path, flate_bin=str(flate_bin), helm_bin="helm")

	first = discovery.discover(loc)
	second = discovery.discover(loc)

	assert first.path_for("demo", "app") == ["spec", "values", "controllers", "main", "containers", "app", "resources"]
	assert first.path_for("cron-demo", "init") == ["spec", "values", "controllers", "worker", "containers", "sidecar", "resources"]
	assert second.path_for("demo", "app") == first.path_for("demo", "app")
	assert count_path.read_text(encoding="utf-8") == "1"


def test_flate_reports_ambiguous_container_mapping(tmp_path: Path, monkeypatch) -> None:
	_patch_chart_loader(monkeypatch)
	first_sentinel, second_sentinel = _test_sentinels(
		("controllers", "main", "containers", "app", "resources"),
		("controllers", "worker", "containers", "sidecar", "resources"),
	)
	flate_bin = tmp_path / "fake-flate"
	_write_executable(
		flate_bin,
		f"""#!/usr/bin/env python3
print('''apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: app
          resources:
            requests:
              cpu: {first_sentinel.requests_cpu}
            limits:
              cpu: {second_sentinel.requests_cpu}
''')
""",
	)

	result = FlateDiscovery(tmp_path, flate_bin=str(flate_bin)).discover(_hr_loc(tmp_path))

	assert result.path_for("demo", "app") is None
	assert any("ambiguous" in note for note in result.notes)


def test_flate_missing_binary_returns_skip_note(tmp_path: Path, monkeypatch) -> None:
	_patch_chart_loader(monkeypatch)

	result = FlateDiscovery(tmp_path, flate_bin=str(tmp_path / "missing-flate")).discover(_hr_loc(tmp_path))

	assert result.path_for("demo", "app") is None
	assert any("flate" in note.lower() and "failed" in note.lower() for note in result.notes)


def test_flate_nonzero_and_malformed_output_return_skip_notes(tmp_path: Path, monkeypatch) -> None:
	_patch_chart_loader(monkeypatch)
	loc = _hr_loc(tmp_path)

	failed_bin = tmp_path / "failed-flate"
	_write_executable(
		failed_bin,
		"""#!/usr/bin/env python3
import sys
print('render failed', file=sys.stderr)
sys.exit(3)
""",
	)
	failed = FlateDiscovery(tmp_path, flate_bin=str(failed_bin)).discover(loc)
	assert any("render failed" in note for note in failed.notes)

	malformed_bin = tmp_path / "malformed-flate"
	_write_executable(malformed_bin, "#!/usr/bin/env python3\nprint('not: [yaml')\n")
	malformed = FlateDiscovery(tmp_path, flate_bin=str(malformed_bin)).discover(loc)
	assert any("parse" in note.lower() for note in malformed.notes)


def test_flate_without_matching_sentinel_returns_skip_note(tmp_path: Path, monkeypatch) -> None:
	_patch_chart_loader(monkeypatch)
	flate_bin = tmp_path / "no-match-flate"
	_write_executable(
		flate_bin,
		"""#!/usr/bin/env python3
print('''apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  containers:
    - name: app
      resources:
        requests:
          cpu: 1m
''')
""",
	)

	result = FlateDiscovery(tmp_path, flate_bin=str(flate_bin)).discover(_hr_loc(tmp_path))

	assert result.path_for("demo", "app") is None
	assert any("no resource sentinel" in note for note in result.notes)


def test_chart_source_supply_uses_effective_release_namespace() -> None:
	doc = YAML(typ="rt").load(
		"""\
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
  namespace: media
spec:
  chartRef:
    kind: OCIRepository
    name: chart
"""
	)
	assert isinstance(doc, CommentedMap)
	chart_ref = ChartRef(
		chart="oci://example.test/chart",
		version="1.0.0",
		source_kind="OCIRepository",
		source_url="oci://example.test/chart",
		source_name="chart",
		source_namespace="media",
	)

	source = _chart_source_doc(doc, chart_ref)

	assert source["metadata"]["name"] == "chart"
	assert source["metadata"]["namespace"] == "media"


def test_discover_many_renders_in_place_once_and_preserves_source(tmp_path: Path, monkeypatch) -> None:
	repo, locs = _git_repo_with_releases(tmp_path)
	_patch_chart_loader(monkeypatch)
	count_path = tmp_path / "count"
	flate_bin = tmp_path / "fake-flate"
	_write_batch_flater(flate_bin, count_path)
	before = (repo / "one" / "helmrelease.yaml").read_bytes()

	batch = FlateDiscovery(repo, flate_bin=str(flate_bin)).discover_many(locs)

	assert isinstance(batch, DiscoveryBatch)
	assert batch.render_invocations == 1
	assert count_path.read_text(encoding="utf-8") == "1"
	assert batch.command is not None
	assert batch.command[1:3] == ["build", "-p"]
	assert "hr" not in batch.command
	assert (repo / "one" / "helmrelease.yaml").read_bytes() == before
	assert subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout == ""
	assert batch.path_for(ReleaseIdentity("one", "release-one", Path("one/helmrelease.yaml"), 0), "release-one", "app") == [
		"spec", "values", "controllers", "main", "containers", "app", "resources"
	]
	assert batch.path_for(ReleaseIdentity("two", "release-two", Path("two/helmrelease.yaml"), 0), "release-two", "app") == [
		"spec", "values", "controllers", "main", "containers", "app", "resources"
	]


def test_discover_many_keeps_partial_output_and_records_failed_release(tmp_path: Path, monkeypatch) -> None:
	repo, locs = _git_repo_with_releases(tmp_path)
	_patch_chart_loader(monkeypatch)
	monkeypatch.setenv("AUTO_KRR_FAKE_FLATE_MODE", "partial")
	flate_bin = tmp_path / "fake-flate"
	_write_batch_flater(flate_bin, tmp_path / "count")
	batch = FlateDiscovery(repo, flate_bin=str(flate_bin)).discover_many(locs)

	assert batch.results[ReleaseIdentity("one", "release-one", Path("one/helmrelease.yaml"), 0)].paths
	failed = batch.results[ReleaseIdentity("two", "release-two", Path("two/helmrelease.yaml"), 0)]
	assert failed.failed
	assert any("exit" in note.lower() or "failed" in note.lower() for note in failed.notes)


def test_discover_many_rejects_cross_release_sentinel_consumption(tmp_path: Path, monkeypatch) -> None:
	repo, locs = _git_repo_with_releases(tmp_path)
	_patch_chart_loader(monkeypatch)
	monkeypatch.setenv("AUTO_KRR_FAKE_FLATE_MODE", "ambiguous")
	flate_bin = tmp_path / "fake-flate"
	_write_batch_flater(flate_bin, tmp_path / "count")
	batch = FlateDiscovery(repo, flate_bin=str(flate_bin)).discover_many(locs)

	assert all(result.paths == {} for result in batch.results.values())
	assert any(result.ambiguous for result in batch.results.values())


def test_discover_many_reports_fanout_and_unmapped_candidates(tmp_path: Path, monkeypatch) -> None:
	repo, locs = _git_repo_with_releases(tmp_path)
	_patch_chart_loader(monkeypatch)
	monkeypatch.setenv("AUTO_KRR_FAKE_FLATE_MODE", "fanout")
	flate_bin = tmp_path / "fake-flate"
	_write_batch_flater(flate_bin, tmp_path / "count")
	batch = FlateDiscovery(repo, flate_bin=str(flate_bin)).discover_many(locs)
	identity = ReleaseIdentity("one", "release-one", Path("one/helmrelease.yaml"), 0)
	assert batch.results[identity].path_for(identity, "release-one", "app")
	assert batch.results[identity].path_for(identity, "release-one", "sidecar")

	monkeypatch.setenv("AUTO_KRR_FAKE_FLATE_MODE", "unmapped")
	unmapped = FlateDiscovery(repo, flate_bin=str(flate_bin)).discover_many(locs)
	assert unmapped.results[identity].unmapped
