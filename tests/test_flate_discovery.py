import stat
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

import auto_krr.flate_discovery as flate_discovery
from auto_krr.flate_discovery import FlateDiscovery
from auto_krr.helm_values import ChartCandidate, ChartRef, ChartValues
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


def test_flate_maps_workloads_and_init_containers_and_caches(tmp_path: Path, monkeypatch) -> None:
	_patch_chart_loader(monkeypatch)
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
              cpu: 1000001m
            limits:
              memory: 4000001Mi
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
                  cpu: 1000002m
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
	flate_bin = tmp_path / "fake-flate"
	_write_executable(
		flate_bin,
		"""#!/usr/bin/env python3
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
              cpu: 1000001m
            limits:
              cpu: 1000002m
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
