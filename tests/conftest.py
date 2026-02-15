from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
PKG_ROOT = SRC_ROOT / "auto_krr"

if str(SRC_ROOT) not in sys.path:
	sys.path.insert(0, str(SRC_ROOT))

for name in list(sys.modules):
	if name == "auto_krr" or name.startswith("auto_krr."):
		del sys.modules[name]

spec = importlib.util.spec_from_file_location(
	"auto_krr",
	PKG_ROOT / "__init__.py",
	submodule_search_locations=[str(PKG_ROOT)],
)
module = importlib.util.module_from_spec(spec)
sys.modules["auto_krr"] = module
assert spec.loader is not None
spec.loader.exec_module(module)
