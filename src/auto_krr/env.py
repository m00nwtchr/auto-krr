from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def _env_get(*names: str) -> Optional[str]:
	for n in names:
		v = os.environ.get(n)
		if v is None:
			continue
		v = v.strip()
		if v == "":
			continue
		return v
	return None


def _env_key(name: str) -> str:
	return name


def _env_candidates(name: str) -> list[str]:
	return [name, f"APPLY_KRR_{name}"]


def _env_str(name: str, default: Optional[str] = None) -> Optional[str]:
	return _env_get(*_env_candidates(name)) or default


def _env_path(name: str, default: Optional[Path] = None) -> Optional[Path]:
	v = _env_get(*_env_candidates(name))
	if v is None:
		return default
	return Path(v)


def _env_bool(name: str, default: bool = False) -> bool:
	v = _env_get(*_env_candidates(name))
	if v is None:
		return default
	v = v.strip().lower()
	if v in ("1", "true", "yes", "y", "on"):
		return True
	if v in ("0", "false", "no", "n", "off"):
		return False
	return default
