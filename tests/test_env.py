
from auto_krr.env import _env_bool, _env_get, _env_path, _env_str


def test_env_helpers(monkeypatch) -> None:
	# Intended behavior: env helpers parse and default correctly.
	monkeypatch.delenv("FOO", raising=False)
	assert _env_get("FOO", "ALT") is None
	assert _env_str("FOO", "bar") == "bar"

	monkeypatch.setenv("FOO", "1")
	assert _env_bool("FOO", False) is True
	assert _env_str("FOO", "bar") == "1"

	monkeypatch.setenv("FOO", "")
	assert _env_bool("FOO", True) is True
	assert _env_str("FOO", "bar") == "bar"

	monkeypatch.setenv("FOO", "/tmp/example")
	assert str(_env_path("FOO", None)) == "/tmp/example"
