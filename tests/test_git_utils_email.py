from pathlib import Path

import auto_krr.git_utils as git_utils


def test_host_from_url_variants() -> None:
	# Intended behavior: normalize host extraction.
	assert git_utils._host_from_url("https://example.com") == "example.com"
	assert git_utils._host_from_url("example.com") == "example.com"
	assert git_utils._host_from_url("") is None


def test_default_git_email_uses_forgejo_url(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: prefer explicit forgejo_url when provided.
	email = git_utils._default_git_email(tmp_path, "https://forgejo.example.com")
	assert email == "krr@forgejo.example.com"


def test_default_git_email_env_and_remote(monkeypatch, tmp_path: Path) -> None:
	# Intended behavior: fall back to env or remote URL when forgejo_url is absent.
	monkeypatch.setenv("FORGEJO_URL", "https://env.example.com")
	email = git_utils._default_git_email(tmp_path, None)
	assert email == "krr@env.example.com"

	monkeypatch.delenv("FORGEJO_URL", raising=False)
	monkeypatch.setattr(git_utils, "_remote_url", lambda *_: "https://remote.example.com/owner/repo.git")
	email = git_utils._default_git_email(tmp_path, None)
	assert email == "krr@remote.example.com"
