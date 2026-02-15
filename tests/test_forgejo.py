import io
import urllib.error
import urllib.request

import pytest

from auto_krr.forgejo import _forgejo_create_pr, _forgejo_find_open_pr, _http_json
from auto_krr.types import ForgejoRepo


class _FakeResponse:
	def __init__(self, body: str) -> None:
		self._body = body.encode("utf-8")

	def read(self) -> bytes:
		return self._body

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc, tb) -> None:
		return None


def test_http_json_success(monkeypatch) -> None:
	# Intended behavior: decode JSON body into a dict.
	def _fake_urlopen(req, context=None):
		return _FakeResponse('{"ok": true}')

	monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
	out = _http_json("GET", "https://example.com", token="t", auth_scheme="token")
	assert out == {"ok": True}


def test_http_json_http_error(monkeypatch) -> None:
	# Intended behavior: HTTP errors are wrapped in RuntimeError with status code.
	body = io.BytesIO(b'{"message":"nope"}')
	err = urllib.error.HTTPError("https://example.com", 401, "Unauthorized", None, body)

	def _fake_urlopen(req, context=None):
		raise err

	monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
	with pytest.raises(RuntimeError) as exc:
		_http_json("GET", "https://example.com", token="t", auth_scheme="token")
	assert "HTTP 401" in str(exc.value)


def test_http_json_url_error(monkeypatch) -> None:
	# Intended behavior: URL errors are wrapped in RuntimeError.
	err = urllib.error.URLError("boom")

	def _fake_urlopen(req, context=None):
		raise err

	monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
	with pytest.raises(RuntimeError) as exc:
		_http_json("GET", "https://example.com", token="t", auth_scheme="token")
	assert "Network error" in str(exc.value)


def test_forgejo_create_pr_returns_html_url(monkeypatch) -> None:
	# Intended behavior: prefer html_url when present.
	repo = ForgejoRepo(base_url="https://forgejo.example.com", owner="o", repo="r", api_prefix="/api/v1")
	monkeypatch.setattr("auto_krr.forgejo._http_json", lambda *a, **k: {"html_url": "https://pr/1"})
	out = _forgejo_create_pr(
		repo,
		token="t",
		auth_scheme="token",
		base_branch="main",
		head_branch="feature",
		title="t",
		body="b",
		insecure_tls=False,
	)
	assert out == "https://pr/1"


def test_forgejo_find_open_pr_matches_head(monkeypatch) -> None:
	# Intended behavior: return html_url for matching open PR and author filter.
	repo = ForgejoRepo(base_url="https://forgejo.example.com", owner="o", repo="r", api_prefix="/api/v1")
	prs = [
		{
			"state": "open",
			"head": {"ref": "feature", "label": "o:feature"},
			"base": {"ref": "main"},
			"user": {"login": "me"},
			"html_url": "https://pr/2",
		}
	]
	monkeypatch.setattr("auto_krr.forgejo._http_json", lambda *a, **k: prs)
	out = _forgejo_find_open_pr(
		repo,
		token="t",
		auth_scheme="token",
		base_branch="main",
		head_branch="feature",
		insecure_tls=False,
		expected_authors={"me"},
	)
	assert out == "https://pr/2"
