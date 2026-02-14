from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .types import ForgejoRepo


def _http_json(
	method: str,
	url: str,
	*,
	token: str,
	auth_scheme: str,
	payload: Optional[Dict[str, Any]] = None,
	insecure_tls: bool = False,
) -> Dict[str, Any]:
	data = None
	scheme = (auth_scheme or "token").strip()
	if not scheme:
		scheme = "token"

	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json",
		"Authorization": f"{scheme} {token}",
		"User-Agent": "apply-krr.py",
	}

	if payload is not None:
		data = json.dumps(payload).encode("utf-8")

	req = urllib.request.Request(url, data=data, method=method, headers=headers)

	ctx = None
	if insecure_tls:
		ctx = ssl._create_unverified_context()

	try:
		with urllib.request.urlopen(req, context=ctx) as resp:
			body = resp.read().decode("utf-8")
			if not body:
				return {}
			return json.loads(body)
	except urllib.error.HTTPError as e:
		body = ""
		try:
			body = e.read().decode("utf-8")
		except Exception:
			pass
		raise RuntimeError(f"HTTP {e.code} {e.reason} for {url}\n{body}") from e
	except urllib.error.URLError as e:
		raise RuntimeError(f"Network error for {url}: {e}") from e


def _forgejo_create_pr(
	repo: ForgejoRepo,
	*,
	token: str,
	auth_scheme: str,
	base_branch: str,
	head_branch: str,
	title: str,
	body: str,
	insecure_tls: bool,
) -> str:
	api_prefix = repo.api_prefix.strip() or "/api/v1"
	if not api_prefix.startswith("/"):
		api_prefix = "/" + api_prefix

	api = repo.base_url.rstrip("/") + api_prefix + f"/repos/{repo.owner}/{repo.repo}/pulls"
	payload = {
		"base": base_branch,
		"head": head_branch,
		"title": title,
		"body": body,
	}
	resp = _http_json("POST", api, token=token, auth_scheme=auth_scheme, payload=payload, insecure_tls=insecure_tls)

	for k in ("html_url", "url"):
		if isinstance(resp, dict) and k in resp and isinstance(resp[k], str):
			return resp[k]
	return api
