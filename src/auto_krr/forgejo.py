from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
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


def _forgejo_find_open_pr(
	repo: ForgejoRepo,
	*,
	token: str,
	auth_scheme: str,
	base_branch: str,
	head_branch: str,
	insecure_tls: bool,
) -> Optional[str]:
	api_prefix = repo.api_prefix.strip() or "/api/v1"
	if not api_prefix.startswith("/"):
		api_prefix = "/" + api_prefix

	query = urllib.parse.urlencode(
		{
			"state": "open",
			"base": base_branch,
			"head": f"{repo.owner}:{head_branch}",
		}
	)
	api = repo.base_url.rstrip("/") + api_prefix + f"/repos/{repo.owner}/{repo.repo}/pulls?{query}"
	resp = _http_json("GET", api, token=token, auth_scheme=auth_scheme, insecure_tls=insecure_tls)
	if not isinstance(resp, list):
		return None

	def _owner_name(h: Dict[str, Any]) -> str:
		repo_obj = h.get("repo") or {}
		owner_obj = repo_obj.get("owner") or {}
		return str(owner_obj.get("login") or owner_obj.get("username") or owner_obj.get("name") or "")

	for pr in resp:
		if not isinstance(pr, dict):
			continue
		if str(pr.get("state") or "").lower() not in ("open", ""):
			continue
		head = pr.get("head") or {}
		base = pr.get("base") or {}
		head_ref = str(head.get("ref") or head.get("name") or "")
		base_ref = str(base.get("ref") or base.get("name") or "")
		head_label = str(head.get("label") or "")
		head_owner = _owner_name(head)

		if base_ref and base_ref != base_branch:
			continue

		if head_ref == head_branch:
			pass
		elif head_label.endswith(f":{head_branch}"):
			pass
		elif head_owner and head_owner == repo.owner and head_ref == head_branch:
			pass
		else:
			continue

		for k in ("html_url", "url"):
			if k in pr and isinstance(pr[k], str):
				return pr[k]
	return None


def _forgejo_find_open_pr_data(
	repo: ForgejoRepo,
	*,
	token: str,
	auth_scheme: str,
	base_branch: str,
	head_branch: str,
	insecure_tls: bool,
) -> Optional[Dict[str, Any]]:
	api_prefix = repo.api_prefix.strip() or "/api/v1"
	if not api_prefix.startswith("/"):
		api_prefix = "/" + api_prefix

	query = urllib.parse.urlencode(
		{
			"state": "open",
			"base": base_branch,
			"head": f"{repo.owner}:{head_branch}",
		}
	)
	api = repo.base_url.rstrip("/") + api_prefix + f"/repos/{repo.owner}/{repo.repo}/pulls?{query}"
	resp = _http_json("GET", api, token=token, auth_scheme=auth_scheme, insecure_tls=insecure_tls)
	if not isinstance(resp, list):
		return None

	def _owner_name(h: Dict[str, Any]) -> str:
		repo_obj = h.get("repo") or {}
		owner_obj = repo_obj.get("owner") or {}
		return str(owner_obj.get("login") or owner_obj.get("username") or owner_obj.get("name") or "")

	for pr in resp:
		if not isinstance(pr, dict):
			continue
		if str(pr.get("state") or "").lower() not in ("open", ""):
			continue
		head = pr.get("head") or {}
		base = pr.get("base") or {}
		head_ref = str(head.get("ref") or head.get("name") or "")
		base_ref = str(base.get("ref") or base.get("name") or "")
		head_label = str(head.get("label") or "")
		head_owner = _owner_name(head)

		if base_ref and base_ref != base_branch:
			continue

		if head_ref == head_branch:
			pass
		elif head_label.endswith(f":{head_branch}"):
			pass
		elif head_owner and head_owner == repo.owner and head_ref == head_branch:
			pass
		else:
			continue

		return pr
	return None


def _forgejo_update_pr(
	repo: ForgejoRepo,
	*,
	token: str,
	auth_scheme: str,
	pr_number: int,
	title: Optional[str] = None,
	body: Optional[str] = None,
	insecure_tls: bool,
) -> str:
	api_prefix = repo.api_prefix.strip() or "/api/v1"
	if not api_prefix.startswith("/"):
		api_prefix = "/" + api_prefix

	api = repo.base_url.rstrip("/") + api_prefix + f"/repos/{repo.owner}/{repo.repo}/pulls/{pr_number}"
	payload: Dict[str, Any] = {}
	if title is not None:
		payload["title"] = title
	if body is not None:
		payload["body"] = body
	resp = _http_json("PATCH", api, token=token, auth_scheme=auth_scheme, payload=payload, insecure_tls=insecure_tls)
	for k in ("html_url", "url"):
		if isinstance(resp, dict) and k in resp and isinstance(resp[k], str):
			return resp[k]
	return api


def _forgejo_get_user(
	repo: ForgejoRepo,
	*,
	token: str,
	auth_scheme: str,
	insecure_tls: bool,
) -> Dict[str, Any]:
	api_prefix = repo.api_prefix.strip() or "/api/v1"
	if not api_prefix.startswith("/"):
		api_prefix = "/" + api_prefix

	api = repo.base_url.rstrip("/") + api_prefix + "/user"
	resp = _http_json("GET", api, token=token, auth_scheme=auth_scheme, insecure_tls=insecure_tls)
	if isinstance(resp, dict):
		return resp
	return {}
