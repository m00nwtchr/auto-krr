from auto_krr.git_utils import _detect_forgejo_from_remote


def test_detect_forgejo_from_remote_variants() -> None:
	# Intended behavior: parse multiple remote URL styles.
	base, owner, repo = _detect_forgejo_from_remote("git@example.com:owner/repo.git")
	assert base == "https://example.com"
	assert owner == "owner"
	assert repo == "repo"

	base, owner, repo = _detect_forgejo_from_remote("ssh://git@example.com/owner/repo.git")
	assert base == "https://example.com"
	assert owner == "owner"
	assert repo == "repo"

	base, owner, repo = _detect_forgejo_from_remote("https://example.com/owner/repo.git")
	assert base == "https://example.com"
	assert owner == "owner"
	assert repo == "repo"

	base, owner, repo = _detect_forgejo_from_remote("not-a-url")
	assert base is None
	assert owner is None
	assert repo is None
