# Existing PR Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make existing Forgejo PRs discoverable so the CLI updates their body instead of treating them as new PRs.

**Architecture:** Keep the existing `_forgejo_find_open_pr_data` lookup and local validation. Correct only the Forgejo list-PR query's `head` value from `owner:branch` to the documented branch name, and pin the request shape with a regression test.

**Tech Stack:** Python 3.13+, `urllib`, pytest.

**Spec:** `docs/superpowers/specs/2026-11-13-existing-pr-update-design.md`

## Global Constraints

- Use the existing standard-library HTTP client; add no dependencies.
- Preserve existing author, base-branch, state, and head-ref validation.
- Keep the CLI's existing update/create flow unchanged outside the lookup query.

## Review Focus

- Query encoding must represent the head as a plain branch name; test the parsed query value.
- Existing PR matching must still honor the base branch; retain the current fixture assertion.
- Existing PR matching must still honor the author filter; retain the current fixture assertion.
- A non-matching head must remain unmatched; add this assertion to the lookup regression test.
- The update path must receive the discovered PR number; the existing CLI update test covers this integration point.

---

### Task 1: Correct Forgejo existing-PR lookup

**Files:**
- Modify: `src/auto_krr/forgejo.py:117-180`
- Test: `tests/test_forgejo.py:79-101`

**Interfaces:**
- Consumes: existing `ForgejoRepo` and `_http_json` lookup interface.
- Produces: unchanged `_forgejo_find_open_pr_data(...) -> Optional[Dict[str, Any]]` behavior, except that Forgejo receives the branch name in its `head` query parameter.

- [ ] **Step 1: Write the failing regression test**

  Extend the existing lookup test to inspect the requested URL, parse its query with `urllib.parse.parse_qs`, assert `head == ["feature"]`, and return the matching PR only when that value is correct. Keep assertions for the matching PR URL and add a non-matching head fixture if needed.

- [ ] **Step 2: Run the focused test to verify it fails**

  Run: `pytest tests/test_forgejo.py::test_forgejo_find_open_pr_matches_head -q`

  Expected: FAIL because the current implementation sends `o:feature` as the `head` query value.

- [ ] **Step 3: Implement the minimal fix**

  In `src/auto_krr/forgejo.py`, change only the query construction in `_forgejo_find_open_pr_data` so `head` is `head_branch`, not `f"{repo.owner}:{head_branch}"`. Leave the local response validation intact.

- [ ] **Step 4: Run the focused test to verify it passes**

  Run: `pytest tests/test_forgejo.py::test_forgejo_find_open_pr_matches_head -q`

  Expected: PASS.

- [ ] **Step 5: Run the relevant PR tests**

  Run: `pytest -q tests/test_forgejo.py tests/test_cli_main.py tests/test_cli_pr_selection.py`

  Expected: all tests pass. If the environment lacks pytest, report that limitation and use the repository's configured development environment if available.

- [ ] **Step 6: Inspect the diff and commit the bounded fix**

  Run: `git diff --check && git diff -- src/auto_krr/forgejo.py tests/test_forgejo.py`

  Expected: only the query correction and focused regression coverage are present; commit with `fix: find existing Forgejo PRs by branch`.
