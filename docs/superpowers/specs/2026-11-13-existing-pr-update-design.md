# Existing PR Update Design

**Intent:** Ensure the Forgejo integration finds an existing pull request for the selected head branch so the tool updates it instead of taking the create-PR path.

**Scope:** Change only the pull-request lookup query and add regression coverage. The existing author filtering, branch matching, push, and PATCH update behavior remain unchanged.

**Approaches considered:**
- Send the documented branch name as `head` (chosen: smallest compatible fix and retains server-side filtering).
- Fetch all PRs for the base branch and filter locally (more tolerant but less efficient and pagination-sensitive).
- Use the dedicated base/head endpoint (less compatible with the current state and author filtering flow).

**Acceptance:** `_forgejo_find_open_pr_data` requests `head=<branch>` and an automated test proves a matching existing PR is returned with that query.
