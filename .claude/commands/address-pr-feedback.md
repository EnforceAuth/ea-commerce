# Address PR Feedback

Fetch and address all review feedback on the current PR.

## Instructions

### 1. Identify the PR

```bash
gh pr view --json number,url,state --jq '{number, url, state}'
```

If no PR exists for the current branch, abort with a message.

### 2. Fetch review comments

```bash
# Get all review comments (inline)
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '.[] | select(.in_reply_to_id == null) | {id, author: .user.login, path, line, body: (.body[:300])}'

# Get IDs already replied to
gh api "repos/{owner}/{repo}/pulls/{pr}/comments" --paginate \
  --jq '[.[] | select(.in_reply_to_id != null) | .in_reply_to_id] | unique'

# Get general PR comments
gh pr view --json comments --jq '.comments[] | {author: .author.login, bodyPreview: (.body[:300])}'

# Get reviews
gh api "repos/{owner}/{repo}/pulls/{pr}/reviews" --paginate \
  --jq '.[] | select(.body | length > 0) | {id, author: .user.login, state, body: (.body[:500])}'
```

Cross-reference to find **unreplied** comments.

### 3. Identify actionable feedback

For each comment, determine:
1. **Valid concern** — fix it
2. **False positive** — reply explaining why
3. **Stale** — code was already changed/removed since the comment was posted
4. **Ambiguous** — ask the user which direction to take

### 4. Present decisions for approval

**STOP and present a table** before making any changes:

| # | Source | File | Line | Comment Summary | Decision | Rationale |
|---|--------|------|------|-----------------|----------|-----------|
| 1 | reviewer | `path/file.rego` | 42 | Brief summary | Fix / Dismiss / Stale | Why |

**Wait for the user to approve** before proceeding.

### 5. Address each item

For valid concerns:
1. Read the file and understand the context
2. Apply the fix
3. Reply using the correct channel by source type:
   ```bash
   # Inline review comment
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="Fixed — <brief explanation>"
   ```
   ```bash
   # General PR comment (issue comment on PR)
   gh pr comment {pr} --body "Addressed: <brief explanation>"
   ```
   ```bash
   # Review-body level feedback
   gh pr review {pr} --comment --body "Addressed review feedback: <brief explanation>"
   ```

For false positives:
1. Reply using the matching channel (inline, general, or review):
   ```bash
   # Inline review comment
   gh api "repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies" \
     -X POST -f body="<explanation of why this is safe>"
   ```
   ```bash
   # General PR comment
   gh pr comment {pr} --body "<explanation of why this is safe>"
   ```

### 6. Run tests

After all fixes are applied, run OPA tests for affected environments:

```bash
opa test dev/ -v    # if dev/ was changed
opa test stage/ -v  # if stage/ was changed
opa test prod/ -v   # if prod/ was changed
```

### 7. Commit and push

If any code changes were made:

```bash
git add -A
git commit -m "fix: address PR review feedback"
git push
```

### 8. Report summary

- **Fixed**: List of issues fixed
- **Dismissed**: False positives with reasoning
- **Stale**: Comments on already-changed code
- **Needs input**: Ambiguous items requiring user decision
- **Tests**: Pass/fail status
