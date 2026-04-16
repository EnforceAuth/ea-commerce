# Code Review Branch Commits

Review all commits on the current branch since diverging from main.

## Prerequisites

**IMPORTANT**: Before starting the review, check if this is a fresh context/session:
- If there is prior conversation history in this session (e.g., you helped write the code being reviewed), STOP immediately
- Inform the user: "Code reviews should be done in a fresh context to avoid bias. Please start a new Claude Code session and run /review there."
- A reviewer should not be the same "person" who wrote the code

## Instructions

When activated, perform a thorough review of OPA/Rego policy changes:

1. **Gather changes**:
   - Run `git log main..HEAD --oneline` to see all commits on this branch
   - Run `git diff main..HEAD` to see all changes
   - For each file changed, read enough context to understand the changes

2. **Run OPA tests**:
   - Determine which environments were modified from the diff
   - Run `opa test <env>/ -v` for each affected environment
   - All tests must pass before proceeding

3. **Review the changes** across these dimensions:

   **Policy correctness**:
   - Are allow/deny rules logically correct?
   - Are there unintended overlaps or gaps in rules?
   - Could any rule combination produce unexpected results?
   - Are default deny semantics preserved?

   **Environment consistency**:
   - If a policy was changed in one env, should it also change in others?
   - Are intentional env differences documented (see README table)?
   - Do data.json files match the expected schema for their env?

   **Test coverage**:
   - Do new/changed rules have corresponding test cases?
   - Are edge cases covered (empty input, missing fields, boundary values)?
   - Are both allow and deny paths tested?

   **Security**:
   - Are authorization boundaries correct (role escalation, cross-tenant access)?
   - Are there overly permissive rules?
   - Is input validation sufficient?

   **Code quality**:
   - Are package names and rule names consistent with conventions?
   - Is there duplicated logic that should be in `shared/`?
   - Are helper rules used appropriately?

4. **Present the review** with severity-rated findings:

   | # | Severity | File | Finding | Recommendation |
   |---|----------|------|---------|----------------|
   | 1 | 🔴 Critical | path/to/file.rego | ... | ... |
   | 2 | 🟡 Warning | path/to/file.rego | ... | ... |
   | 3 | 🔵 Suggestion | path/to/file.rego | ... | ... |

## Follow-up

After presenting the review, present a **fix plan table** for the user to approve before making any changes:

| # | File | Issue | Proposed Action |
|---|------|-------|-----------------|
| 1 | path/to/file.rego | Brief description | Fix / Skip / Ask |

**Wait for the user to approve the plan** before applying fixes. Run `opa test` for affected environments after all fixes are applied.
