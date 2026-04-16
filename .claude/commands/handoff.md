---
name: handoff
description: Structured handoff between agents
---

# Session Handoff

Generate a structured handoff for the next session. Output must be self-contained — the next agent should be able to resume without reading this session's history.

## Instructions

### 1. Gather current state

Run these in parallel:

```bash
git branch --show-current
git log --oneline -5
git status --short
gh pr view --json number,url,state,title 2>/dev/null || echo "No PR for this branch"
```

### 2. Produce the handoff document

Output the following sections in order:

---

## Handoff — {feature or change description}

**Date:** {today}
**Branch:** `{current branch}`
**PR:** {PR URL and state, or "none"}

---

### Completed this session

Table format. Be specific — what was done, where, and what artifact proves it.

| Item | Status | Artifact |
|------|--------|----------|
| ... | Done | PR #NNN / commit SHA |

---

### Current state

- What branch is active and whether it's clean or has uncommitted work
- Open PRs and their review status
- Which environments have been tested

---

### Next session: what to do

Be concrete. Name the files, the policies, the commands. The next agent should be able to start without asking clarifying questions.

**Immediate (< 30 min):**
- [ ] {specific action}

**Main work:**
- Files: {list the key files to read first}
- Environments affected: {dev, stage, prod}
- Test command: {e.g., `opa test dev/ -v`}

---

### Decisions made this session

Any non-obvious choices that the next agent needs to know about. Keep it brief — one bullet per decision, include the rationale.

- {decision}: {why}

---

### Open questions / blockers

What is unresolved that may block next session. If none, omit this section.

---

### Key files for next session

List the files the next agent should read first, in priority order. Use relative paths.

## Notes

- Do NOT summarize the whole session history — focus on what the next session needs
- If the branch has uncommitted changes, say so explicitly with what they are
- If tests were left failing, say so and why — do not hide failures
