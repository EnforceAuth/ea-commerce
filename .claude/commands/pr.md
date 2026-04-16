# Create Pull Request

Create a pull request for the current branch.

## Instructions

When activated, create a pull request for the current branch:

1. **Verify branch state**:
   - Run `git branch --show-current` to get the current branch name
   - Ensure we're not on `main` (abort if so)
   - Run `git log main..HEAD --oneline` to see commits to include

2. **Push the branch** (if not already pushed):
   - Run `git push -u origin <branch-name>`

3. **Determine which environments are affected**:
   - Run `git diff main..HEAD --stat` to see changed files
   - Identify which env folders (`dev/`, `stage/`, `prod/`) are touched
   - This informs the PR title and description

4. **Generate PR title and body**:
   - Title: Conventional commit format (e.g., `feat(dev): add loyalty tier rate limiting`)
   - Use env scope when changes target specific environments: `(dev)`, `(stage)`, `(prod)`, or omit for cross-env changes
   - Body should include:
     - **Summary**: Brief description of what this PR does
     - **Environments affected**: Which env folders have changes
     - **Changes**: Bullet list of key policy changes
     - **Testing**: OPA test commands to verify (e.g., `opa test dev/ -v`)

5. **Create the PR**:
   ```bash
   gh pr create --title "<title>" --body "<body>" --base main --assignee @me
   ```

6. **Report the PR URL** to the user

If the user provides arguments (e.g., `/pr "Custom title"`), use that as the PR title instead of generating one.
