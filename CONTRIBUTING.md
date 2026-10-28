# Contributing

This guide defines the repository workflow for contributors and automated coding agents.

## Work items

1. Check existing issues and pull requests before opening a new issue. Reuse an open issue for the same task; link related issues and pull requests.
2. Create one issue for each distinct task. Write issue titles and descriptions in English and use the repository's existing labels.
3. Start a topic branch from the latest `main` using `type/summary`, with a short lowercase kebab-case summary. Examples: `feat/linux-uhid-backend`, `docs/contribution-workflow`.
4. Keep commits focused on reviewable units. Use `type: lower-case imperative summary`; omit a scope and trailing period. Examples: `feat: add linux uhid backend`, `docs: document contribution workflow`.
5. Push the topic branch and open one pull request against `main` for the issue. Write the PR title and description in English. Use the pull request template, close the issue with `Closes #<number>`, and reference related work.
6. Review the complete diff and report the checks performed. Merge with a **merge commit** after applicable checks pass and blocking feedback is resolved. Do not change repository protection settings as part of a task unless that change is explicitly requested.
7. After merge, return to `main`, update it with `git pull --ff-only`, and confirm the worktree is clean before starting another task.

If a required check is unavailable or fails, leave the pull request open and report the blocker instead of merging it.

## Naming

Use the same task type across the branch and commit when practical. Supported types are:

- `feat`: user-visible capability
- `fix`: defect correction
- `docs`: documentation
- `refactor`: behavior-preserving code restructuring
- `test`: test-only changes
- `build`: build and dependency configuration
- `ci`: continuous integration configuration
- `chore`: maintenance work
- `style`: formatting-only changes
- `perf`: performance improvements
- `revert`: reverting an earlier change

Issue titles use a concise English category prefix, such as `[Feature]`, `[Bug]`, `[Documentation]`, or `[Task]`. Pull request titles use `type: summary`, matching the commit convention.

## Pull request expectations

- Keep each PR focused on its linked issue.
- State what changed and how it was verified; identify checks that were not run and why.
- Include screenshots or recordings for visible UI changes when useful.
- Disclose user-facing limitations, migration needs, and security implications.
- Keep every task commit in history by using GitHub's **Create a merge commit** option.

## Repository status

The repository currently has no configured CI workflow or branch protection on `main`. Do not imply that an automated check ran when it did not. Each PR must state its actual verification results.
