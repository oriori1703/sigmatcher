# CLAUDE.md

`sigmatcher` is a CLI that matches Java classes, methods, fields, and "exports" (arbitrary
strings) across versions of an Android app by running YAML-defined signatures against
decoded smali. It's reverse-engineering infrastructure: signatures are authored once and
re-resolved as the target app changes between versions.

For commands, environment setup, the architecture map, and the coding rules (absolute
imports, strict typing, Pydantic conventions, subprocess argv-only, etc.), read
[`AGENTS.md`](AGENTS.md). The rules in there apply equally to Claude Code sessions. The
README has the user-facing signature-file documentation.

This file only holds Claude-Code-specific guidance not covered there.

## Splitting work — commits, branches, worktrees

Cleanliness over convenience. The goal is a history a reviewer can read top-to-bottom
without rebuilding the story themselves.

- **One logical change per commit.** Don't bundle a refactor with a bug fix with a
  dependency bump. If you find yourself writing "and also" in the commit subject, split it.
- **Refactors before behavior changes.** When prep work and the real change land together,
  stage them as separate commits in that order — the diff for the behavior change should
  be small and obvious.
- **Don't sneak in drive-by changes.** Unrelated formatting, rename, or cleanup belongs in
  its own commit (or its own PR). If touching it is unavoidable, call it out in the message.
- **Branch per concern.** New branch off `main` for each independent piece of work; don't
  pile unrelated work onto a feature branch because it's already checked out.
- **Use `git worktree` when contexts collide.** If you need to keep an in-progress branch
  checked out while doing review/hotfix work elsewhere, prefer
  `git worktree add ../sigmatcher-<topic> <branch>` over stashing. Avoids dirty trees and
  half-finished work getting accidentally amended into the wrong commit.
- **Remove worktrees when done** (`git worktree remove …`) — don't leave stale checkouts
  lying around.
- **Rebase, don't merge, for local cleanup.** Squash fixup commits and reorder before
  opening the PR so the public history is the curated version, not the working version.
  Never rewrite history that's already been pushed and reviewed.
- **Commit messages explain *why*.** The diff already shows *what*. One-sentence subject
  in the imperative; body only when the reasoning isn't obvious from the code.
