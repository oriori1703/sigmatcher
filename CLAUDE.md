# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A companion `AGENTS.md` at the repo root has a more detailed agent-oriented breakdown (commands, completion checklist, coding rules). Read it for anything not covered here — do not duplicate its content into this file.

## What this is

`sigmatcher` is a CLI that matches Java classes, methods, fields, and "exports" (arbitrary strings) across versions of an Android app by running YAML-defined signatures against decoded smali. It's reverse-engineering infrastructure: signatures are authored once and re-resolved as the target app changes between versions.

## Environment

- Python `>=3.10`. Use `uv` for everything — never invoke `pip` directly.
- Bootstrap: `uv sync --locked --all-extras --dev`.
- External binaries `rg` (ripgrep) and `apktool` are required for the full pipeline and for tests marked `external`.

## Commands

```bash
uv run sigmatcher schema --output definitions.schema.json   # regen JSON schema for signature YAMLs

uv run ruff check ./src                                     # lint
uv run ruff format --check --diff ./src                     # format check
uv run mypy .                                               # type check (strict, pydantic plugin)

uv run pytest                                               # default: skips `external`-marked tests
uv run pytest -m external                                   # run only the external-tool tests
uv run pytest tests/unit/test_analysis.py::<test_name>      # single test
```

Default `pytest` config (`pyproject.toml`) sets `addopts = "-m 'not external'"`. CI runs additional type-checkers (`ty`, `pyrefly`, `basedpyright`) via `uv run --with ...`; see `AGENTS.md` for the exact invocations.

## Architecture

The pipeline is roughly: **unpack APK → grep smali → resolve definitions in dependency order → emit mapping**. Modules under `src/sigmatcher/`:

- `cli.py` — Typer entry point. Subcommands: `analyze`, `convert`, `schema`, `cache`. `analyze` is the main flow; `convert` translates between output formats (`raw`, `enigma`, `jadx`, `legacy`); `schema` exports the Pydantic schema as JSON.
- `definitions.py` — Pydantic models for YAML signature files (classes / methods / fields / exports + their `signatures`). Models are typically `frozen=True, extra="forbid"`. Holds merge logic for combining multiple signature files.
- `analysis.py` — The analyzer. Builds a dependency graph over definitions (so macros like `${ConnectionManager.fields.socket.java}` can reference results from other definitions regardless of YAML order), topologically sorts it, then resolves each definition by running its signatures through `grep.py`. Macro resolution happens after sort.
- `results.py` — Result models for matched classes/methods/fields/exports. These are what macros read properties off of.
- `formats.py` — Read/write the different mapping output formats.
- `cache.py` — Cache key derivation + serialization of analysis results (so re-running on the same unpacked APK is cheap).
- `grep.py` — Thin wrapper around `rg` for count + search semantics used by signatures.
- `unpack.py` — Wraps `apktool` to decode APK / `.apkm` / `.xapk` / split-APK directories; extracts the app version for `version_range` filtering.
- `input_paths.py` — Normalizes the various supported input shapes.
- `errors.py` — `SigmatcherError` hierarchy. Errors carry both a `short_message()` (user-facing) and `debug_message()` (verbose). Raise these — not bare `RuntimeError` — for expected matching/analysis failures.

The signature file model is documented at length in `README.md` (macros, `version_range`, `count` ranges, `regex` vs `glob`). The Pydantic models in `definitions.py` are the source of truth; `definitions.schema.json` at the repo root is the generated artifact and must be regenerated via `uv run sigmatcher schema --output definitions.schema.json` when those models change.

## Repo-specific conventions

- **Absolute imports only** (`from sigmatcher.x import y`). Relative imports are banned by ruff's `flake8-tidy-imports` config.
- Line length 120, Ruff defaults otherwise.
- Strict typing: annotate params/returns, avoid `Any`. For 3.10/3.11 compatibility, use `typing_extensions` for `override` / `Self`.
- Prefer `collections.abc` interfaces in type hints over concrete types.
- Subprocess: explicit argv lists, never `shell=True`.
- CLI: normal output to stdout, diagnostics/errors to stderr.
- Pydantic models in this repo lean on `frozen=True` + `extra="forbid"`; use tuples for immutable definition collections, lists for mutable accumulators.
- Analyzer child names use dotted form (e.g. `Class.methods.read`) — keep that convention when adding new analyzers.

## Splitting work — commits, branches, worktrees

Cleanliness over convenience. The goal is a history a reviewer can read top-to-bottom without rebuilding the story themselves.

- **One logical change per commit.** Don't bundle a refactor with a bug fix with a dependency bump. If you find yourself writing "and also" in the commit subject, split it.
- **Refactors before behavior changes.** When prep work and the real change land together, stage them as separate commits in that order — the diff for the behavior change should be small and obvious.
- **Don't sneak in drive-by changes.** Unrelated formatting, rename, or cleanup belongs in its own commit (or its own PR). If touching it is unavoidable, call it out in the message.
- **Branch per concern.** New branch off `main` for each independent piece of work; don't pile unrelated work onto a feature branch because it's already checked out.
- **Use `git worktree` when contexts collide.** If you need to keep an in-progress branch checked out while doing review/hotfix work elsewhere, prefer `git worktree add ../sigmatcher-<topic> <branch>` over stashing. Avoids dirty trees and half-finished work getting accidentally amended into the wrong commit.
- **Remove worktrees when done** (`git worktree remove …`) — don't leave stale checkouts lying around.
- **Rebase, don't merge, for local cleanup.** Squash fixup commits and reorder before opening the PR so the public history is the curated version, not the working version. Never rewrite history that's already been pushed and reviewed.
- **Commit messages explain *why*.** The diff already shows *what*. One-sentence subject in the imperative; body only when the reasoning isn't obvious from the code.
