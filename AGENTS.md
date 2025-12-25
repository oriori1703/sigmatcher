# AGENTS.md - sigmatcher agent guide

This is a minimal, repo-specific guide for coding agents.

## What this project is

- `sigmatcher` is a CLI that matches Java/Smali classes, methods, fields, and exports across APK versions.
- It uses YAML signature definitions (regex/glob, counts, version ranges, macros).
- Typical flow: decode APK (`apktool`) -> scan smali (`rg`) -> resolve dependencies/macros -> emit mappings.
- Output formats: `raw`, `enigma`, `jadx`, `legacy`.
- For full usage and signature examples, read `README.md`.

## Environment and tools

- Python project (`requires-python >=3.10`).
- Use `uv` for all env/package/command execution (do not use `pip` directly).
- Install dev environment with:

```bash
uv sync --locked --all-extras --dev
```

- External tools used in some flows/tests: `rg` (ripgrep), `apktool`.

## Commands that matter

```bash
# Build
uv build

# Schema
uv run sigmatcher schema --output definitions.schema.json

# Lint / format check
uv run ruff check ./src
uv run ruff format --check --diff ./src

# Types
uv run mypy .
uv run --with ty ty check --output-format github
uv run --with pyrefly pyrefly check
uv run --with basedpyright basedpyright

# Tests
uv run pytest
uv run pytest -m external

# Single test target (template)
uv run pytest tests/unit/test_analysis.py::test_resolve_macro_reads_result_new_object
```

## Test suite notes

- Tests live in `tests/unit/` and `tests/integration/`.
- Default pytest config excludes external tests (`-m 'not external'`).
- Markers:
  - `integration`: slower workflow/e2e-style tests
  - `external`: requires system tools like `rg` / `apktool`

## Architecture map

- `sigmatcher.cli`: Typer CLI (`analyze`, `convert`, `schema`, `cache`).
- `sigmatcher.definitions`: Pydantic models for YAML signatures + merge logic.
- `sigmatcher.analysis`: analyzer execution, dependency sorting, macro resolution.
- `sigmatcher.results`: matched class/method/field/export models.
- `sigmatcher.formats`: mapping conversion/parsing.
- `sigmatcher.errors`: domain exception hierarchy.
- `sigmatcher.cache`: cache keying + serialized analysis cache.
- `sigmatcher.grep`: wrapper around `rg` count/search behavior.
- `sigmatcher.unpack`: APK unpack/version helpers around `apktool`.

## Repo-specific coding rules

- Formatting: Ruff defaults, max line length `120`.
- Imports: absolute imports only (`from sigmatcher...`), no relative imports.
- Typing: strict checks in CI; annotate params/returns; avoid `Any` when possible.
- Typing compat: use `typing_extensions` fallbacks for `override`/`Self` where needed.
- Collections: prefer `collections.abc` interfaces in type hints.
- Data modeling: Pydantic models are commonly `frozen=True` and `extra="forbid"`.
- Definitions: tuples for immutable definition collections; lists for mutable accumulators.
- Naming: analyzer children use dotted names (example: `Class.methods.read`).
- Errors: expected matching/analysis failures should use `SigmatcherError` subclasses.
- Error messaging split: concise `short_message()` + detailed `debug_message()`.
- Subprocess: use explicit argv lists; do not use `shell=True`.
- CLI output: normal output on stdout, diagnostics/errors on stderr.

## Completion checklist

- Run the narrowest relevant test first.
- Before finishing, run at least:

```bash
uv run ruff check ./src
uv run mypy .
uv run pytest
```

- If you touched external-tool integration, also run:

```bash
uv run pytest -m external
```
