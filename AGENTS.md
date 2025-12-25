# AGENTS.md

This file provides guidance for AI coding agents working in the sigmatcher codebase.

## Project Overview

Sigmatcher is a CLI tool for matching Java classes and methods between versions of Android APK files. It uses regex/glob signatures on disassembled smali code to identify and correlate code elements across app versions.

## Build and Development Commands

### Package Manager

This project uses `uv` (Astral's UV package manager). Do not use pip directly.

```bash
uv sync --all-extras --dev        # Install dependencies (including dev dependencies)
uv run sigmatcher --help          # Run the CLI
```

### Linting and Formatting

```bash
uv run --all-extras ruff check src/            # Run ruff linter
uv run --all-extras ruff format --check src/   # Run ruff formatter (check mode)
uv run --all-extras ruff check --fix src/      # Auto-fix linting issues
uv run --all-extras ruff format src/           # Auto-format code
```

### Type Checking

```bash
# mypy (primary type checker)
uv run --all-extras mypy .
```

CI also runs basedpyright, ty, and pyrefly. All must pass.

### Testing

No test suite currently exists. When adding tests:

```bash
uv run --all-extras pytest                                          # Run all tests
uv run --all-extras pytest tests/test_module.py                     # Run a single test file
uv run --all-extras pytest tests/test_module.py::test_function_name # Run a single test function
uv run --all-extras pytest -v                                       # Run with verbose output
```

## Code Style Guidelines

### Line Length

Maximum line length is **120 characters** (configured in `pyproject.toml`).

### Import Conventions

1. **Absolute imports only** - Relative imports are banned (`ban-relative-imports = "all"`)
2. **Import order** (enforced by ruff's isort):
   - Standard library
   - Third-party packages
   - Local imports (`from sigmatcher.xxx import yyy`)
3. **Version-conditional imports** for typing backports:

```python
import sys

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self
```

### Type Annotations

- **Strict typing is required** - mypy runs with `strict = true`
- Annotate all function parameters and return types
- Use `TypeAlias` for complex type definitions
- Use `Annotated` for adding metadata (especially with pydantic/typer)
- Prefer `X | None` over `Optional[X]`
- Prefer `list[X]` over `List[X]` (use modern generic syntax)

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `ClassAnalyzer`, `MatchedField`)
- **Functions/methods**: `snake_case` (e.g., `check_match_count`, `get_dependencies`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_CACHE_DIR_PATH`)
- **Private methods**: Prefix with underscore (e.g., `_get_dependencies`)
- **Type variables**: `PascalCase` with descriptive names (e.g., `TDefinition`, `SignatureMatch`)

### Pydantic Models

```python
class MyModel(pydantic.BaseModel, frozen=True, use_attribute_docstrings=True, extra="forbid"):
    field_name: str
    """Docstring for the field (used for JSON schema generation)."""
```

- `frozen=True` - Makes instances immutable
- `use_attribute_docstrings=True` - Docstrings become field descriptions
- `extra="forbid"` - Reject unknown fields during validation

### Dataclasses

Use `frozen=True` for immutable data structures:

```python
@dataclasses.dataclass(frozen=True)
class Analyzer(ABC):
    definition: Definition
    app_version: str | None
```

### Abstract Base Classes

Use ABC pattern with `@abstractmethod` and `@override`.

## Error Handling

All custom exceptions inherit from `SigmatcherError`:

- Override `short_message()` for user-facing error text
- Override `debug_message()` for verbose debugging output

## Architecture Overview

### Core Modules

| Module | Purpose |
|--------|---------|
| `cli.py` | Typer-based CLI commands (`analyze`, `convert`, `schema`, `cache`) |
| `definitions.py` | Pydantic models for signature YAML files (`ClassDefinition`, `Signature`, etc.) |
| `analysis.py` | Core analysis engine (`Analyzer` classes, dependency resolution) |
| `results.py` | Output models (`MatchedClass`, `MatchedMethod`, `MatchedField`) |
| `errors.py` | Exception hierarchy |
| `formats.py` | Input/output format converters (raw, enigma, jadx, legacy) |
| `cache.py` | APK analysis result caching |
| `grep.py` | ripgrep subprocess wrapper |

### Key Patterns

- **Analyzer pattern**: Each definition type has a corresponding analyzer (`ClassAnalyzer`, `MethodAnalyzer`, etc.)
- **Dependency graph**: Analyzers declare dependencies; `graphlib.TopologicalSorter` orders execution
- **Macro resolution**: Signatures can reference results from other analyzers via `${Name.property}` syntax

## External Dependencies

The following tools must be available on `$PATH`:

- `rg` (ripgrep) - Fast regex search across smali files
- `apktool` - APK disassembly (decoding to smali)
