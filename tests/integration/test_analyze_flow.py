import re
from pathlib import Path

import pytest

import sigmatcher.definitions
from sigmatcher.analysis import analyze
from sigmatcher.cache import Cache
from sigmatcher.definitions import ClassDefinition, ExportDefinition, FieldDefinition, MethodDefinition, RegexSignature
from sigmatcher.errors import MacroPointsToDynamicError, MissingDynamicCaptureGroupError
from sigmatcher.results import MatchedClass, MatchedExport, MatchedField, MatchedMethod


def _python_rip_regex(pattern: str, search_paths: set[Path]) -> dict[Path, int]:
    regex = re.compile(pattern)
    result: dict[Path, int] = {}
    for path in search_paths:
        files = path.rglob("*.smali") if path.is_dir() else [path]
        for file_path in files:
            raw = file_path.read_text()
            count = len(regex.findall(raw))
            if count > 0:
                result[file_path] = count
    return result


@pytest.mark.integration
def test_analyze_end_to_end_with_macros_and_children(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    connection_manager_smali = apktool_dir / "ConnectionManager.smali"
    _ = connection_manager_smali.write_text(
        """
.class public Lcom/example/a;
.super Ljava/lang/Object;

.field private b:I

.method public c()V
    const-string v0, "READ_OK"
    return-void
.end method
""".strip()
    )

    network_handler_smali = apktool_dir / "NetworkHandler.smali"
    _ = network_handler_smali.write_text(
        """
.class public Lcom/example/n;
.super Ljava/lang/Object;

.method public handle()V
    new-instance v0, Lcom/example/a;
    return-void
.end method
""".strip()
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions = [
        ClassDefinition(
            name="ConnectionManager",
            package="com.example.original",
            signatures=(RegexSignature(type="regex", signature=re.compile(r'const-string v0, "READ_OK"')),),
            methods=(
                MethodDefinition(
                    name="read",
                    signatures=(RegexSignature(type="regex", signature=re.compile(r'const-string v0, "READ_OK"')),),
                ),
            ),
            fields=(
                FieldDefinition(
                    name="counter",
                    signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<match>b:I)")),),
                ),
            ),
            exports=(
                ExportDefinition(
                    name="readConst",
                    signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<match>READ_OK)")),),
                ),
            ),
        ),
        ClassDefinition(
            name="NetworkHandler",
            signatures=(
                RegexSignature(type="regex", signature=re.compile(r"new-instance v0, ${ConnectionManager.java}")),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")

    connection_manager_results = results["ConnectionManager"]
    assert isinstance(connection_manager_results, list)
    assert len(connection_manager_results) == 1
    connection_manager_result = connection_manager_results[0]
    assert isinstance(connection_manager_result, MatchedClass)
    assert connection_manager_result.new.to_java_representation() == "Lcom/example/a;"

    read_results = results["ConnectionManager.methods.read"]
    assert isinstance(read_results, list)
    assert isinstance(read_results[0], MatchedMethod)

    counter_results = results["ConnectionManager.fields.counter"]
    assert isinstance(counter_results, list)
    assert isinstance(counter_results[0], MatchedField)

    export_results = results["ConnectionManager.exports.readConst"]
    assert isinstance(export_results, list)
    assert isinstance(export_results[0], MatchedExport)

    network_handler_results = results["NetworkHandler"]
    assert isinstance(network_handler_results, list)
    network_handler_result = network_handler_results[0]
    assert isinstance(network_handler_result, MatchedClass)
    assert network_handler_result.new.to_java_representation() == "Lcom/example/n;"

    cached_results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")

    cached_connection_manager_results = cached_results["ConnectionManager"]
    assert isinstance(cached_connection_manager_results, list)
    cached_connection_manager_result = cached_connection_manager_results[0]
    assert isinstance(cached_connection_manager_result, MatchedClass)
    assert [method.original.name for method in cached_connection_manager_result.matched_methods] == ["read"]
    assert [field.original.name for field in cached_connection_manager_result.matched_fields] == ["counter"]
    assert [export.new.name for export in cached_connection_manager_result.exports] == ["readConst"]


def _write_dynamic_name_smali(apktool_dir: Path, obfuscated_name: str, contents: str) -> Path:
    smali = apktool_dir / f"{obfuscated_name}.smali"
    header = f".class public Lcom/example/{obfuscated_name};\n.super Ljava/lang/Object;\n"
    _ = smali.write_text(header + contents)
    return smali


@pytest.mark.integration
def test_analyze_dynamic_name_captures_readable_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "ConnectionManager{state=connected"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions = [
        ClassDefinition(
            name="UnknownToStringClass",
            dynamic_name=True,
            signatures=(
                RegexSignature(
                    type="regex",
                    signature=re.compile(r'"(?P<class_name>\w+)\{state='),
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")

    result_entries = results["UnknownToStringClass"]
    assert isinstance(result_entries, list)
    assert len(result_entries) == 1
    result = result_entries[0]
    assert isinstance(result, MatchedClass)
    assert result.original.name == "ConnectionManager"
    assert result.new.to_java_representation() == "Lcom/example/a;"


@pytest.mark.integration
def test_analyze_dynamic_name_zero_captures_is_empty_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """File-level signature matches via a non-capturing alternative, but the class_name
    group never captures anything. With the dynamic 0+ redesign this is a legitimate
    empty result list — not an error."""
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "trigger-token"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions = [
        ClassDefinition(
            name="UnknownToStringClass",
            dynamic_name=True,
            signatures=(
                RegexSignature(
                    type="regex",
                    signature=re.compile(r'trigger-token|"(?P<class_name>\w+)\{state='),
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")

    result = results["UnknownToStringClass"]
    assert result == []


@pytest.mark.integration
def test_analyze_dynamic_name_multi_capture_yields_multiple_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dynamic class definition that captures multiple distinct readable names from
    the same smali file emits one MatchedClass per captured name (decision #1 of the
    redesign: dynamic defs match 0+ entities)."""
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public describe()Ljava/lang/String;\n"
        '    const-string v0, "Alpha{state=on"\n'
        '    const-string v1, "Beta{state=off"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions = [
        ClassDefinition(
            name="UnknownToStringClass",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r'"(?P<class_name>\w+)\{state=',
                        "count": "1-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")

    matches = results["UnknownToStringClass"]
    assert isinstance(matches, list)
    captured_names = {match.original.name for match in matches if isinstance(match, MatchedClass)}
    assert captured_names == {"Alpha", "Beta"}


@pytest.mark.integration
def test_analyze_dynamic_name_cache_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "ConnectionManager{state=connected"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions = [
        ClassDefinition(
            name="UnknownToStringClass",
            dynamic_name=True,
            signatures=(
                RegexSignature(
                    type="regex",
                    signature=re.compile(r'"(?P<class_name>\w+)\{state='),
                ),
            ),
        ),
    ]

    first = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    first_entries = first["UnknownToStringClass"]
    assert isinstance(first_entries, list)
    first_result = first_entries[0]
    assert isinstance(first_result, MatchedClass)
    assert first_result.original.name == "ConnectionManager"

    cached = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    cached_entries = cached["UnknownToStringClass"]
    assert isinstance(cached_entries, list)
    cached_result = cached_entries[0]
    assert isinstance(cached_result, MatchedClass)
    assert cached_result.original.name == "ConnectionManager"
    assert cached_result.new.to_java_representation() == "Lcom/example/a;"


@pytest.mark.integration
def test_analyze_dynamic_name_strips_whitespace_and_collapses_captures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pin the documented semantics: captures are compared after str.strip(), so the
    same readable name captured with and without leading whitespace collapses to a
    single value instead of raising TooManyMatchesError."""
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public describe()Ljava/lang/String;\n"
        '    const-string v0, " ConnectionManager{state=on"\n'
        '    const-string v1, "ConnectionManager{state=off"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions = [
        ClassDefinition(
            name="UnknownToStringClass",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r'"(?P<class_name>\s?\w+)\{state=',
                        "count": "1-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    result_entries = results["UnknownToStringClass"]
    assert isinstance(result_entries, list)
    assert len(result_entries) == 1
    result = result_entries[0]
    assert isinstance(result, MatchedClass)
    assert result.original.name == "ConnectionManager"


@pytest.mark.integration
def test_analyze_dynamic_name_version_filtered_out_raises_dedicated_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A definition with two signatures — one non-capturing for old versions, one
    capturing for new versions — passes model-level validation but the runtime
    subset for an old version has no class_name group. The analyzer raises the
    dedicated MissingDynamicCaptureGroupError instead of a misleading NoMatchesError."""
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "legacy-token"\n'
        '    const-string v1, "ConnectionManager{state=connected"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions = [
        ClassDefinition(
            name="UnknownToStringClass",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r"legacy-token",
                        "version_range": "<2.0.0",
                    }
                ),
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r'"(?P<class_name>\w+)\{state=',
                        "version_range": ">=2.0.0",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    result = results["UnknownToStringClass"]
    assert isinstance(result, MissingDynamicCaptureGroupError)
    assert result.app_version == "1.0.0"


def test_macro_points_at_dynamic_def_load_error() -> None:
    """A second ClassDefinition references a dynamic-name class via ${X.java}.

    Dynamic definitions emit 0+ matches and cannot be macro-resolved to a single
    concrete value (decision #4). The validator that runs after
    merge_definitions_groups must hard-error at load time, before analysis runs."""
    from sigmatcher.definitions import validate_definitions  # noqa: PLC0415

    definitions = [
        ClassDefinition(
            name="UnknownToStringClass",
            dynamic_name=True,
            signatures=(
                RegexSignature(
                    type="regex",
                    signature=re.compile(r'"(?P<class_name>\w+)\{state='),
                ),
            ),
        ),
        ClassDefinition(
            name="NetworkHandler",
            signatures=(
                RegexSignature(
                    type="regex",
                    signature=re.compile(r"new-instance v\d+, ${UnknownToStringClass.java}"),
                ),
            ),
        ),
    ]

    with pytest.raises(MacroPointsToDynamicError) as exc_info:
        validate_definitions(definitions)
    assert exc_info.value.analyzer_name == "NetworkHandler"
    assert exc_info.value.dynamic_dependency == "UnknownToStringClass"
