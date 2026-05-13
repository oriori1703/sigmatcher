import re
from pathlib import Path

import pytest

import sigmatcher.definitions
from sigmatcher.analysis import analyze
from sigmatcher.cache import Cache
from sigmatcher.definitions import (
    ClassDefinition,
    ExportDefinition,
    FieldDefinition,
    MethodDefinition,
    RegexSignature,
    TopLevelDefinition,
    TopLevelExportDefinition,
    TopLevelFieldDefinition,
    TopLevelMethodDefinition,
)
from sigmatcher.errors import (
    ChildFailedForParentError,
    MacroPointsToDynamicError,
    MissingDynamicCaptureGroupError,
)
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


@pytest.mark.integration
def test_programmatic_analyze_calls_validate_definitions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Programmatic callers using sigmatcher.analysis.analyze directly must not be able
    to bypass the dynamic-macro validator. Pre-fix, the CLI's _read_definitions wrapper
    was the only validation gate; calling analyze() with a macro-to-dynamic definition
    set would slip past validation and crash with a bare AssertionError downstream."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "ConnectionManager{state=connected"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
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

    with pytest.raises(MacroPointsToDynamicError):
        _ = analyze(definitions=definitions, cache=cache, app_version="1.0.0")


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


def _setup_corpus(tmp_path: Path) -> tuple[Cache, Path]:
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)
    return cache, apktool_dir


EXPECTED_TWO_PARENT_MATCHES = 2


@pytest.mark.integration
def test_top_level_dynamic_class_def_multi_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A single dynamic class def that matches three smali files produces three results."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    for obfuscated, readable in (("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")):
        _write_dynamic_name_smali(
            apktool_dir,
            obfuscated,
            ".method public toString()Ljava/lang/String;\n"
            f'    const-string v0, "{readable}{{state=on"\n'
            "    return-object v0\n"
            ".end method\n",
        )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        ClassDefinition(
            name="ToStringPlaceholder",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<class_name>\w+)\{state=', "count": "1-10"}
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    matches = results["ToStringPlaceholder"]
    assert isinstance(matches, list)
    captured = {m.original.name for m in matches if isinstance(m, MatchedClass)}
    assert captured == {"Alpha", "Beta", "Gamma"}


@pytest.mark.integration
def test_top_level_dynamic_method_def_corpus_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache, apktool_dir = _setup_corpus(tmp_path)
    for obfuscated in ("a", "b"):
        _write_dynamic_name_smali(
            apktool_dir,
            obfuscated,
            ".method public toString()Ljava/lang/String;\n"
            "    .registers 2\n"
            f'    const-string v0, "{obfuscated.upper()}_TOKEN"\n'
            "    return-object v0\n"
            ".end method\n",
        )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelMethodDefinition(
            name="AutoToStringPlaceholder",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'const-string v\d+, "(?P<method_name>\w+_TOKEN)"', "count": "1-10"}
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    matches = results["AutoToStringPlaceholder"]
    assert isinstance(matches, list)
    captured = {m.original.name for m in matches if isinstance(m, MatchedMethod)}
    assert captured == {"A_TOKEN", "B_TOKEN"}


@pytest.mark.integration
def test_top_level_dynamic_field_def_corpus_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".field private final socket:Lcom/example/Socket;\n.field private final buffer:Lcom/example/Buffer;\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelFieldDefinition(
            name="ExampleFieldPlaceholder",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r"\.field private final (?P<match>(?P<field_name>\w+):Lcom/example/\w+;)",
                        "count": "1-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    matches = results["ExampleFieldPlaceholder"]
    assert isinstance(matches, list)
    captured = {m.original.name for m in matches if isinstance(m, MatchedField)}
    assert captured == {"socket", "buffer"}


@pytest.mark.integration
def test_top_level_dynamic_export_def_corpus_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        '    const-string v0, "FEATURE_alpha"\n    const-string v1, "FEATURE_beta"\n',
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelExportDefinition(
            name="FeatureFlag",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<match>FEATURE_(?P<export_name>\w+))"', "count": "1-10"}
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    matches = results["FeatureFlag"]
    assert isinstance(matches, list)
    captured = {m.new.name for m in matches if isinstance(m, MatchedExport)}
    assert captured == {"alpha", "beta"}


@pytest.mark.integration
def test_top_level_dynamic_method_non_participating_capture_group_yields_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pin the BLOCKER-2 fix: a method_name group inside an alternation that the actual
    input matches via the non-capturing alternative must not crash with AttributeError."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "sentinel"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelMethodDefinition(
            name="TolerantMethod",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r'const-string v\d+, "(?:sentinel|(?P<method_name>FOO))"',
                        "count": "0-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    assert results["TolerantMethod"] == []


@pytest.mark.integration
def test_top_level_dynamic_field_non_participating_capture_group_yields_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".field private final sentinel:I\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelFieldDefinition(
            name="TolerantField",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r"\.field private final (?:sentinel|(?P<field_name>foo)):I",
                        "count": "0-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    assert results["TolerantField"] == []


@pytest.mark.integration
def test_top_level_dynamic_export_non_participating_capture_group_yields_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        '    const-string v0, "SENTINEL_TOKEN"\n',
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelExportDefinition(
            name="TolerantExport",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r'"(?P<match>SENTINEL_TOKEN|(?P<export_name>FEATURE_\w+))"',
                        "count": "0-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    assert results["TolerantExport"] == []


@pytest.mark.integration
def test_dynamic_def_zero_matches_is_not_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dynamic def that matches nothing yields an empty list, not an exception (decision #8)."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(apktool_dir, "a", "")

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelMethodDefinition(
            name="WontMatchAnything",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<method_name>nothing-here)"', "count": "0-10"}
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    assert results["WontMatchAnything"] == []


@pytest.mark.integration
def test_dynamic_parent_with_static_children_all_or_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dynamic parent matching N classes: a static child that fails for one of them
    yields one SigmatcherError for the whole child (decision #6). When all parents
    yield the child cleanly, the child produces N results."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    # Two classes match the dynamic parent. The child field signature only matches
    # in one of them — so the all-or-nothing rule should surface a single error.
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "Alpha{state=on"\n'
        "    return-object v0\n"
        ".end method\n"
        ".field private final value:I\n",
    )
    _write_dynamic_name_smali(
        apktool_dir,
        "b",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "Beta{state=on"\n'
        "    return-object v0\n"
        ".end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        ClassDefinition(
            name="DynParent",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<class_name>\w+)\{state=', "count": "1-10"}
                ),
            ),
            fields=(
                FieldDefinition(
                    name="value",
                    signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<match>value:I)")),),
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    parent_matches = results["DynParent"]
    assert isinstance(parent_matches, list)
    assert len(parent_matches) == EXPECTED_TWO_PARENT_MATCHES

    child_result = results["DynParent.fields.value"]
    # The static child cannot match in the Beta parent, so per decision #6 the entire
    # child result is one SigmatcherError, not a mixed list.
    assert isinstance(child_result, ChildFailedForParentError)
    # The error must name the *failing* parent class so authors can disambiguate
    # which capture caused the failure. Beta is the parent without a `value:I` field.
    assert child_result.parent_class_java == "Lcom/example/b;"
    debug = child_result.debug_message()
    short = child_result.short_message()
    assert "Lcom/example/b;" in debug or "Lcom/example/b;" in short
    # All-or-nothing: the successful per-parent capture for Alpha must be DISCARDED
    # — the parent MatchedClass must not retain a MatchedField from this run.
    alpha_parent = next(
        match for match in parent_matches if isinstance(match, MatchedClass) and match.original.name == "Alpha"
    )
    assert alpha_parent.matched_fields == []


@pytest.mark.integration
def test_dynamic_parent_with_static_children_success_yields_n_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Companion to the all-or-nothing test: when the static child succeeds for every
    parent match, the child analyzer produces N results."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    for obfuscated, readable in (("a", "Alpha"), ("b", "Beta")):
        _write_dynamic_name_smali(
            apktool_dir,
            obfuscated,
            ".method public toString()Ljava/lang/String;\n"
            f'    const-string v0, "{readable}{{state=on"\n'
            "    return-object v0\n"
            ".end method\n"
            ".field private final value:I\n",
        )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        ClassDefinition(
            name="DynParent",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<class_name>\w+)\{state=', "count": "1-10"}
                ),
            ),
            fields=(
                FieldDefinition(
                    name="value",
                    signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<match>value:I)")),),
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    child_result = results["DynParent.fields.value"]
    assert isinstance(child_result, list)
    assert len(child_result) == EXPECTED_TWO_PARENT_MATCHES


@pytest.mark.integration
def test_static_parent_dynamic_method_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A top-level dynamic method def works alongside a static class def in the same
    signature file. Covers the 0, 1, and N capture cases for the top-level method
    analyzer (the static class def is just a co-tenant)."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "Alpha"\n'
        "    return-object v0\n"
        ".end method\n",
    )
    _write_dynamic_name_smali(
        apktool_dir,
        "b",
        ".method public toString()Ljava/lang/String;\n"
        '    const-string v0, "Beta"\n'
        "    return-object v0\n"
        ".end method\n"
        ".method public toString2()Ljava/lang/String;\n"
        '    const-string v0, "BetaTwo"\n'
        "    return-object v0\n"
        ".end method\n",
    )
    _write_dynamic_name_smali(
        apktool_dir,
        "c",
        ".method public irrelevant()V\n    return-void\n.end method\n",
    )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        TopLevelMethodDefinition(
            name="ToStringMethods",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r'const-string v\d+, "(?P<method_name>\w+)"',
                        "count": "1-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    matches = results["ToStringMethods"]
    assert isinstance(matches, list)
    captured = {m.original.name for m in matches if isinstance(m, MatchedMethod)}
    # 3 method captures expected: Alpha (a), Beta (b), BetaTwo (b). c.smali has no
    # const-string so it contributes nothing — exercising the 0-capture-per-file path.
    assert captured == {"Alpha", "Beta", "BetaTwo"}


@pytest.mark.integration
def test_dynamic_parent_with_dynamic_children(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both axes dynamic: dynamic parent matching N classes paired with a top-level
    dynamic method analyzer should yield N method results across the matched parents."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    for obfuscated, readable in (("a", "Alpha"), ("b", "Beta")):
        _write_dynamic_name_smali(
            apktool_dir,
            obfuscated,
            ".method public toString()Ljava/lang/String;\n"
            f'    const-string v0, "{readable}{{state=on"\n'
            "    return-object v0\n"
            ".end method\n",
        )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        ClassDefinition(
            name="DynParent",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<class_name>\w+)\{state=', "count": "1-10"}
                ),
            ),
        ),
        TopLevelMethodDefinition(
            name="DynToStringChild",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {
                        "type": "regex",
                        "signature": r'const-string v\d+, "(?P<method_name>\w+)\{state=',
                        "count": "1-10",
                    }
                ),
            ),
        ),
    ]

    results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    parent_matches = results["DynParent"]
    assert isinstance(parent_matches, list)
    method_matches = results["DynToStringChild"]
    assert isinstance(method_matches, list)
    captured_methods = {m.original.name for m in method_matches if isinstance(m, MatchedMethod)}
    assert captured_methods == {"Alpha", "Beta"}


@pytest.mark.integration
def test_cache_round_trip_dynamic_multi_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write the cache, re-run, verify N matches are restored and child re-linking works."""
    cache, apktool_dir = _setup_corpus(tmp_path)
    for obfuscated, readable in (("a", "Alpha"), ("b", "Beta")):
        _write_dynamic_name_smali(
            apktool_dir,
            obfuscated,
            ".method public toString()Ljava/lang/String;\n"
            f'    const-string v0, "{readable}{{state=on"\n'
            "    return-object v0\n"
            ".end method\n"
            ".field private final value:I\n",
        )

    monkeypatch.setattr(sigmatcher.definitions, "rip_regex", _python_rip_regex)

    definitions: list[TopLevelDefinition] = [
        ClassDefinition(
            name="DynParent",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<class_name>\w+)\{state=', "count": "1-10"}
                ),
            ),
            fields=(
                FieldDefinition(
                    name="value",
                    signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<match>value:I)")),),
                ),
            ),
        ),
    ]

    first = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    assert isinstance(first["DynParent"], list)
    assert len(first["DynParent"]) == EXPECTED_TWO_PARENT_MATCHES

    second = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    parent_matches = second["DynParent"]
    assert isinstance(parent_matches, list)
    assert len(parent_matches) == EXPECTED_TWO_PARENT_MATCHES
    captured = {m.original.name for m in parent_matches if isinstance(m, MatchedClass)}
    assert captured == {"Alpha", "Beta"}

    child_results = second["DynParent.fields.value"]
    assert isinstance(child_results, list)
    assert len(child_results) == EXPECTED_TWO_PARENT_MATCHES
    # Each child carries its parent's obfuscated java repr so re-linking is unambiguous.
    parent_javas: set[str] = set()
    for child in child_results:
        assert isinstance(child, MatchedField)
        assert child.smali_class is not None
        parent_javas.add(child.smali_class.to_java_representation())
    assert parent_javas == {"Lcom/example/a;", "Lcom/example/b;"}


@pytest.mark.integration
def test_cache_round_trip_one_smali_two_captured_names(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A single dynamic parent def whose signature matches one smali file but captures
    two distinct readable names (Alpha and Beta) must surface BOTH parents independently
    on cache replay. Pre-fix, the parent-by-smali dict was keyed by java repr only, so
    the second readable name overwrote the first."""
    cache, apktool_dir = _setup_corpus(tmp_path)
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

    definitions: list[TopLevelDefinition] = [
        ClassDefinition(
            name="DynParent",
            dynamic_name=True,
            signatures=(
                RegexSignature.model_validate(
                    {"type": "regex", "signature": r'"(?P<class_name>\w+)\{state=', "count": "1-10"}
                ),
            ),
        ),
    ]

    first = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    first_parents = first["DynParent"]
    assert isinstance(first_parents, list)
    first_captured = {p.original.name for p in first_parents if isinstance(p, MatchedClass)}
    assert first_captured == {"Alpha", "Beta"}

    # Cache replay: both captured-name parents must survive independently — neither
    # one should overwrite the other in the cache-rebuild path.
    second = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    second_parents = second["DynParent"]
    assert isinstance(second_parents, list)
    second_captured = {p.original.name for p in second_parents if isinstance(p, MatchedClass)}
    assert second_captured == {"Alpha", "Beta"}
