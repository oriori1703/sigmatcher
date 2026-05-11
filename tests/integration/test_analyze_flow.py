import re
from pathlib import Path

import pytest

import sigmatcher.definitions
from sigmatcher.analysis import analyze
from sigmatcher.cache import Cache
from sigmatcher.definitions import ClassDefinition, ExportDefinition, FieldDefinition, MethodDefinition, RegexSignature
from sigmatcher.errors import NoMatchesError, TooManyMatchesError
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

    assert isinstance(results["ConnectionManager"], MatchedClass)
    assert isinstance(results["ConnectionManager.methods.read"], MatchedMethod)
    assert isinstance(results["ConnectionManager.fields.counter"], MatchedField)
    assert isinstance(results["ConnectionManager.exports.readConst"], MatchedExport)
    assert isinstance(results["NetworkHandler"], MatchedClass)

    connection_manager_result = results["ConnectionManager"]
    assert isinstance(connection_manager_result, MatchedClass)
    assert connection_manager_result.new.to_java_representation() == "Lcom/example/a;"

    network_handler_result = results["NetworkHandler"]
    assert isinstance(network_handler_result, MatchedClass)
    assert network_handler_result.new.to_java_representation() == "Lcom/example/n;"

    cached_results = analyze(definitions=definitions, cache=cache, app_version="1.0.0")

    cached_connection_manager_result = cached_results["ConnectionManager"]
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

    result = results["UnknownToStringClass"]
    assert isinstance(result, MatchedClass)
    assert result.original.name == "ConnectionManager"
    assert result.new.to_java_representation() == "Lcom/example/a;"


@pytest.mark.integration
def test_analyze_dynamic_name_zero_captures_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """File-level signature matches via a non-capturing alternative, but the class_name
    group never captures anything. Should fail with NoMatchesError."""
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        '    const-string v0, "trigger-token"\n',
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
    assert isinstance(result, NoMatchesError)


@pytest.mark.integration
def test_analyze_dynamic_name_multi_capture_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        '    const-string v0, "Alpha{state=on"\n    const-string v1, "Beta{state=off"\n',
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

    result = results["UnknownToStringClass"]
    assert isinstance(result, TooManyMatchesError)
    assert result.matches == {"Alpha", "Beta"}


@pytest.mark.integration
def test_analyze_dynamic_name_cache_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = Cache(tmp_path / "cache")
    apktool_dir = cache.get_apktool_cache_dir()
    apktool_dir.mkdir(parents=True)

    _write_dynamic_name_smali(
        apktool_dir,
        "a",
        '    const-string v0, "ConnectionManager{state=connected"\n',
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
    first_result = first["UnknownToStringClass"]
    assert isinstance(first_result, MatchedClass)
    assert first_result.original.name == "ConnectionManager"

    cached = analyze(definitions=definitions, cache=cache, app_version="1.0.0")
    cached_result = cached["UnknownToStringClass"]
    assert isinstance(cached_result, MatchedClass)
    assert cached_result.original.name == "ConnectionManager"
    assert cached_result.new.to_java_representation() == "Lcom/example/a;"
