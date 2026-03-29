import re
from pathlib import Path

import pytest

import sigmatcher.definitions
from sigmatcher.analysis import analyze
from sigmatcher.cache import Cache
from sigmatcher.definitions import ClassDefinition, ExportDefinition, FieldDefinition, MethodDefinition, RegexSignature
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
