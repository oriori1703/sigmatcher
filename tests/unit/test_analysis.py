import re
from pathlib import Path

from sigmatcher.analysis import (
    create_analyzers,
    filter_signature_matches,
    resolve_macro,
    resolve_signatures,
    sort_analyzers,
)
from sigmatcher.definitions import ClassDefinition, MacroStatement, MethodDefinition, RegexSignature, Signature
from sigmatcher.errors import InvalidMacroModifierError, MissingDependenciesError, SigmatcherError
from sigmatcher.results import Class, MatchedClass, Result


def test_filter_signature_matches_intersects_all_signatures() -> None:
    signatures = [
        # pyrefly: ignore [bad-argument-type]
        RegexSignature(type="regex", signature=re.compile(r"first")),
        # pyrefly: ignore [bad-argument-type]
        RegexSignature(type="regex", signature=re.compile(r"second")),
    ]
    initial = {"a", "b", "c"}

    def callback(signature: Signature, matches: set[str]) -> list[str]:
        assert isinstance(signature, RegexSignature)
        if signature.signature.pattern == "first":
            assert matches == {"a", "b", "c"}
            return ["a", "b"]
        assert matches == {"a", "b"}
        return ["b"]

    result = filter_signature_matches(signatures, initial, callback)
    assert result == {"b"}


def test_resolve_macro_reads_result_new_object() -> None:
    result = MatchedClass(
        original=Class(name="OldClass", package="com.old"),
        new=Class(name="NewClass", package="com.new"),
        matched_methods=[],
        matched_fields=[],
        exports=[],
    )
    statement = MacroStatement(subject="Target", modifier="java")
    assert resolve_macro(result, statement, "Analyzer") == "Lcom/new/NewClass;"


def test_resolve_macro_invalid_modifier_raises() -> None:
    result = MatchedClass(
        original=Class(name="OldClass", package="com.old"),
        new=Class(name="NewClass", package="com.new"),
        matched_methods=[],
        matched_fields=[],
        exports=[],
    )
    statement = MacroStatement(subject="Target", modifier="does_not_exist")

    try:
        _ = resolve_macro(result, statement, "Analyzer")
        raise AssertionError("Expected InvalidMacroModifierError")
    except InvalidMacroModifierError:
        pass


def test_resolve_signatures_substitutes_macros() -> None:
    # pyrefly: ignore [bad-argument-type]
    signatures = (RegexSignature(type="regex", signature=re.compile(r"new-instance v0, ${Target.java}")),)
    results: dict[str, Result | SigmatcherError] = {
        "Target": MatchedClass(
            original=Class(name="OldClass", package="com.old"),
            new=Class(name="NewClass", package="com.new"),
            matched_methods=[],
            matched_fields=[],
            exports=[],
        )
    }

    resolved = resolve_signatures(signatures, results, "Analyzer")
    assert isinstance(resolved[0].signature, re.Pattern)
    assert resolved[0].signature.pattern != signatures[0].signature.pattern
    assert "Lcom/new/NewClass;" in resolved[0].signature.pattern


def test_create_and_sort_analyzers_handles_missing_dependencies(tmp_path: Path) -> None:
    definition = ClassDefinition(
        name="Main",
        # pyrefly: ignore [bad-argument-type]
        signatures=(RegexSignature(type="regex", signature=re.compile(r"invoke ${Missing.java}")),),
        methods=(
            # pyrefly: ignore [bad-argument-type]
            MethodDefinition(name="run", signatures=(RegexSignature(type="regex", signature=re.compile(r"run")),)),
        ),
    )

    analyzers = create_analyzers([definition], tmp_path, app_version="1.0.0")
    assert "Main" in analyzers
    assert "Main.methods.run" in analyzers

    results: dict[str, Result | SigmatcherError] = {}
    order = list(sort_analyzers(analyzers, results))
    assert "Main.methods.run" in order
    assert "Main" in order
    assert isinstance(results["Main"], MissingDependenciesError)
