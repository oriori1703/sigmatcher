import re

from sigmatcher.definitions import (
    ClassDefinition,
    CountRange,
    GlobSignature,
    MacroStatement,
    MethodDefinition,
    RegexSignature,
    is_in_version_range,
    merge_definitions_groups,
)

EXACT_COUNT = 2


def test_is_in_version_range_supports_none_and_list() -> None:
    assert is_in_version_range(None, ">=1.0")
    assert is_in_version_range("1.2.0", None)
    assert is_in_version_range("1.2.0", ["<1.0", ">=1.1"])
    assert not is_in_version_range("1.0.0", ">1.0.0")


def test_count_parser_and_serializer() -> None:
    exact = RegexSignature.model_validate({"type": "regex", "signature": r"needle", "count": EXACT_COUNT})
    assert exact.count == CountRange(min_count=EXACT_COUNT, max_count=EXACT_COUNT)
    assert exact.model_dump(mode="json")["count"] == EXACT_COUNT

    ranged = RegexSignature.model_validate({"type": "regex", "signature": r"needle", "count": "2-5"})
    assert ranged.count == CountRange(min_count=2, max_count=5)
    assert ranged.model_dump(mode="json")["count"] == "2-5"


def test_macro_detection_and_resolution() -> None:
    signature = RegexSignature.model_validate(
        {"type": "regex", "signature": r"invoke ${TargetClass.java} and ${TargetClass.methods.run.java}"}
    )
    macros = signature.get_macro_definitions()
    assert MacroStatement("TargetClass", "java") in macros
    assert MacroStatement("TargetClass.methods.run", "java") in macros

    resolved = signature.resolve_macro(MacroStatement("TargetClass", "java"), "Lcom/example/TargetClass;")
    assert isinstance(resolved.signature, re.Pattern)
    assert r"\$\{" not in resolved.signature.pattern
    assert "Lcom/example/TargetClass;" in resolved.signature.pattern


def test_glob_signature_translates_to_regex() -> None:
    glob = GlobSignature.model_validate({"type": "glob", "signature": "*doWork*"})
    assert isinstance(glob.signature, re.Pattern)
    assert glob.check_strings(["abc doWork xyz"]) == ["abc doWork xyz"]


def test_merge_definitions_groups_prefers_last_signatures_and_merges_children() -> None:
    base = ClassDefinition(
        name="ConnectionManager",
        package="com.example",
        # pyrefly: ignore [bad-argument-type]
        signatures=(RegexSignature(type="regex", signature=re.compile(r"old")),),
        methods=(
            # pyrefly: ignore [bad-argument-type]
            MethodDefinition(name="read", signatures=(RegexSignature(type="regex", signature=re.compile(r"m1")),)),
        ),
    )
    override = ClassDefinition(
        name="ConnectionManager",
        package="com.example",
        # pyrefly: ignore [bad-argument-type]
        signatures=(RegexSignature(type="regex", signature=re.compile(r"new")),),
        methods=(
            # pyrefly: ignore [bad-argument-type]
            MethodDefinition(name="write", signatures=(RegexSignature(type="regex", signature=re.compile(r"m2")),)),
        ),
    )

    merged = merge_definitions_groups([[base], [override]])
    assert len(merged) == 1
    merged_class = merged[0]
    signature = merged_class.signatures[0]
    assert isinstance(signature, RegexSignature)
    assert signature.signature.pattern == "new"
    assert {method.name for method in merged_class.methods} == {"read", "write"}
