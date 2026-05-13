import re

import pydantic
import pytest

from sigmatcher.definitions import (
    DEFINITIONS_TYPE_ADAPTER,
    ClassDefinition,
    CountRange,
    GlobSignature,
    MacroStatement,
    MethodDefinition,
    RegexSignature,
    TopLevelExportDefinition,
    TopLevelFieldDefinition,
    TopLevelMethodDefinition,
    is_in_version_range,
    merge_definitions_groups,
    validate_definitions,
)
from sigmatcher.errors import MacroPointsToDynamicError

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
        signatures=(RegexSignature(type="regex", signature=re.compile(r"old")),),
        methods=(
            MethodDefinition(name="read", signatures=(RegexSignature(type="regex", signature=re.compile(r"m1")),)),
        ),
    )
    override = ClassDefinition(
        name="ConnectionManager",
        package="com.example",
        signatures=(RegexSignature(type="regex", signature=re.compile(r"new")),),
        methods=(
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


def test_capture_class_name_extracts_single_value() -> None:
    signature = RegexSignature.model_validate({"type": "regex", "signature": r'"(?P<class_name>\w+)\{state='})
    assert signature.capture_class_name('const-string v0, "ConnectionManager{state=connected"') == {"ConnectionManager"}


def test_capture_class_name_extracts_multiple_distinct() -> None:
    signature = RegexSignature.model_validate({"type": "regex", "signature": r'"(?P<class_name>\w+)\{state='})
    captures = signature.capture_class_name('const-string v0, "Alpha{state="\nconst-string v1, "Beta{state="\n')
    assert captures == {"Alpha", "Beta"}


def test_capture_class_name_returns_empty_when_pattern_misses() -> None:
    signature = RegexSignature.model_validate({"type": "regex", "signature": r'"(?P<class_name>\w+)\{state='})
    assert signature.capture_class_name("nothing here") == set()


def test_has_class_name_group_reflects_pattern() -> None:
    with_group = RegexSignature.model_validate({"type": "regex", "signature": r"(?P<class_name>\w+)"})
    without_group = RegexSignature.model_validate({"type": "regex", "signature": r"\w+"})
    assert with_group.has_class_name_group()
    assert not without_group.has_class_name_group()


def test_dynamic_name_validator_requires_group() -> None:
    with pytest.raises(pydantic.ValidationError, match="class_name"):
        ClassDefinition(
            name="UnknownClass",
            signatures=(RegexSignature(type="regex", signature=re.compile(r"plain pattern")),),
            dynamic_name=True,
        )


def test_dynamic_name_validator_forbids_group_when_false() -> None:
    with pytest.raises(
        pydantic.ValidationError,
        match=r"contains a \(\?P<class_name>\.\.\.\) named group but dynamic_name is not set",
    ):
        ClassDefinition(
            name="StaticClass",
            signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<class_name>\w+)")),),
            dynamic_name=False,
        )


def test_merge_definitions_groups_revalidates_dynamic_name_consistency() -> None:
    """Merging a non-dynamic base with a dynamic override (whose signature carries the
    `class_name` group) used to silently produce a ClassDefinition with
    dynamic_name=False because pydantic's model_copy does not run validators. The merge
    should re-run the consistency check and reject this inconsistency."""
    base = ClassDefinition(
        name="ConnectionManager",
        signatures=(RegexSignature(type="regex", signature=re.compile(r"plain pattern")),),
        dynamic_name=False,
    )
    override = ClassDefinition(
        name="ConnectionManager",
        signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<class_name>\w+)\{state=")),),
        dynamic_name=True,
    )
    with pytest.raises(
        pydantic.ValidationError,
        match=r"contains a \(\?P<class_name>\.\.\.\) named group but dynamic_name is not set",
    ):
        _ = merge_definitions_groups([[base], [override]])


def test_dynamic_name_validator_accepts_consistent_definitions() -> None:
    dynamic = ClassDefinition(
        name="UnknownClass",
        signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<class_name>\w+)\{state=")),),
        dynamic_name=True,
    )
    assert dynamic.dynamic_name

    static = ClassDefinition(
        name="StaticClass",
        signatures=(RegexSignature(type="regex", signature=re.compile(r"plain pattern")),),
    )
    assert not static.dynamic_name


def test_class_name_group_survives_macro_resolution() -> None:
    signature = RegexSignature.model_validate(
        {
            "type": "regex",
            "signature": r"new-instance .+, ${OtherClass.java}.*?(?P<class_name>\w+)\{state=",
        }
    )
    resolved = signature.resolve_macro(MacroStatement("OtherClass", "java"), "Lcom/example/Other;")
    assert "class_name" in resolved.signature.groupindex
    assert resolved.capture_class_name('new-instance v0, Lcom/example/Other; foo bar "Captured{state=') == {"Captured"}


def test_top_level_method_def_round_trip() -> None:
    raw_yaml = [
        {
            "type": "method",
            "name": "ToString",
            "dynamic_name": True,
            "signatures": [
                {"type": "regex", "signature": r'const-string v\d+, "(?P<method_name>\w+)\{state='},
            ],
        }
    ]
    definitions = DEFINITIONS_TYPE_ADAPTER.validate_python(raw_yaml)
    assert len(definitions) == 1
    method_def = definitions[0]
    assert isinstance(method_def, TopLevelMethodDefinition)
    assert method_def.name == "ToString"
    assert method_def.dynamic_name


def test_top_level_field_def_round_trip() -> None:
    raw_yaml = [
        {
            "type": "field",
            "name": "EventBus",
            "dynamic_name": True,
            "signatures": [
                {
                    "type": "regex",
                    "signature": r"^\.field private final (?P<match>.+:Lcom/(?P<field_name>\w+)/Bus;)",
                },
            ],
        }
    ]
    definitions = DEFINITIONS_TYPE_ADAPTER.validate_python(raw_yaml)
    assert isinstance(definitions[0], TopLevelFieldDefinition)
    assert definitions[0].dynamic_name


def test_top_level_export_def_round_trip() -> None:
    raw_yaml = [
        {
            "type": "export",
            "name": "ApiVersion",
            "dynamic_name": True,
            "signatures": [
                {"type": "regex", "signature": r'"api/v(?P<export_name>\d+)/"'},
            ],
        }
    ]
    definitions = DEFINITIONS_TYPE_ADAPTER.validate_python(raw_yaml)
    assert isinstance(definitions[0], TopLevelExportDefinition)
    assert definitions[0].dynamic_name


def test_backward_compat_no_type_field() -> None:
    """A bare list of class defs without `type:` must keep validating (decision #1)."""
    raw_yaml = [
        {
            "name": "ConnectionManager",
            "signatures": [
                {"type": "regex", "signature": "old-class-signature"},
            ],
            "methods": [
                {
                    "name": "read",
                    "signatures": [{"type": "regex", "signature": "old-method-signature"}],
                },
            ],
        }
    ]
    definitions = DEFINITIONS_TYPE_ADAPTER.validate_python(raw_yaml)
    assert isinstance(definitions[0], ClassDefinition)
    assert definitions[0].name == "ConnectionManager"


def test_validate_macro_points_at_dynamic() -> None:
    """Validator must raise at load time, after merge_definitions_groups."""
    dynamic = ClassDefinition(
        name="Dyn",
        dynamic_name=True,
        signatures=(RegexSignature(type="regex", signature=re.compile(r"(?P<class_name>\w+)\{state=")),),
    )
    consumer = ClassDefinition(
        name="Consumer",
        signatures=(RegexSignature(type="regex", signature=re.compile(r"new-instance v0, ${Dyn.java}")),),
    )
    with pytest.raises(MacroPointsToDynamicError):
        validate_definitions([dynamic, consumer])
