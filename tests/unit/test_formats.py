import pytest

from sigmatcher.errors import DuplicateCapturedNameError
from sigmatcher.formats import MappingFormat, convert_to_format, flatten_analyzer_results, parse_from_format
from sigmatcher.results import (
    Class,
    Export,
    Field,
    MatchedClass,
    MatchedExport,
    MatchedField,
    MatchedMethod,
    Method,
    Result,
)


def test_raw_format_excludes_smali_file(sample_matched_class: MatchedClass) -> None:
    payload = {"Sample": sample_matched_class}
    raw = convert_to_format(payload, MappingFormat.RAW)
    assert "smali_file" not in raw

    parsed = parse_from_format(raw, MappingFormat.RAW)
    assert "Sample" in parsed
    assert parsed["Sample"].new == sample_matched_class.new


def test_enigma_format_round_trip_preserves_core_mappings(sample_matched_class: MatchedClass) -> None:
    payload = {"Sample": sample_matched_class}
    enigma = convert_to_format(payload, MappingFormat.ENIGMA)
    parsed = parse_from_format(enigma, MappingFormat.ENIGMA)

    parsed_class = parsed["OriginalSample"]
    assert parsed_class.new == sample_matched_class.new
    assert parsed_class.original == sample_matched_class.original
    assert parsed_class.matched_fields[0].new.name == "b"
    assert parsed_class.matched_methods[0].new.name == "a"


def test_jadx_parser_creates_holder_class_for_non_renamed_parent() -> None:
    jadx_json = """
    {
      "codeData": {
        "renames": [
          {
            "newName": "renamedField",
            "nodeRef": {
              "refType": "FIELD",
              "declClass": "com.example.Holder",
              "shortId": "a:I"
            }
          }
        ]
      }
    }
    """

    parsed = parse_from_format(jadx_json, MappingFormat.JADX)
    assert "Holder" in parsed
    holder = parsed["Holder"]
    assert holder.new == Class(name="Holder", package="com.example")
    assert holder.original == Class(name="Holder", package="com.example")
    assert holder.matched_fields[0].original.name == "renamedField"


def test_legacy_formatter_includes_exports(sample_matched_class: MatchedClass) -> None:
    payload = {"Sample": sample_matched_class}
    legacy = convert_to_format(payload, MappingFormat.LEGACY)
    assert '"exports"' in legacy
    assert '"exportA": "VALUE_A"' in legacy


def test_legacy_formatter_uses_captured_original_name_as_key(sample_matched_class: MatchedClass) -> None:
    payload = {"PlaceholderId": sample_matched_class}
    legacy = convert_to_format(payload, MappingFormat.LEGACY)
    assert '"OriginalSample"' in legacy
    assert '"PlaceholderId"' not in legacy


def test_legacy_formatter_sorts_by_captured_original_name(
    sample_matched_class: MatchedClass,
) -> None:
    alpha = sample_matched_class.model_copy(update={"original": Class(name="Alpha", package="com.example.old")})
    zeta = sample_matched_class.model_copy(update={"original": Class(name="Zeta", package="com.example.old")})
    legacy = convert_to_format({"Z_placeholder": zeta, "A_placeholder": alpha}, MappingFormat.LEGACY)
    assert legacy.index('"Alpha"') < legacy.index('"Zeta"')


def _make_class(original_name: str, new_name: str) -> MatchedClass:
    return MatchedClass(
        original=Class(name=original_name, package="com.example.old"),
        new=Class(name=new_name, package="com.example"),
        matched_methods=[],
        matched_fields=[],
        exports=[],
    )


def test_raw_format_multi_match() -> None:
    """Multiple captured names from a dynamic class def each surface as top-level keys."""
    alpha = _make_class("Alpha", "a")
    beta = _make_class("Beta", "b")
    analyzer_results: dict[str, list[Result]] = {"DynamicClass": [alpha, beta]}
    flattened = flatten_analyzer_results(analyzer_results)
    raw = convert_to_format(flattened, MappingFormat.RAW)
    assert '"Alpha"' in raw
    assert '"Beta"' in raw


def test_legacy_format_multi_match() -> None:
    alpha = _make_class("Alpha", "a")
    beta = _make_class("Beta", "b")
    flattened = flatten_analyzer_results({"DynamicClass": [alpha, beta]})
    legacy = convert_to_format(flattened, MappingFormat.LEGACY)
    assert '"Alpha"' in legacy
    assert '"Beta"' in legacy


def test_enigma_format_multi_match_round_trip() -> None:
    alpha = _make_class("Alpha", "a")
    beta = _make_class("Beta", "b")
    flattened = flatten_analyzer_results({"DynamicClass": [alpha, beta]})
    enigma = convert_to_format(flattened, MappingFormat.ENIGMA)
    parsed = parse_from_format(enigma, MappingFormat.ENIGMA)
    assert {parsed["Alpha"].new.name, parsed["Beta"].new.name} == {"a", "b"}


def test_jadx_format_multi_match_round_trip() -> None:
    alpha = _make_class("Alpha", "a")
    beta = _make_class("Beta", "b")
    flattened = flatten_analyzer_results({"DynamicClass": [alpha, beta]})
    jadx = convert_to_format(flattened, MappingFormat.JADX)
    parsed = parse_from_format(jadx, MappingFormat.JADX)
    assert {parsed["Alpha"].new.name, parsed["Beta"].new.name} == {"a", "b"}


def test_format_collision_raises() -> None:
    """Two analyzers capturing the same readable name must hard-error (decision #9)."""
    first = _make_class("Shared", "a")
    second = _make_class("Shared", "b")
    with pytest.raises(DuplicateCapturedNameError) as exc_info:
        _ = flatten_analyzer_results({"FirstAnalyzer": [first], "SecondAnalyzer": [second]})
    assert exc_info.value.captured_name == "Shared"


def test_flatten_synthesizes_holder_for_top_level_method() -> None:
    """Top-level dynamic method results land in a synthesized holder class entry
    keyed by the obfuscated parent class (decision #10)."""
    smali_class = Class(name="a", package="com.example")
    method = MatchedMethod(
        original=Method(name="toString", argument_types="", return_type="Ljava/lang/String;"),
        new=Method(name="x", argument_types="", return_type="Ljava/lang/String;"),
        smali_class=smali_class,
    )
    flattened = flatten_analyzer_results({"DynToString": [method]})
    assert "a" in flattened
    holder = flattened["a"]
    assert holder.matched_methods == [method]


def test_flatten_synthesizes_holder_for_top_level_field_and_export() -> None:
    smali_class = Class(name="a", package="com.example")
    field = MatchedField(
        original=Field(name="b", type="I"),
        new=Field(name="b", type="I"),
        smali_class=smali_class,
    )
    export = MatchedExport(new=Export(name="VERSION", value="1.0"), smali_class=smali_class)
    flattened = flatten_analyzer_results({"DynField": [field], "DynExport": [export]})
    holder = flattened["a"]
    assert holder.matched_fields == [field]
    assert holder.exports == [export]


def test_flatten_does_not_synthesize_holder_for_nested_static_children() -> None:
    """Children of a class analyzer (e.g. `ConnectionManager.methods.read`) carry a
    `smali_class` attribute on their pydantic model — same shape as the top-level
    dynamic analyzers' results — but they're already attached to their parent
    `MatchedClass`. They must NOT be routed into a synthesized holder, otherwise
    the children would appear twice in the output: once under their parent's
    captured/static name, once under the obfuscated smali class key.

    Regression test for BLOCKER 1 of the dynamic-redesign CR.
    """
    smali_class = Class(name="a", package="com.example")
    method = MatchedMethod(
        original=Method(name="read", argument_types="", return_type="V"),
        new=Method(name="c", argument_types="", return_type="V"),
        smali_class=smali_class,
    )
    field = MatchedField(
        original=Field(name="counter", type="I"),
        new=Field(name="b", type="I"),
        smali_class=smali_class,
    )
    parent_class = MatchedClass(
        original=Class(name="ConnectionManager", package="com.example.old"),
        new=smali_class,
        matched_methods=[method],
        matched_fields=[field],
        exports=[],
    )
    analyzer_results: dict[str, list[Result]] = {
        "ConnectionManager": [parent_class],
        "ConnectionManager.methods.read": [method],
        "ConnectionManager.fields.counter": [field],
    }

    flattened = flatten_analyzer_results(analyzer_results)
    # Exactly one entry, keyed by the captured/static readable parent name.
    assert set(flattened.keys()) == {"ConnectionManager"}

    raw = convert_to_format(flattened, MappingFormat.RAW)
    # The obfuscated smali class name must not appear as a top-level key in raw output.
    parsed = parse_from_format(raw, MappingFormat.RAW)
    assert "a" not in parsed
