from sigmatcher.formats import MappingFormat, convert_to_format, parse_from_format
from sigmatcher.results import Class, MatchedClass


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
