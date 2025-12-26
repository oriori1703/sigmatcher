from pathlib import Path

from sigmatcher.cli import _read_definitions  # pyright: ignore[reportPrivateUsage]
from sigmatcher.definitions import RegexSignature
from sigmatcher.unpack import get_apk_version


def test_get_apk_version_parses_string(tmp_path: Path) -> None:
    unpacked = tmp_path / "apktool"
    unpacked.mkdir()
    _ = (unpacked / "apktool.yml").write_text("versionInfo:\n  versionName: 1.2.3\n")

    assert get_apk_version(unpacked) == "1.2.3"


def test_get_apk_version_casts_number_to_string(tmp_path: Path) -> None:
    unpacked = tmp_path / "apktool"
    unpacked.mkdir()
    _ = (unpacked / "apktool.yml").write_text("versionInfo:\n  versionName: 12\n")

    assert get_apk_version(unpacked) == "12"


def test_read_definitions_merges_definition_groups(tmp_path: Path) -> None:
    base = tmp_path / "base.yaml"
    override = tmp_path / "override.yaml"

    _ = base.write_text(
        """
- name: ConnectionManager
  signatures:
    - type: regex
      signature: old-class-signature
  methods:
    - name: read
      signatures:
        - type: regex
          signature: old-method-signature
""".strip()
    )
    _ = override.write_text(
        """
- name: ConnectionManager
  signatures:
    - type: regex
      signature: new-class-signature
  methods:
    - name: write
      signatures:
        - type: regex
          signature: new-method-signature
""".strip()
    )

    merged = _read_definitions([base, override])
    assert len(merged) == 1
    class_def = merged[0]
    signature = class_def.signatures[0]
    assert isinstance(signature, RegexSignature)
    assert signature.signature.pattern == "new-class-signature"
    assert {method.name for method in class_def.methods} == {"read", "write"}
