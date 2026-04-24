from pathlib import Path

from sigmatcher.cli import _read_definitions  # pyright: ignore[reportPrivateUsage]
from sigmatcher.definitions import RegexSignature


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
