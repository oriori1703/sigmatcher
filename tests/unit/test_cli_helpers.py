from pathlib import Path

import pytest

from sigmatcher.cli import _read_definitions  # pyright: ignore[reportPrivateUsage]
from sigmatcher.definitions import ClassDefinition, RegexSignature
from sigmatcher.errors import DuplicateTopLevelDefinitionError


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
    assert isinstance(class_def, ClassDefinition)
    signature = class_def.signatures[0]
    assert isinstance(signature, RegexSignature)
    assert signature.signature.pattern == "new-class-signature"
    assert {method.name for method in class_def.methods} == {"read", "write"}


def test_read_definitions_rejects_duplicate_top_level_method(tmp_path: Path) -> None:
    """Top-level method/field/export defs are not merged across files (unlike class
    definitions). Two YAML files declaring the same top-level method name would
    have silently overwritten one another in `create_analyzers` — surface this as a
    hard error at load time."""
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"

    _ = first.write_text(
        """
- type: method
  name: ToString
  dynamic_name: true
  signatures:
    - type: regex
      signature: 'const-string v\\d+, "(?P<method_name>\\w+)\\{state='
""".strip()
    )
    _ = second.write_text(
        """
- type: method
  name: ToString
  dynamic_name: true
  signatures:
    - type: regex
      signature: 'const-string v\\d+, "(?P<method_name>\\w+)_TOKEN"'
""".strip()
    )

    with pytest.raises(DuplicateTopLevelDefinitionError) as exc_info:
        _ = _read_definitions([first, second])
    assert exc_info.value.analyzer_name == "ToString"
    assert exc_info.value.definition_kind == "method"
