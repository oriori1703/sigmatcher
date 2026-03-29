from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmatcher.cli import app

runner = CliRunner()


@pytest.mark.integration
def test_schema_writes_file(tmp_path: Path) -> None:
    output_file = tmp_path / "schema.json"
    result = runner.invoke(app, ["schema", "--output", str(output_file)])

    assert result.exit_code == 0
    assert output_file.exists()
    raw_schema = output_file.read_text()
    assert '"title": "Sigmatcher\'s Definitions"' in raw_schema


@pytest.mark.integration
def test_convert_from_enigma_to_raw(tmp_path: Path) -> None:
    input_file = tmp_path / "mapping.enigma"
    _ = input_file.write_text(
        "CLASS com/example/NewName com/example/OldName\n\tFIELD a oldField I\n\tMETHOD b oldMethod ()V"
    )

    output_file = tmp_path / "mapping.json"
    result = runner.invoke(
        app,
        [
            "convert",
            "--input-file",
            str(input_file),
            "--input-format",
            "enigma",
            "--output-file",
            str(output_file),
            "--output-format",
            "raw",
        ],
    )

    assert result.exit_code == 0
    raw_output = output_file.read_text()
    assert '"OldName"' in raw_output
    assert '"oldMethod"' in raw_output
