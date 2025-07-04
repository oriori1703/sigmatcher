import hashlib
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import platformdirs
import pydantic
import pydantic.json_schema
import pydantic_core
import typer
import yaml
from rich.console import Console

import sigmatcher.analysis
from sigmatcher import __version__
from sigmatcher.definitions import DEFINITIONS_TYPE_ADAPTER, ClassDefinition, merge_definitions_groups
from sigmatcher.formats import MappingFormat, convert_to_format, parse_from_format
from sigmatcher.results import MatchedClass

app = typer.Typer()

stdout_console = Console(soft_wrap=True)
stderr_console = Console(soft_wrap=True, stderr=True)

cache_app = typer.Typer(help="Manage Sigmatcher's cache.")
app.add_typer(cache_app, name="cache")

CACHE_DIR_PATH = platformdirs.user_cache_path("sigmatcher", "oriori1703", ensure_exists=True)


@cache_app.command()
def info() -> None:
    """
    Get the path to Sigmatcher's cache directory.
    """
    print(str(CACHE_DIR_PATH))


@cache_app.command()
def clean() -> None:
    """
    Clean the cache directory.
    """
    for path in CACHE_DIR_PATH.iterdir():
        shutil.rmtree(path)
    stdout_console.print("[green]Successfully cleaned the cache directory.[/green]")


def version_callback(value: bool) -> None:
    if value:
        stdout_console.print(f"Sigmatcher version: [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def callback(
    _version: Annotated[
        bool | None, typer.Option("--version", help="Show the version and exit.", callback=version_callback)
    ] = None,
) -> None:
    pass


@app.command()
def schema(
    output: Annotated[
        Path | None, typer.Option(help="Output path for the json schema. If none is given print to stdout")
    ] = None,
) -> None:
    """
    Get the json schema for writing definitions.
    """

    class SigmatcherGenerateJsonSchema(pydantic.json_schema.GenerateJsonSchema):
        def generate(
            self, schema: pydantic_core.CoreSchema, mode: pydantic.json_schema.JsonSchemaMode = "validation"
        ) -> pydantic.json_schema.JsonSchemaValue:
            json_schema = super().generate(schema, mode=mode)
            json_schema["title"] = "Sigmatcher's Definitions"
            json_schema["$schema"] = self.schema_dialect
            return json_schema

    definitions_schema = DEFINITIONS_TYPE_ADAPTER.json_schema(schema_generator=SigmatcherGenerateJsonSchema)
    definitions_schema_json = json.dumps(definitions_schema, indent=2)
    if output is not None:
        output.write_text(definitions_schema_json)
    else:
        stdout_console.print(definitions_schema_json)


def apktool_callback(value: str) -> str:
    if shutil.which(value) is None:
        raise typer.BadParameter("Cannot find the apktool executable")
    return value


@app.command()
def convert(
    input_file: Annotated[
        Path | None, typer.Option(help="Path for the input mapping output", exists=True, file_okay=True, dir_okay=False)
    ] = None,
    input_format: Annotated[
        MappingFormat, typer.Option(help="The mapping format of the input file")
    ] = MappingFormat.ENIGMA,
    output_file: Annotated[Path | None, typer.Option(help="Path for the output mapping file")] = None,
    output_format: Annotated[MappingFormat, typer.Option(help="The output mapping format")] = MappingFormat.RAW,
) -> None:
    """
    Convert a mapping output from one format to another.
    """
    if input_file is not None:
        raw_input = input_file.read_text()
    elif isinstance(sys.stdin, io.TextIOBase):
        raw_input = sys.stdin.read()
    else:
        raise ValueError("Cannot read from stdin, please provide an input file")
    intermidiate_mappings = parse_from_format(raw_input, input_format)

    mapping_output = convert_to_format(intermidiate_mappings, output_format)
    if output_file is None:
        stdout_console.print(mapping_output)
    else:
        output_file.write_text(mapping_output)


@app.command()
def analyze(
    apk: Annotated[
        Path, typer.Argument(help="Path to the apk that will be analyzed", exists=True, file_okay=True, dir_okay=False)
    ],
    signatures: Annotated[
        list[Path],
        typer.Option(
            help="Path to a signature file. If multiple files are given, they are merged together",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ],
    output_file: Annotated[Path | None, typer.Option(help="Output path for the final mapping output")] = None,
    output_format: Annotated[MappingFormat, typer.Option(help="The output mapping format")] = MappingFormat.RAW,
    apktool: Annotated[
        str, typer.Option(help="The command to use when running apktool", callback=apktool_callback)
    ] = "apktool",
) -> None:
    """
    Analyze an APK file using the provided signatures.
    """
    definition_groups: list[tuple[ClassDefinition, ...]] = []
    for signature_file in signatures:
        with signature_file.open("r") as f:
            raw_yaml = yaml.safe_load(f)
        definitions = DEFINITIONS_TYPE_ADAPTER.validate_python(raw_yaml)
        definition_groups.append(tuple(definitions))
    merged_definitions = merge_definitions_groups(definition_groups)

    apk_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    unpacked_path = CACHE_DIR_PATH / apk_hash
    if not unpacked_path.exists():
        subprocess.run(
            [apktool, "decode", apk, "--no-res", "--no-assets", "-f", "--output", unpacked_path.with_suffix(".tmp")]
        )
        shutil.move(unpacked_path.with_suffix(".tmp"), unpacked_path)

    apktool_yaml_file = unpacked_path / "apktool.yml"
    with apktool_yaml_file.open() as f:
        apk_version = yaml.safe_load(f)["versionInfo"]["versionName"]
    assert isinstance(apk_version, str)

    results = sigmatcher.analysis.analyze(merged_definitions, unpacked_path, apk_version)
    successful_results: dict[str, MatchedClass] = {}
    unsuccessful_results: dict[str, Exception] = {}
    for analyzer_name, result in results.items():
        if isinstance(result, Exception):
            unsuccessful_results[analyzer_name] = result
        elif isinstance(result, MatchedClass):
            successful_results[analyzer_name] = result

    mapping_output = convert_to_format(successful_results, output_format)
    if output_file is None:
        stdout_console.print(mapping_output)
    else:
        output_file.write_text(mapping_output)

    for analyzer_name, result in unsuccessful_results.items():
        stderr_console.print(f"[yellow]Error in {analyzer_name} - {result!s}[/yellow]")


def main() -> None:
    app()
