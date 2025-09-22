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
from packaging import version
from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.tree import Tree

import sigmatcher.analysis
from sigmatcher import __version__
from sigmatcher.definitions import DEFINITIONS_TYPE_ADAPTER, ClassDefinition, merge_definitions_groups
from sigmatcher.exceptions import DependencyMatchError, SigmatcherError
from sigmatcher.formats import MappingFormat, convert_to_format, parse_from_format
from sigmatcher.results import MatchedClass, Result

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


def _read_definitions(signatures: list[Path]) -> tuple[ClassDefinition, ...]:
    definition_groups: list[tuple[ClassDefinition, ...]] = []
    for signature_file in signatures:
        with signature_file.open("r") as f:
            raw_yaml = yaml.safe_load(f)
        definitions = DEFINITIONS_TYPE_ADAPTER.validate_python(raw_yaml)
        definition_groups.append(tuple(definitions))
    return merge_definitions_groups(definition_groups)


def _get_apktool_version(apktool: str) -> str:
    proc = subprocess.run([apktool, "--version"], check=True, capture_output=True)
    return proc.stdout.decode()


def _unpack_apk(apktool: str, apk: Path) -> Path:
    apk_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    unpacked_path = CACHE_DIR_PATH / apk_hash
    if not unpacked_path.exists():
        if version.parse(_get_apktool_version(apktool)) >= version.parse("2.12.0"):
            only_manifest_flag = "--only-manifest"
        else:
            only_manifest_flag = "--force-manifest"
        subprocess.run(
            [
                apktool,
                "decode",
                apk,
                only_manifest_flag,
                "--no-assets",
                "-f",
                "--output",
                unpacked_path.with_suffix(".tmp"),
            ],
            check=True,
        )
        shutil.move(unpacked_path.with_suffix(".tmp"), unpacked_path)
    return unpacked_path


def _get_apk_version(unpacked_path: Path) -> str | None:
    apktool_yaml_file = unpacked_path / "apktool.yml"
    with apktool_yaml_file.open() as f:
        apk_version = yaml.safe_load(f)["versionInfo"]["versionName"]

    if isinstance(apk_version, float | int):
        apk_version = str(apk_version)
    assert isinstance(apk_version, str) or apk_version is None
    return apk_version


def _output_successful_results(
    results: dict[str, MatchedClass], output_file: Path | None, output_format: MappingFormat
) -> None:
    mapping_output = convert_to_format(results, output_format)
    if output_file is None:
        stdout_console.print(mapping_output)
    else:
        output_file.write_text(mapping_output)


def _render_error(error: SigmatcherError, debug: bool) -> RenderableType:
    error_message = f"[red]{error.analyzer_name}[/red] - {error.short_message()}"
    if debug and (debug_message := error.debug_message()):
        formated_debug_message = Padding(f"[yellow]{debug_message}[/yellow]", (0, 4))
        return Group(error_message, "[yellow]Debug Info:[/yellow]", formated_debug_message)

    return Group(error_message)


def _output_failed_results_flat(failed_results: dict[str, SigmatcherError], debug: bool) -> None:
    stderr_console.print("Errors:")
    for result in failed_results.values():
        stderr_console.print(_render_error(result, debug))


def _output_failed_results_tree(failed_results: dict[str, SigmatcherError], debug: bool) -> None:
    dependent_errors: dict[str, list[SigmatcherError]] = {}
    top_level_errors: list[SigmatcherError] = []
    for result in failed_results.values():
        if isinstance(result, DependencyMatchError):
            result.should_show_debug = False
            for dependecy in result.missing_dependencies:
                dependent_errors.setdefault(dependecy, []).append(result)
        else:
            top_level_errors.append(result)

    def create_error_tree(error: SigmatcherError, tree: Tree) -> None:
        error_message = _render_error(error, debug)
        branch = tree.add(error_message)
        for dependent_error in dependent_errors.get(error.analyzer_name, []):
            create_error_tree(dependent_error, branch)

    tree = Tree("Errors:")
    for result in top_level_errors:
        create_error_tree(result, tree)

    stderr_console.print(tree)


def _output_results(
    results: dict[str, Result | SigmatcherError],
    output_file: Path | None,
    output_format: MappingFormat,
    output_errors_as_tree: bool,
    debug: bool,
) -> None:
    successful_results: dict[str, MatchedClass] = {}
    failed_results: dict[str, SigmatcherError] = {}

    for analyzer_name, result in results.items():
        if isinstance(result, Exception):
            failed_results[analyzer_name] = result
        elif isinstance(result, MatchedClass):
            successful_results[analyzer_name] = result

    _output_successful_results(successful_results, output_file, output_format)
    if not failed_results:
        return
    if output_errors_as_tree:
        _output_failed_results_tree(failed_results, debug)
    else:
        _output_failed_results_flat(failed_results, debug)


@app.command()
def analyze(  # noqa: PLR0913
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
    tree_errors: Annotated[bool, typer.Option(help="Show dependency errors as a tree")] = False,
    debug: Annotated[
        bool, typer.Option(help="Provide more verbose error messages to help you debug match failures")
    ] = False,
    apktool: Annotated[
        str, typer.Option(help="The command to use when running apktool", callback=apktool_callback)
    ] = "apktool",
) -> None:
    """
    Analyze an APK file using the provided signatures.
    """
    merged_definitions = _read_definitions(signatures)
    unpacked_path = _unpack_apk(apktool, apk)

    apk_version = _get_apk_version(unpacked_path)
    if apk_version is None:
        stderr_console.print("[yellow][Warning][/yellow] No version was found in the APK. Using 0.0.0.0")
        apk_version = "0.0.0.0"

    results = sigmatcher.analysis.analyze(merged_definitions, unpacked_path, apk_version)
    _output_results(results, output_file, output_format, tree_errors, debug)


def main() -> None:
    app()
