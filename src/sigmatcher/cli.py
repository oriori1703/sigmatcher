import hashlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

if sys.version_info < (3, 9):
    from typing_extensions import Annotated
else:
    from typing import Annotated

import platformdirs
import rich
import typer
import yaml

import sigmatcher.analysis
from sigmatcher import __version__
from sigmatcher.definitions import Definitions

app = typer.Typer()

cache_app = typer.Typer(help="Manage Sigmatcher's cache")
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
    rich.print("[green]Successfully cleaned the cache directory.[/green]")


def version_callback(value: bool) -> None:
    if value:
        rich.print(f"Sigmatcher version: [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def callback(
    _version: Annotated[
        Optional[bool],
        typer.Option("--version", help="Show the version and exit.", callback=version_callback),
    ] = None,
) -> None:
    pass


def apktool_callback(value: str) -> str:
    if shutil.which(value) is None:
        raise typer.BadParameter("Cannot find the apktool executable")
    return value


@app.command()
def analyze(
    apk: Annotated[
        Path, typer.Argument(help="Path to the apk that will be analyzed", exists=True, file_okay=True, dir_okay=False)
    ],
    signatures: Annotated[
        Path, typer.Option(help="Path to a signature file", exists=True, file_okay=True, dir_okay=False)
    ],
    apktool: Annotated[
        str, typer.Option(help="The command to use when running apktool", callback=apktool_callback)
    ] = "apktool",
) -> None:
    with signatures.open("r") as f:
        parsed_definitions = Definitions(**yaml.safe_load(f))

    apk_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    unpacked_path = CACHE_DIR_PATH / apk_hash
    if not unpacked_path.exists():
        subprocess.run([apktool, "decode", apk, "--output", unpacked_path])
    sigmatcher.analysis.analyze(parsed_definitions, unpacked_path)


def main() -> None:
    app()
