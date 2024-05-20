from pathlib import Path
from typing import Annotated, Optional

import rich
import typer

from sigmatcher import __version__

app = typer.Typer()


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


@app.command()
def analyze(
    apk: Annotated[
        Path, typer.Argument(help="Path to the apk that will be analyzed", exists=True, file_okay=True, dir_okay=False)
    ],
    signatures: Annotated[Path, typer.Option(help="Path to a signature file", exists=True, file_okay=True, dir_okay=False)],
    apktool: Annotated[str, typer.Option(help="The command to use when running apktool")] = "apktool",
) -> None:
    print(apk, signatures, apktool)


def main() -> None:
    app()
