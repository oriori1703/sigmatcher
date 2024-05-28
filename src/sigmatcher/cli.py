import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Annotated, Dict, List, Optional, Set, Tuple, TypeAlias, Union

import pydantic
import rich
import typer
import yaml

from sigmatcher import __version__

app = typer.Typer()

Signature: TypeAlias = Union[re.Pattern[str], Dict[re.Pattern[str], int]]


class FieldDefinition(pydantic.BaseModel):
    name: str
    signatures: List[Signature]


class MethodDefinition(pydantic.BaseModel):
    name: str
    signatures: List[Signature]


class ClassDefinition(pydantic.BaseModel):
    name: str
    package: Optional[str] = None
    signatures: List[Signature]
    fields: Optional[FieldDefinition] = None
    methods: Optional[MethodDefinition] = None


class Definitions(pydantic.BaseModel):
    defs: List[ClassDefinition]


def parse_rg_line(line: str) -> Tuple[Path, int]:
    path, count = line.split(":")
    return Path(path), int(count)


def rip_regex(pattern: Union[str, re.Pattern[str]], unpacked_path: Path) -> Dict[Path, int]:
    if isinstance(pattern, re.Pattern):
        pattern = pattern.pattern
    process = subprocess.run(
        ["rg", "--count-matches", "--multiline", "--no-ignore", "--hidden", "--regexp", pattern, unpacked_path],
        stdout=subprocess.PIPE,
        text=True,
    )

    if bool(process.returncode):
        return {}

    return dict(parse_rg_line(line) for line in process.stdout.splitlines())


def is_matching(signature: Signature, unpacked_path: Path) -> List[Path]:
    if isinstance(signature, dict):
        pattern, count = next(iter(signature.items()))
    else:
        pattern = signature
        count = 1

    return [path for path, match_count in rip_regex(pattern, unpacked_path).items() if match_count == count]


def find_class_matches(class_def: ClassDefinition, unpacked_path: Path) -> Set[Path]:
    matches: Set[Path] = set(is_matching(class_def.signatures[0], unpacked_path))
    for signature in class_def.signatures[1:]:
        matches.difference_update(is_matching(signature, unpacked_path))
    return matches


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
    signatures: Annotated[Path, typer.Option(help="Path to a signature file", exists=True, file_okay=True, dir_okay=False)],
    apktool: Annotated[
        str, typer.Option(help="The command to use when running apktool", callback=apktool_callback)
    ] = "apktool",
) -> None:
    with signatures.open("r") as f:
        parsed_signatures = Definitions(**yaml.safe_load(f))

    apk_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    unpacked_path = Path(apk_hash)
    if not unpacked_path.exists():
        subprocess.run([apktool, "decode", apk, "--output", unpacked_path])
    results = {class_def.name: find_class_matches(class_def, unpacked_path) for class_def in parsed_signatures.defs}
    print(results)


def main() -> None:
    app()
