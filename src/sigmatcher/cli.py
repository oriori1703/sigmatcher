import fnmatch
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Literal, Optional, Set, Tuple, TypeAlias, Union

if sys.version_info < (3, 9):
    from typing_extensions import Annotated
else:
    from typing import Annotated

import pydantic
import rich
import typer
import yaml

from sigmatcher import __version__

app = typer.Typer()


class BaseRegexSignature(pydantic.BaseModel):
    signature: re.Pattern[str]
    count: int = 1

    def check(self, directory: Path) -> List[Path]:
        return [path for path, match_count in rip_regex(self.signature, directory).items() if match_count == self.count]


class RegexSignature(BaseRegexSignature):
    type: Literal["regex"] = "regex"


class GlobSignature(BaseRegexSignature):
    type: Literal["glob"] = "glob"

    @pydantic.field_validator("signature", mode="before")
    @classmethod
    def parse_glob(cls, v: str) -> str:
        # TODO: removing the atomic group, i.e. the "(?>" makes glob signature in the form of "*WORD*" slower then
        #  their regex counterparts
        return fnmatch.translate(v).replace("\\Z", "$").replace("(?>", "(?:")


class TreeSitterSignature(pydantic.BaseModel):
    signature: str
    count: int = 1
    type: Literal["treesitter"] = "treesitter"

    def check(self, directory: Path) -> List[Path]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")


Signature: TypeAlias = Annotated[
    Union[RegexSignature, GlobSignature, TreeSitterSignature], pydantic.Field(discriminator="type")
]


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
    path, _, count = line.rpartition(":")
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


def find_class_matches(class_def: ClassDefinition, unpacked_path: Path) -> Set[Path]:
    whitelist_matches: Set[Path] = set()
    blacklist_matches: Set[Path] = set()

    for signature in class_def.signatures:
        matching = signature.check(unpacked_path)
        if signature.count == 0:
            blacklist_matches.update(matching)
        else:
            whitelist_matches.update(matching)
    whitelist_matches.difference_update(blacklist_matches)
    return whitelist_matches


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
        parsed_definitions = Definitions(**yaml.safe_load(f))

    apk_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    unpacked_path = Path(apk_hash)
    if not unpacked_path.exists():
        subprocess.run([apktool, "decode", apk, "--output", unpacked_path])
    results = {class_def.name: find_class_matches(class_def, unpacked_path) for class_def in parsed_definitions.defs}
    print(results)


def main() -> None:
    app()
