import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Set, Tuple, Union

if TYPE_CHECKING:
    from sigmatcher.definitions import ClassDefinition, Definitions


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


def find_class_matches(class_def: "ClassDefinition", unpacked_path: Path) -> Set[Path]:
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


def analyze(parsed_definitions: "Definitions", unpacked_path: Path) -> None:
    results = {class_def.name: find_class_matches(class_def, unpacked_path) for class_def in parsed_definitions.defs}
    print(results)
