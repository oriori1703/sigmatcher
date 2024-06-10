from pathlib import Path
from typing import Set

from sigmatcher.definitions import ClassDefinition, Definitions


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


def analyze(parsed_definitions: Definitions, unpacked_path: Path) -> None:
    results = {class_def.name: find_class_matches(class_def, unpacked_path) for class_def in parsed_definitions.defs}
    print(results)
