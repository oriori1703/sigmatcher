import dataclasses
from pathlib import Path
from typing import List, Set

import rich

from sigmatcher.definitions import ClassDefinition, Definitions


@dataclasses.dataclass
class Field:
    name: str


@dataclasses.dataclass
class MatchedField:
    original: Field
    new: Field


@dataclasses.dataclass
class Method:
    name: str


@dataclasses.dataclass
class MatchedMethod:
    original: Field
    new: Field


@dataclasses.dataclass
class Class:
    name: str
    pacakge: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Class":
        name, _, package = java_representation[1:-1].replace("/", ".").rpartition(".")
        return cls(name, package)


@dataclasses.dataclass
class MatchedClass:
    original: Class
    new: Class
    smali_file: Path
    matched_methods: List[MatchedMethod]
    matched_fields: List[MatchedField]


class MatchError(Exception):
    pass


class NoMatchesError(MatchError):
    pass


class TooManyMatchesError(MatchError):
    pass


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


def analyze_class(definition: ClassDefinition, unpacked_path: Path) -> MatchedClass:
    class_matches = find_class_matches(definition, unpacked_path)
    if len(class_matches) == 0:
        raise NoMatchesError(f"Found no match for {definition.name}!")
    if len(class_matches) > 1:
        raise TooManyMatchesError(f"Found too many matches for {definition.name}: {class_matches}")
    match = next(iter(class_matches))
    with match.open() as f:
        class_definition_line = f.readline().rstrip("\n")
    _, _, raw_class_name = class_definition_line.rpartition(" ")
    new_class = Class.from_java_representation(raw_class_name)
    original_class = Class(definition.name, definition.package or new_class.pacakge)
    return MatchedClass(original_class, new_class, match, [], [])


def analyze(definitions: Definitions, unpacked_path: Path) -> None:
    unmatched_definitions = list(definitions.defs)
    result = {}
    previous_len = len(unmatched_definitions)
    while unmatched_definitions:
        for i, definition in enumerate(unmatched_definitions):
            try:
                result[definition] = analyze_class(definition, unpacked_path)
                del unmatched_definitions[i]
            except MatchError as e:
                rich.print(f"[yellow]{e!s}[/yellow]")

        current_len = len(unmatched_definitions)
        if previous_len == current_len:
            rich.print("[yellow]No progress in the current loop![/yellow]")
            break
        previous_len = current_len

    rich.print(result)
