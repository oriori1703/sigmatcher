import dataclasses
import sys
from abc import abstractmethod
from pathlib import Path
from typing import Dict, List, Set, Tuple, Union

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

import rich

from sigmatcher.definitions import ClassDefinition, Definition, Definitions, FieldDefinition, MethodDefinition


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


Result: TypeAlias = Union[MatchedClass, MatchedField, MatchedMethod]


@dataclasses.dataclass(frozen=True)
class Analyzer:
    definition: Definition
    dependencies: Tuple["Analyzer", ...]

    @abstractmethod
    def analyze(self, unpacked_path: Path, results: Dict["Analyzer", Union[Result, Exception, None]]) -> Result:
        pass


@dataclasses.dataclass(frozen=True)
class ClassAnalyzer(Analyzer):
    definition: ClassDefinition

    @staticmethod
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

    def analyze(self, unpacked_path: Path, results: Dict["Analyzer", Union[Result, Exception, None]]) -> MatchedClass:
        class_matches = self.find_class_matches(self.definition, unpacked_path)
        if len(class_matches) == 0:
            raise NoMatchesError(f"Found no match for {self.definition.name}!")
        if len(class_matches) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.definition.name}: {class_matches}")
        match = next(iter(class_matches))
        with match.open() as f:
            class_definition_line = f.readline().rstrip("\n")
        _, _, raw_class_name = class_definition_line.rpartition(" ")
        new_class = Class.from_java_representation(raw_class_name)
        original_class = Class(self.definition.name, self.definition.package or new_class.pacakge)
        return MatchedClass(original_class, new_class, match, [], [])


@dataclasses.dataclass(frozen=True)
class FieldAnalyzer(Analyzer):
    definition: FieldDefinition
    parent: ClassAnalyzer

    def analyze(self, unpacked_path: Path, results: Dict["Analyzer", Union[Result, Exception, None]]) -> MatchedField:
        raise NoMatchesError(f"Found no match for {self.definition.name}!")


@dataclasses.dataclass(frozen=True)
class MethodAnalyzer(Analyzer):
    definition: MethodDefinition
    parent: ClassAnalyzer

    def analyze(self, unpacked_path: Path, results: Dict["Analyzer", Union[Result, Exception, None]]) -> MatchedMethod:
        raise NoMatchesError(f"Found no match for {self.definition.name}!")


def analyze(definitions: Definitions, unpacked_path: Path) -> None:
    analyzers: List[Analyzer] = []
    for class_definition in definitions.defs:
        class_analyzer = ClassAnalyzer(class_definition, dependencies=())
        analyzers.append(class_analyzer)
        for method_definition in class_definition.methods:
            analyzers.append(MethodAnalyzer(method_definition, dependencies=(class_analyzer,), parent=class_analyzer))
        for field_definition in class_definition.fields:
            analyzers.append(FieldAnalyzer(field_definition, dependencies=(class_analyzer,), parent=class_analyzer))

    result: Dict[Analyzer, Union[Result, Exception, None]] = {}
    for analyzer in analyzers:
        try:
            result[analyzer] = analyzer.analyze(unpacked_path, result)
        except MatchError as e:
            result[analyzer] = e
            rich.print(f"[yellow]{e!s}[/yellow]")

    rich.print(result)
