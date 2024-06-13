import dataclasses
import sys
from abc import abstractmethod
from pathlib import Path
from types import NoneType
from typing import Dict, Iterable, List, Set, Tuple, TypeVar, Union

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

import rich

from sigmatcher.definitions import (
    ClassDefinition,
    Definition,
    Definitions,
    FieldDefinition,
    MethodDefinition,
    Signature,
)


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
    argument_types: str
    return_type: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Method":
        name, _, types = java_representation.partition("(")
        argument_types, _, return_type = types.partition(")")
        return cls(name, argument_types, return_type)


@dataclasses.dataclass
class MatchedMethod:
    original: Method
    new: Method


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


class DependencyMatchError(MatchError):
    pass


Result: TypeAlias = Union[MatchedClass, MatchedField, MatchedMethod]

T = TypeVar("T", str, Path)


def filter_signature_matches(matches_per_signature: Iterable[Tuple[Signature, List[T]]]) -> Set[T]:
    whitelist_matches: Set[T] = set()
    blacklist_matches: Set[T] = set()

    for signature, matches in matches_per_signature:
        if signature.count == 0:
            blacklist_matches.update(matches)
        elif whitelist_matches:
            whitelist_matches.intersection_update(matches)
        else:
            whitelist_matches.update(matches)
    whitelist_matches.difference_update(blacklist_matches)
    return whitelist_matches


@dataclasses.dataclass(frozen=True)
class Analyzer:
    definition: Definition
    dependencies: Tuple["Analyzer", ...]

    @abstractmethod
    def analyze(self, unpacked_path: Path, results: Dict["Analyzer", Union[Result, Exception, None]]) -> Result:
        pass

    def check_dependencies(self, results: Dict["Analyzer", Union[Result, Exception, None]]) -> bool:
        failed_dependencies: List[str] = []
        for dependency in self.dependencies:
            dependency_result = results[dependency]
            assert dependency_result is not None
            if isinstance(dependency_result, Exception):
                failed_dependencies.append(dependency.name)

        if failed_dependencies:
            raise DependencyMatchError(
                f"Skipped {self.name} because of the following dependencies failed: {failed_dependencies}"
            )

        return all(not isinstance(results[dependency], (Exception, NoneType)) for dependency in self.dependencies)

    @property
    def name(self) -> str:
        return self.definition.name


@dataclasses.dataclass(frozen=True)
class ClassAnalyzer(Analyzer):
    definition: ClassDefinition

    def analyze(self, unpacked_path: Path, results: Dict["Analyzer", Union[Result, Exception, None]]) -> MatchedClass:
        class_matches = filter_signature_matches(
            (signature, signature.check_directory(unpacked_path)) for signature in self.definition.signatures
        )
        if len(class_matches) == 0:
            raise NoMatchesError(f"Found no match for {self.name}!")
        if len(class_matches) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.name}: {class_matches}")
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
        parent_class_result = results[self.parent]
        assert isinstance(parent_class_result, MatchedClass)

        raw_class = parent_class_result.smali_file.read_text()
        signature = self.definition.signatures[0]
        captured_names = set(signature.capture(raw_class))

        if len(captured_names) == 0:
            raise NoMatchesError(f"Found no match for {self.name}!")
        if len(captured_names) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.name}: {captured_names}")
        field_name = next(iter(captured_names))

        new_field = Field(field_name)
        original_field = Field(self.definition.name)
        return MatchedField(original_field, new_field)

    @property
    def name(self) -> str:
        return f"{self.parent.name}.fields.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class MethodAnalyzer(Analyzer):
    definition: MethodDefinition
    parent: ClassAnalyzer

    def analyze(self, unpacked_path: Path, results: Dict["Analyzer", Union[Result, Exception, None]]) -> MatchedMethod:
        parent_class_result = results[self.parent]
        assert isinstance(parent_class_result, MatchedClass)

        raw_methods = parent_class_result.smali_file.read_text().split(".method")[1:]
        methods = [".method" + method for method in raw_methods]

        method_matches = filter_signature_matches(
            (signature, signature.check_strings(methods)) for signature in self.definition.signatures
        )
        if len(method_matches) == 0:
            raise NoMatchesError(f"Found no match for {self.definition.name}!")
        if len(method_matches) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.definition.name}: {method_matches}")
        match = next(iter(method_matches))
        method_definition_line, _, _ = match.partition("\n")
        _, _, raw_method_name = method_definition_line.rpartition(" ")

        new_method = Method.from_java_representation(raw_method_name)
        # TODO: should we get the types for the original method from the definition?
        original_method = Method(self.definition.name, new_method.argument_types, new_method.return_type)
        return MatchedMethod(original_method, new_method)

    @property
    def name(self) -> str:
        return f"{self.parent.name}.methods.{self.definition.name}"


def analyze(definitions: Definitions, unpacked_path: Path) -> None:
    analyzers: List[Analyzer] = []
    for class_definition in definitions.defs:
        class_analyzer = ClassAnalyzer(class_definition, dependencies=())
        analyzers.append(class_analyzer)
        for method_definition in class_definition.methods:
            analyzers.append(MethodAnalyzer(method_definition, dependencies=(class_analyzer,), parent=class_analyzer))
        for field_definition in class_definition.fields:
            analyzers.append(FieldAnalyzer(field_definition, dependencies=(class_analyzer,), parent=class_analyzer))

    results: Dict[Analyzer, Union[Result, Exception, None]] = {}
    for analyzer in analyzers:
        try:
            analyzer.check_dependencies(results)
            results[analyzer] = analyzer.analyze(unpacked_path, results)
        except MatchError as e:
            results[analyzer] = e
            rich.print(f"[yellow]{e!s}[/yellow]")

    rich.print({analyzer.name: result for analyzer, result in results.items()})
