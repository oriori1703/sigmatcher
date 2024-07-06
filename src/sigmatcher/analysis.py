import dataclasses
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple, TypeVar, Union

import graphlib
import rich

from sigmatcher.definitions import (
    ClassDefinition,
    Definition,
    Definitions,
    ExportDefinition,
    FieldDefinition,
    InvalidMacroModifierError,
    MethodDefinition,
    Signature,
)
from sigmatcher.results import (
    Class,
    Field,
    MatchedClass,
    MatchedExport,
    MatchedField,
    MatchedMethod,
    Method,
    Result,
)


class MatchError(Exception):
    pass


class NoMatchesError(MatchError):
    pass


class TooManyMatchesError(MatchError):
    pass


class DependencyMatchError(MatchError):
    pass


SignatureMatch = TypeVar("SignatureMatch", str, Path)


def filter_signature_matches(
    matches_per_signature: Iterable[Tuple[Signature, List[SignatureMatch]]],
) -> Set[SignatureMatch]:
    whitelist_matches: Set[SignatureMatch] = set()
    blacklist_matches: Set[SignatureMatch] = set()

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
class Analyzer(ABC):
    definition: Definition

    @abstractmethod
    def analyze(self, unpacked_path: Path, results: Dict[str, Union[Result, Exception, None]]) -> Result:
        pass

    def check_match_count(self, matches: Set[SignatureMatch]) -> None:
        if len(matches) == 0:
            raise NoMatchesError(f"Found no match for {self.name}!")
        if len(matches) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.name}: {matches}")

    def get_dependencies(self) -> Set[str]:
        return self.definition.get_dependencies()

    def check_dependencies(self, results: Dict[str, Union[Result, Exception, None]]) -> None:
        failed_dependencies: List[str] = []
        for dependency_name in self.get_dependencies():
            child_result = results[dependency_name]
            assert child_result is not None
            if isinstance(child_result, Exception):
                failed_dependencies.append(dependency_name)

        if failed_dependencies:
            raise DependencyMatchError(
                f"Skipped {self.name} because of the following dependencies failed: {failed_dependencies}"
            )

    @property
    def name(self) -> str:
        return self.definition.name

    def __repr__(self) -> str:
        return self.name


@dataclasses.dataclass(frozen=True)
class ClassAnalyzer(Analyzer):
    definition: ClassDefinition

    def analyze(self, unpacked_path: Path, results: Dict[str, Union[Result, Exception, None]]) -> MatchedClass:
        class_matches = filter_signature_matches(
            (signature, signature.resolve_macros(results).check_directory(unpacked_path))
            for signature in self.definition.signatures
        )
        self.check_match_count(class_matches)
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

    def analyze(self, unpacked_path: Path, results: Dict[str, Union[Result, Exception, None]]) -> MatchedField:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)

        raw_class = parent_class_result.smali_file.read_text()
        signature = self.definition.signatures[0].resolve_macros(results)
        captured_names = set(signature.capture(raw_class))
        self.check_match_count(captured_names)
        raw_field_name = next(iter(captured_names))

        new_field = Field.from_java_representation(raw_field_name)
        # TODO: should we get the types for the original field from the definition?
        original_field = Field(self.definition.name, new_field.type)
        matched_field = MatchedField(original_field, new_field)
        parent_class_result.matched_fields.append(matched_field)
        return matched_field

    def get_dependencies(self) -> Set[str]:
        return self.definition.get_dependencies() | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.fields.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class MethodAnalyzer(Analyzer):
    definition: MethodDefinition
    parent: ClassAnalyzer

    def analyze(self, unpacked_path: Path, results: Dict[str, Union[Result, Exception, None]]) -> MatchedMethod:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)

        raw_methods = parent_class_result.smali_file.read_text().split(".method")[1:]
        methods = [".method" + method for method in raw_methods]

        method_matches = filter_signature_matches(
            (signature, signature.resolve_macros(results).check_strings(methods))
            for signature in self.definition.signatures
        )
        self.check_match_count(method_matches)
        match = next(iter(method_matches))
        method_definition_line, _, _ = match.partition("\n")
        _, _, raw_method_name = method_definition_line.rpartition(" ")

        new_method = Method.from_java_representation(raw_method_name)
        # TODO: should we get the types for the original method from the definition?
        original_method = Method(self.definition.name, new_method.argument_types, new_method.return_type)
        matched_method = MatchedMethod(original_method, new_method)
        parent_class_result.matched_methods.append(matched_method)
        return matched_method

    def get_dependencies(self) -> Set[str]:
        return self.definition.get_dependencies() | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.methods.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class ExportAnalyzer(Analyzer):
    definition: ExportDefinition
    parent: ClassAnalyzer

    def analyze(self, unpacked_path: Path, results: Dict[str, Union[Result, Exception, None]]) -> MatchedExport:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)

        raw_class = parent_class_result.smali_file.read_text()
        signature = self.definition.signatures[0].resolve_macros(results)
        captured_names = set(signature.capture(raw_class))
        self.check_match_count(captured_names)
        export_value = next(iter(captured_names))

        return MatchedExport.from_value(export_value)

    def get_dependencies(self) -> Set[str]:
        return self.definition.get_dependencies() | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.exports.{self.definition.name}"


def create_analyzers(definitions: Definitions) -> Dict[str, Analyzer]:
    name_to_analyzer: Dict[str, Analyzer] = {}
    for class_definition in definitions.defs:
        class_analyzer = ClassAnalyzer(class_definition)
        name_to_analyzer[class_definition.name] = class_analyzer

        for method_definition in class_definition.methods:
            method_analyzer = MethodAnalyzer(method_definition, parent=class_analyzer)
            name_to_analyzer[method_analyzer.name] = method_analyzer

        for field_definition in class_definition.fields:
            field_analyzer = FieldAnalyzer(field_definition, parent=class_analyzer)
            name_to_analyzer[field_analyzer.name] = field_analyzer

        for export_definition in class_definition.exports:
            export_analyzer = ExportAnalyzer(export_definition, parent=class_analyzer)
            name_to_analyzer[export_analyzer.name] = export_analyzer

    return name_to_analyzer


def analyze(definitions: Definitions, unpacked_path: Path) -> None:
    name_to_analyzer = create_analyzers(definitions)

    sorter: graphlib.TopologicalSorter[str] = graphlib.TopologicalSorter()
    for analyzer in name_to_analyzer.values():
        sorter.add(analyzer.name, *analyzer.get_dependencies())

    results: Dict[str, Union[Result, Exception, None]] = {}
    for analyzer_name in sorter.static_order():
        analyzer = name_to_analyzer[analyzer_name]
        try:
            analyzer.check_dependencies(results)
            results[analyzer_name] = analyzer.analyze(unpacked_path, results)
        except (MatchError, InvalidMacroModifierError) as e:
            results[analyzer_name] = e
            rich.print(f"[yellow]{e!s}[/yellow]")

    rich.print(results)
