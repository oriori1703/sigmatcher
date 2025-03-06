import dataclasses
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, TypeVar, Union

import graphlib

from sigmatcher.definitions import (
    ClassDefinition,
    Definition,
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
    def analyze(
        self, unpacked_path: Path, app_version: Optional[str], results: Dict[str, Union[Result, Exception]]
    ) -> Result:
        pass

    def check_match_count(self, matches: Optional[Set[SignatureMatch]]) -> None:
        if matches is None or len(matches) == 0:
            raise NoMatchesError(f"Found no match for {self.name}!")
        if len(matches) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.name}: {matches}")

    def get_dependencies(self, app_version: Optional[str]) -> Set[str]:
        return self.definition.get_dependencies(app_version)

    def check_dependencies(self, app_version: Optional[str], results: Dict[str, Union[Result, Exception]]) -> None:
        failed_dependencies: List[str] = []
        for dependency_name in self.get_dependencies(app_version):
            child_result = results[dependency_name]
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

    def analyze(
        self, unpacked_path: Path, app_version: Optional[str], results: Dict[str, Union[Result, Exception]]
    ) -> MatchedClass:
        signatures = self.definition.get_signatures_for_version(app_version)
        class_matches = filter_signature_matches(
            (signature, signature.resolve_macros(results).check_directory(unpacked_path)) for signature in signatures
        )
        self.check_match_count(class_matches)
        match = next(iter(class_matches))
        with match.open() as f:
            class_definition_line = f.readline().rstrip("\n")
        _, _, raw_class_name = class_definition_line.rpartition(" ")
        new_class = Class.from_java_representation(raw_class_name)
        original_class = Class(name=self.definition.name, package=self.definition.package or new_class.package)
        return MatchedClass(
            original=original_class, new=new_class, smali_file=match, matched_methods=[], matched_fields=[]
        )


@dataclasses.dataclass(frozen=True)
class FieldAnalyzer(Analyzer):
    definition: FieldDefinition
    parent: ClassAnalyzer

    def analyze(
        self, unpacked_path: Path, app_version: Optional[str], results: Dict[str, Union[Result, Exception]]
    ) -> MatchedField:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)

        raw_class = parent_class_result.smali_file.read_text()
        signatures = self.definition.get_signatures_for_version(app_version)
        signature = signatures[0].resolve_macros(results)
        captured_names = signature.capture(raw_class)
        self.check_match_count(captured_names)
        raw_field_name = next(iter(captured_names))

        new_field = Field.from_java_representation(raw_field_name)
        # TODO: should we get the types for the original field from the definition?
        original_field = Field(name=self.definition.name, type=new_field.type)
        matched_field = MatchedField(original=original_field, new=new_field)
        parent_class_result.matched_fields.append(matched_field)
        return matched_field

    def get_dependencies(self, app_version: Optional[str]) -> Set[str]:
        return self.definition.get_dependencies(app_version) | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.fields.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class MethodAnalyzer(Analyzer):
    definition: MethodDefinition
    parent: ClassAnalyzer

    def analyze(
        self, unpacked_path: Path, app_version: Optional[str], results: Dict[str, Union[Result, Exception]]
    ) -> MatchedMethod:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)

        raw_methods = parent_class_result.smali_file.read_text().split(".method")[1:]
        methods = [".method" + method for method in raw_methods]

        signatures = self.definition.get_signatures_for_version(app_version)
        method_matches = filter_signature_matches(
            (signature, signature.resolve_macros(results).check_strings(methods)) for signature in signatures
        )
        self.check_match_count(method_matches)
        match = next(iter(method_matches))
        method_definition_line, _, _ = match.partition("\n")
        _, _, raw_method_name = method_definition_line.rpartition(" ")

        new_method = Method.from_java_representation(raw_method_name)
        # TODO: should we get the types for the original method from the definition?
        original_method = Method(
            name=self.definition.name, argument_types=new_method.argument_types, return_type=new_method.return_type
        )
        matched_method = MatchedMethod(original=original_method, new=new_method)
        parent_class_result.matched_methods.append(matched_method)
        return matched_method

    def get_dependencies(self, app_version: Optional[str]) -> Set[str]:
        return self.definition.get_dependencies(app_version) | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.methods.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class ExportAnalyzer(Analyzer):
    definition: ExportDefinition
    parent: ClassAnalyzer

    def analyze(
        self, unpacked_path: Path, app_version: Optional[str], results: Dict[str, Union[Result, Exception]]
    ) -> MatchedExport:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)

        raw_class = parent_class_result.smali_file.read_text()
        signatures = self.definition.get_signatures_for_version(app_version)
        signature = signatures[0].resolve_macros(results)
        captured_names = signature.capture(raw_class)
        self.check_match_count(captured_names)
        export_value = next(iter(captured_names))

        return MatchedExport.from_value(export_value)

    def get_dependencies(self, app_version: Optional[str]) -> Set[str]:
        return self.definition.get_dependencies(app_version) | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.exports.{self.definition.name}"


def create_analyzers(definitions: Sequence[ClassDefinition], app_version: Optional[str]) -> Dict[str, Analyzer]:
    name_to_analyzer: Dict[str, Analyzer] = {}
    for class_definition in definitions:
        if not class_definition.is_in_version_range(app_version):
            continue

        class_analyzer = ClassAnalyzer(class_definition)
        name_to_analyzer[class_definition.name] = class_analyzer

        for method_definition in class_definition.methods:
            if not method_definition.is_in_version_range(app_version):
                continue
            method_analyzer = MethodAnalyzer(method_definition, parent=class_analyzer)
            name_to_analyzer[method_analyzer.name] = method_analyzer

        for field_definition in class_definition.fields:
            if not field_definition.is_in_version_range(app_version):
                continue
            field_analyzer = FieldAnalyzer(field_definition, parent=class_analyzer)
            name_to_analyzer[field_analyzer.name] = field_analyzer

        for export_definition in class_definition.exports:
            if not export_definition.is_in_version_range(app_version):
                continue
            export_analyzer = ExportAnalyzer(export_definition, parent=class_analyzer)
            name_to_analyzer[export_analyzer.name] = export_analyzer

    return name_to_analyzer


def analyze(
    definitions: Sequence[ClassDefinition], unpacked_path: Path, app_version: str
) -> Dict[str, Union[Result, Exception]]:
    name_to_analyzer = create_analyzers(definitions, app_version)

    sorter: graphlib.TopologicalSorter[str] = graphlib.TopologicalSorter()
    for analyzer in name_to_analyzer.values():
        sorter.add(analyzer.name, *analyzer.get_dependencies(app_version))

    results: Dict[str, Union[Result, Exception]] = {}
    for analyzer_name in sorter.static_order():
        analyzer = name_to_analyzer[analyzer_name]
        try:
            analyzer.check_dependencies(app_version, results)
            results[analyzer_name] = analyzer.analyze(unpacked_path, app_version, results)
        except (MatchError, InvalidMacroModifierError) as e:
            results[analyzer_name] = e
    return results
