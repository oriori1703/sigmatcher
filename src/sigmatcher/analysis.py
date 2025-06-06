import dataclasses
import graphlib
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TypeVar

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
    signatures: Iterable[Signature],
    initial_matches: set[SignatureMatch],
    check_signature_callback: Callable[[Signature, set[SignatureMatch]], list[SignatureMatch]],
) -> set[SignatureMatch]:
    all_matches: set[SignatureMatch] = initial_matches
    for signature in signatures:
        signature_match = check_signature_callback(signature, all_matches)
        if signature.count == 0:
            all_matches.difference_update(signature_match)
        else:
            all_matches.intersection_update(signature_match)
            if len(all_matches) == 0:
                break

    return all_matches


@dataclasses.dataclass(frozen=True)
class Analyzer(ABC):
    definition: Definition
    app_version: str | None

    @abstractmethod
    def analyze(self, results: dict[str, Result | Exception]) -> Result:
        pass

    def check_match_count(self, matches: set[SignatureMatch] | None) -> None:
        if matches is None or len(matches) == 0:
            raise NoMatchesError(f"Found no match for {self.name}!")
        if len(matches) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.name}: {matches}")

    def get_dependencies(self) -> set[str]:
        return self.definition.get_dependencies(self.app_version)

    def check_dependencies(self, results: dict[str, Result | Exception]) -> None:
        failed_dependencies: list[str] = []
        for dependency_name in self.get_dependencies():
            child_result = results[dependency_name]
            if isinstance(child_result, Exception):
                failed_dependencies.append(dependency_name)

        if failed_dependencies:
            raise DependencyMatchError(
                f"Skipped {self.name} because of the following dependencies failed: {failed_dependencies}"
            )

    def get_signatures_for_version(self) -> tuple[Signature, ...]:
        return self.definition.get_signatures_for_version(self.app_version)

    @property
    def name(self) -> str:
        return self.definition.name

    def __repr__(self) -> str:
        return self.name


@dataclasses.dataclass(frozen=True)
class ClassAnalyzer(Analyzer):
    definition: ClassDefinition
    search_root: Path

    def analyze(self, results: dict[str, Result | Exception]) -> MatchedClass:
        signatures = list(self.get_signatures_for_version())
        if len(signatures) == 0:
            raise NoMatchesError(f"Found no signatures for {self.name}! Make sure your version ranges are correct.")

        # Make sure the first signature is a whitelist signature in order to improve performance
        whitelist_signature_index = 0
        for i, signature in enumerate(signatures):
            if signature.count != 0:
                whitelist_signature_index = i
                break
        signatures.insert(0, signatures.pop(whitelist_signature_index))

        def check_signature_callback(signature: Signature, matches: set[Path]) -> list[Path]:
            # Limit the search avoid too many arguments to ripgrep
            if len(matches) < 100:
                search_paths = matches
            else:
                search_paths = {self.search_root}

            return signature.resolve_macros(results).check_files(search_paths)

        initial_matches = set(self.search_root.rglob("*.smali"))
        class_matches = filter_signature_matches(signatures, initial_matches, check_signature_callback)

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

    def analyze(self, results: dict[str, Result | Exception]) -> MatchedField:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)
        assert isinstance(parent_class_result.smali_file, Path)

        raw_class = parent_class_result.smali_file.read_text()
        signatures = self.get_signatures_for_version()
        if len(signatures) == 0:
            raise NoMatchesError(f"Found no signatures for {self.name}! Make sure your version ranges are correct.")
        if len(signatures) > 1:
            raise NoMatchesError(
                f"Found {len(signatures)} signatures for {self.name}. Field definitions should only have one."
            )
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

    def get_dependencies(self) -> set[str]:
        return super().get_dependencies() | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.fields.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class MethodAnalyzer(Analyzer):
    definition: MethodDefinition
    parent: ClassAnalyzer

    def analyze(self, results: dict[str, Result | Exception]) -> MatchedMethod:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)
        assert isinstance(parent_class_result.smali_file, Path)

        raw_methods = parent_class_result.smali_file.read_text().split(".method")[1:]
        methods = {".method" + method for method in raw_methods}

        signatures = self.get_signatures_for_version()
        if len(signatures) == 0:
            raise NoMatchesError(f"Found no signatures for {self.name}! Make sure your version ranges are correct.")

        def check_signature_callback(signature: Signature, matches: set[str]) -> list[str]:
            return signature.resolve_macros(results).check_strings(matches)

        method_matches = filter_signature_matches(signatures, methods, check_signature_callback)

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

    def get_dependencies(self) -> set[str]:
        return super().get_dependencies() | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.methods.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class ExportAnalyzer(Analyzer):
    definition: ExportDefinition
    parent: ClassAnalyzer

    def analyze(self, results: dict[str, Result | Exception]) -> MatchedExport:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)
        assert isinstance(parent_class_result.smali_file, Path)

        raw_class = parent_class_result.smali_file.read_text()
        signatures = self.get_signatures_for_version()
        signature = signatures[0].resolve_macros(results)
        if len(signatures) == 0:
            raise NoMatchesError(f"Found no signatures for {self.name}! Make sure your version ranges are correct.")
        if len(signatures) > 1:
            raise NoMatchesError(
                f"Found {len(signatures)} signatures for {self.name}. Export definitions should only have one."
            )

        captured_names = signature.capture(raw_class)
        self.check_match_count(captured_names)
        export_value = next(iter(captured_names))

        return MatchedExport.from_value(export_value)

    def get_dependencies(self) -> set[str]:
        return super().get_dependencies() | {self.parent.name}

    @property
    def name(self) -> str:
        return f"{self.parent.name}.exports.{self.definition.name}"


def create_analyzers(
    definitions: Sequence[ClassDefinition], search_root: Path, app_version: str | None
) -> dict[str, Analyzer]:
    canonical_search_root = search_root.resolve()
    name_to_analyzer: dict[str, Analyzer] = {}
    for class_definition in definitions:
        if not class_definition.is_in_version_range(app_version):
            continue

        class_analyzer = ClassAnalyzer(class_definition, app_version, canonical_search_root)
        name_to_analyzer[class_definition.name] = class_analyzer

        for method_definition in class_definition.methods:
            if not method_definition.is_in_version_range(app_version):
                continue
            method_analyzer = MethodAnalyzer(method_definition, app_version, parent=class_analyzer)
            name_to_analyzer[method_analyzer.name] = method_analyzer

        for field_definition in class_definition.fields:
            if not field_definition.is_in_version_range(app_version):
                continue
            field_analyzer = FieldAnalyzer(field_definition, app_version, parent=class_analyzer)
            name_to_analyzer[field_analyzer.name] = field_analyzer

        for export_definition in class_definition.exports:
            if not export_definition.is_in_version_range(app_version):
                continue
            export_analyzer = ExportAnalyzer(export_definition, app_version, parent=class_analyzer)
            name_to_analyzer[export_analyzer.name] = export_analyzer

    return name_to_analyzer


def analyze(
    definitions: Sequence[ClassDefinition], unpacked_path: Path, app_version: str | None
) -> dict[str, Result | Exception]:
    name_to_analyzer = create_analyzers(definitions, unpacked_path, app_version)

    sorter: graphlib.TopologicalSorter[str] = graphlib.TopologicalSorter()
    for analyzer in name_to_analyzer.values():
        sorter.add(analyzer.name, *analyzer.get_dependencies())

    results: dict[str, Result | Exception] = {}
    for analyzer_name in sorter.static_order():
        analyzer = name_to_analyzer[analyzer_name]
        try:
            analyzer.check_dependencies(results)
            results[analyzer_name] = analyzer.analyze(results)
        except (MatchError, InvalidMacroModifierError) as e:
            results[analyzer_name] = e
    return results
