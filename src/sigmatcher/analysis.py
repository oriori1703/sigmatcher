import dataclasses
import graphlib
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Sequence
from functools import cache
from pathlib import Path

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

from sigmatcher.definitions import (
    ClassDefinition,
    Definition,
    ExportDefinition,
    FieldDefinition,
    MacroStatement,
    MethodDefinition,
    Signature,
    SignatureMatch,
)
from sigmatcher.exceptions import (
    DependencyMatchError,
    InvalidMacroModifierError,
    NoMatchesError,
    NoSignaturesError,
    SigmatcherError,
    TooManyMatchesError,
    TooManySignaturesError,
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


def filter_signature_matches(
    signatures: Iterable[Signature],
    initial_matches: Iterable[SignatureMatch],
    check_signature_callback: Callable[[Signature, set[SignatureMatch]], list[SignatureMatch]],
) -> set[SignatureMatch]:
    all_matches: set[SignatureMatch] = set(initial_matches)
    for signature in signatures:
        signature_match = check_signature_callback(signature, all_matches)
        all_matches.intersection_update(signature_match)
        if len(all_matches) == 0:
            break

    return all_matches


@cache
def get_smali_files(search_root: Path) -> frozenset[Path]:
    return frozenset(search_root.rglob("*.smali"))


@dataclasses.dataclass(frozen=True)
class Analyzer(ABC):
    definition: Definition
    app_version: str | None

    @abstractmethod
    def analyze(self, results: dict[str, Result | SigmatcherError]) -> Result:
        pass

    def check_match_count(
        self, matches: set[SignatureMatch] | None, signatures: tuple[Signature, ...] | None = None
    ) -> None:
        if matches is None or len(matches) == 0:
            raise NoMatchesError(self.name, signatures)
        if len(matches) > 1:
            raise TooManyMatchesError[SignatureMatch](self.name, matches, signatures)

    def get_dependencies(self) -> set[str]:
        return self.definition.get_dependencies(self.app_version)

    def check_dependencies(self, results: dict[str, Result | SigmatcherError]) -> None:
        failed_dependencies: list[str] = []
        for dependency_name in self.get_dependencies():
            child_result = results[dependency_name]
            if isinstance(child_result, Exception):
                failed_dependencies.append(dependency_name)

        if failed_dependencies:
            raise DependencyMatchError(self.name, failed_dependencies)

    def resolve_macro(self, results: dict[str, Result | SigmatcherError], macro_statement: MacroStatement) -> str:
        result = results[macro_statement.subject]
        assert not isinstance(result, Exception)

        try:
            resolved_macro = getattr(result.new, macro_statement.modifier)  # pyright: ignore[reportAny]
        except AttributeError:
            raise InvalidMacroModifierError(self.name, macro_statement, result.new.__class__.__name__) from None

        assert isinstance(resolved_macro, str)
        return resolved_macro

    def get_resolved_signatures(self, results: dict[str, Result | SigmatcherError]) -> tuple[Signature, ...]:
        resolved_signatures: list[Signature] = []
        for signature in self.get_signatures_for_version():
            resolved_signature = signature
            for macro_statement in signature.get_macro_definitions():
                resolved_macro = self.resolve_macro(results, macro_statement)
                resolved_signature = resolved_signature.resolve_macro(macro_statement, resolved_macro)
            resolved_signatures.append(resolved_signature)

        return tuple(resolved_signatures)

    def get_signatures_for_version(self) -> tuple[Signature, ...]:
        return self.definition.get_signatures_for_version(self.app_version)

    @property
    def name(self) -> str:
        return self.definition.name

    @override
    def __repr__(self) -> str:
        return self.name


@dataclasses.dataclass(frozen=True)
class ClassAnalyzer(Analyzer):
    definition: ClassDefinition
    search_root: Path

    @override
    def analyze(self, results: dict[str, Result | SigmatcherError]) -> MatchedClass:
        signatures = list(self.get_resolved_signatures(results))
        if len(signatures) == 0:
            raise NoSignaturesError(self.name)

        # Make sure the first signature is a whitelist signature in order to improve performance
        whitelist_signature_index = 0
        for i, signature in enumerate(signatures):
            if signature.count.min_count > 0:
                whitelist_signature_index = i
                break
        signatures.insert(0, signatures.pop(whitelist_signature_index))

        def check_signature_callback(signature: Signature, matches: set[Path]) -> list[Path]:
            return signature.check_files(matches, self.search_root)

        initial_matches = get_smali_files(self.search_root)
        class_matches = filter_signature_matches(signatures, initial_matches, check_signature_callback)

        self.check_match_count(class_matches, tuple(signatures))
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

    @override
    def analyze(self, results: dict[str, Result | SigmatcherError]) -> MatchedField:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)
        assert isinstance(parent_class_result.smali_file, Path)

        signatures = self.get_resolved_signatures(results)
        if len(signatures) == 0:
            raise NoSignaturesError(self.name)
        if len(signatures) > 1:
            raise TooManySignaturesError(self.name, signatures)
        signature = signatures[0]

        raw_class = parent_class_result.smali_file.read_text()
        captured_names = signature.capture(raw_class)
        self.check_match_count(captured_names, signatures)
        raw_field_name = next(iter(captured_names))

        new_field = Field.from_java_representation(raw_field_name)
        # TODO: should we get the types for the original field from the definition?
        original_field = Field(name=self.definition.name, type=new_field.type)
        matched_field = MatchedField(original=original_field, new=new_field)
        parent_class_result.matched_fields.append(matched_field)
        return matched_field

    @override
    def get_dependencies(self) -> set[str]:
        return super().get_dependencies() | {self.parent.name}

    @property
    @override
    def name(self) -> str:
        return f"{self.parent.name}.fields.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class MethodAnalyzer(Analyzer):
    definition: MethodDefinition
    parent: ClassAnalyzer

    @override
    def analyze(self, results: dict[str, Result | SigmatcherError]) -> MatchedMethod:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)
        assert isinstance(parent_class_result.smali_file, Path)

        raw_methods = parent_class_result.smali_file.read_text().split(".method")[1:]
        methods = {".method" + method for method in raw_methods}

        signatures = self.get_resolved_signatures(results)
        if len(signatures) == 0:
            raise NoSignaturesError(self.name)

        def check_signature_callback(signature: Signature, matches: set[str]) -> list[str]:
            return signature.check_strings(matches)

        method_matches = filter_signature_matches(signatures, methods, check_signature_callback)

        self.check_match_count(method_matches, signatures)
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

    @override
    def get_dependencies(self) -> set[str]:
        return super().get_dependencies() | {self.parent.name}

    @property
    @override
    def name(self) -> str:
        return f"{self.parent.name}.methods.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class ExportAnalyzer(Analyzer):
    definition: ExportDefinition
    parent: ClassAnalyzer

    @override
    def analyze(self, results: dict[str, Result | SigmatcherError]) -> MatchedExport:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)
        assert isinstance(parent_class_result.smali_file, Path)

        signatures = self.get_resolved_signatures(results)
        if len(signatures) == 0:
            raise NoSignaturesError(self.name)
        if len(signatures) > 1:
            raise TooManySignaturesError(self.name, signatures)
        signature = signatures[0]

        raw_class = parent_class_result.smali_file.read_text()
        captured_names = signature.capture(raw_class)
        self.check_match_count(captured_names, signatures)
        export_value = next(iter(captured_names))

        return MatchedExport.from_value(export_value)

    @override
    def get_dependencies(self) -> set[str]:
        return super().get_dependencies() | {self.parent.name}

    @property
    @override
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
) -> dict[str, Result | SigmatcherError]:
    name_to_analyzer = create_analyzers(definitions, unpacked_path, app_version)

    sorter: graphlib.TopologicalSorter[str] = graphlib.TopologicalSorter()
    for analyzer in name_to_analyzer.values():
        sorter.add(analyzer.name, *analyzer.get_dependencies())

    results: dict[str, Result | SigmatcherError] = {}
    for analyzer_name in sorter.static_order():
        analyzer = name_to_analyzer[analyzer_name]
        try:
            analyzer.check_dependencies(results)
            results[analyzer_name] = analyzer.analyze(results)
        except SigmatcherError as e:
            results[analyzer_name] = e
    return results
