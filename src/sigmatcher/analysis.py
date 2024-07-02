import dataclasses
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple, TypeVar, Union

import rich

from sigmatcher.definitions import (
    ClassDefinition,
    Definition,
    Definitions,
    FieldDefinition,
    InvalidMacroModifierError,
    MethodDefinition,
    Signature,
)
from sigmatcher.results import Class, Field, MatchedClass, MatchedField, MatchedMethod, Method, Result


class MatchError(Exception):
    pass


class NoMatchesError(MatchError):
    pass


class TooManyMatchesError(MatchError):
    pass


class DependencyMatchError(MatchError):
    pass


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
class Analyzer(ABC):
    definition: Definition

    @abstractmethod
    def analyze(self, unpacked_path: Path, results: Dict[str, Union[Result, Exception, None]]) -> Result:
        pass

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

    def analyze(self, unpacked_path: Path, results: Dict[str, Union[Result, Exception, None]]) -> MatchedField:
        parent_class_result = results[self.parent.name]
        assert isinstance(parent_class_result, MatchedClass)

        raw_class = parent_class_result.smali_file.read_text()
        signature = self.definition.signatures[0].resolve_macros(results)
        captured_names = set(signature.capture(raw_class))

        if len(captured_names) == 0:
            raise NoMatchesError(f"Found no match for {self.name}!")
        if len(captured_names) > 1:
            raise TooManyMatchesError(f"Found too many matches for {self.name}: {captured_names}")
        raw_field_name = next(iter(captured_names))

        new_field = Field.from_java_representation(raw_field_name)
        # TODO: should we get the types for the original field from the definition?
        original_field = Field(self.definition.name, new_field.type)
        matched_field = MatchedField(original_field, new_field)
        parent_class_result.matched_fields.append(matched_field)
        return matched_field

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
        matched_method = MatchedMethod(original_method, new_method)
        parent_class_result.matched_methods.append(matched_method)
        return matched_method

    @property
    def name(self) -> str:
        return f"{self.parent.name}.methods.{self.definition.name}"


@dataclasses.dataclass
class DependencyNode:
    analyzer: Analyzer
    successors: Set["DependencyNode"] = dataclasses.field(default_factory=set)
    ancestors: Set["DependencyNode"] = dataclasses.field(default_factory=set)
    score: int = 0

    def add_ancestor(self, ancestor: "DependencyNode") -> None:
        self.ancestors.add(ancestor)
        ancestor.successors.add(self)

    def add_successor(self, dependency: "DependencyNode") -> None:
        self.successors.add(dependency)
        dependency.ancestors.add(self)

    def check_dependencies(self, results: Dict["str", Union[Result, Exception, None]]) -> None:
        failed_dependencies: List[str] = []
        for child in self.ancestors:
            child_result = results[child.analyzer.name]
            assert child_result is not None
            if isinstance(child_result, Exception):
                failed_dependencies.append(child.analyzer.name)

        if failed_dependencies:
            raise DependencyMatchError(
                f"Skipped {self.analyzer.name} because of the following dependencies failed: {failed_dependencies}"
            )

    def __hash__(self) -> int:
        return hash(self.analyzer)

    def __repr__(self) -> str:
        return f"DependencyNode({self.analyzer.name})"


def create_dependency_graph(name_to_node: Dict[str, DependencyNode]) -> List[DependencyNode]:
    root_node: List[DependencyNode] = []
    for node in name_to_node.values():
        for dependency in node.analyzer.definition.get_dependencies():
            node.add_ancestor(name_to_node[dependency])
        if not node.ancestors:
            root_node.append(node)

    return root_node


def sort_dependency_graph(root_nodes: List[DependencyNode], nodes: Iterable[DependencyNode]) -> List[DependencyNode]:
    def visit(node: DependencyNode) -> None:
        if node.ancestors:
            new_score = max(ancestor.score for ancestor in node.ancestors) + 1
        else:
            new_score = 1
        if new_score > node.score:
            node.score = new_score
            for successor in node.successors:
                visit(successor)

    for root_node in root_nodes:
        visit(root_node)
    return sorted(nodes, key=lambda node: node.score)


def sort_dependencies(name_to_node: Dict[str, DependencyNode]) -> List[DependencyNode]:
    root_nodes = create_dependency_graph(name_to_node)
    return sort_dependency_graph(root_nodes, name_to_node.values())


def analyze(definitions: Definitions, unpacked_path: Path) -> None:
    name_to_node: Dict[str, DependencyNode] = {}
    for class_definition in definitions.defs:
        class_analyzer = ClassAnalyzer(class_definition)
        class_node = DependencyNode(class_analyzer)
        name_to_node[class_definition.name] = class_node

        for method_definition in class_definition.methods:
            method_analyzer = MethodAnalyzer(method_definition, parent=class_analyzer)
            method_node = DependencyNode(method_analyzer)
            method_node.add_ancestor(class_node)
            name_to_node[method_analyzer.name] = method_node

        for field_definition in class_definition.fields:
            field_analyzer = FieldAnalyzer(field_definition, parent=class_analyzer)
            field_node = DependencyNode(field_analyzer)
            field_node.add_ancestor(class_node)
            name_to_node[field_analyzer.name] = field_node

    sorted_nodes = sort_dependencies(name_to_node)

    results: Dict[str, Union[Result, Exception, None]] = {}
    for node in sorted_nodes:
        analyzer = node.analyzer
        try:
            node.check_dependencies(results)
            results[analyzer.name] = analyzer.analyze(unpacked_path, results)
        except (MatchError, InvalidMacroModifierError) as e:
            results[analyzer.name] = e
            rich.print(f"[yellow]{e!s}[/yellow]")

    rich.print(results)
