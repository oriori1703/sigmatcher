import dataclasses
import graphlib
import hashlib
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Sequence
from functools import cache, cached_property
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    import re

from sigmatcher.cache import Cache, ResultsCacheType
from sigmatcher.definitions import (
    SIGNATURES_TYPE_ADAPTER,
    BaseRegexSignature,
    ClassDefinition,
    Definition,
    ExportDefinition,
    FieldDefinition,
    MacroStatement,
    MethodDefinition,
    Signature,
    SignatureMatch,
    TopLevelDefinition,
    TopLevelExportDefinition,
    TopLevelFieldDefinition,
    TopLevelMethodDefinition,
)
from sigmatcher.errors import (
    FailedDependencyError,
    InvalidMacroModifierError,
    MissingDependenciesError,
    MissingDynamicCaptureGroupError,
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

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


# Each analyzer produces zero or more results. Static analyzers always produce
# exactly one entry; dynamic analyzers may produce 0+ entries. The dict value
# is either the list of matches or the SigmatcherError raised while computing
# it.
ResultsMapType = dict[str, list[Result] | SigmatcherError]


class ProgressObserver(ABC):
    @abstractmethod
    def on_start(self, total_analyzers: int) -> None:
        """Called once when analysis begins."""

    @abstractmethod
    def on_analyzer_start(self, analyzer_name: str) -> None:
        """Called immediately before analyzing each analyzer."""

    @abstractmethod
    def on_analyzer_complete(self, analyzer_name: str) -> None:
        """Called immediately after each analyzer completes."""


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


def resolve_macro(result: Result, macro_statement: MacroStatement, analyzer_name: str) -> str:
    try:
        resolved_macro = getattr(result.new, macro_statement.modifier)  # pyright: ignore[reportAny]
    except AttributeError:
        raise InvalidMacroModifierError(analyzer_name, macro_statement, result.new.__class__.__name__) from None

    assert isinstance(resolved_macro, str)
    return resolved_macro


def resolve_signatures(
    signatures: tuple[Signature, ...], results: ResultsMapType, analyzer_name: str
) -> tuple[Signature, ...]:
    resolved_signatures: list[Signature] = []
    for signature in signatures:
        resolved_signature = signature
        for macro_statement in signature.get_macro_definitions():
            result_entries = results[macro_statement.subject]
            assert not isinstance(result_entries, Exception)
            # Macros are forbidden against dynamic-name definitions (see the
            # validation pass that runs after merge_definitions_groups), so the
            # referenced result is always a singleton list.
            assert len(result_entries) == 1
            result = result_entries[0]
            resolved_macro = resolve_macro(result, macro_statement, analyzer_name)
            resolved_signature = resolved_signature.resolve_macro(macro_statement, resolved_macro)
        resolved_signatures.append(resolved_signature)

    return tuple(resolved_signatures)


@dataclasses.dataclass(frozen=True)
class Analyzer(ABC):
    definition: Definition
    app_version: str | None

    @abstractmethod
    def analyze(self, results: ResultsMapType) -> list[Result]:
        pass

    def check_match_count(
        self, matches: set[SignatureMatch] | None, signatures: tuple[Signature, ...] | None = None
    ) -> None:
        if matches is None or len(matches) == 0:
            raise NoMatchesError(self.name, signatures)
        if len(matches) > 1:
            raise TooManyMatchesError[SignatureMatch](self.name, signatures, matches)

    def _get_dependencies(self) -> set[str]:
        return self.definition.get_dependencies(self.app_version)

    @cached_property
    def dependencies(self) -> set[str]:
        return self._get_dependencies()

    def check_dependencies(self, results: ResultsMapType) -> None:
        failed_dependencies: list[str] = []
        for dependency_name in self.dependencies:
            child_result = results[dependency_name]
            if isinstance(child_result, Exception):
                failed_dependencies.append(dependency_name)

        if failed_dependencies:
            raise FailedDependencyError(self.name, failed_dependencies)

    def get_resolved_signatures(self, results: ResultsMapType) -> tuple[Signature, ...]:
        return resolve_signatures(self.get_signatures_for_version(), results, self.name)

    def get_signatures_for_version(self) -> tuple[Signature, ...]:
        return self.definition.get_signatures_for_version(self.app_version)

    def _get_cache_content_to_hash(self, results: ResultsMapType) -> bytes:
        return SIGNATURES_TYPE_ADAPTER.dump_json(self.get_resolved_signatures(results))

    def get_cache_key(self, results: ResultsMapType) -> str:
        analyzer_content_hash = hashlib.sha256(self._get_cache_content_to_hash(results))
        # v5: cache value shape changed from a single Result to list[Result] to support
        # dynamic definitions that emit 0+ matches. Previous-version caches are silently
        # ignored (they fail validation and miss).
        return f"v5_{self.name}_{self.app_version}_{analyzer_content_hash.hexdigest()}"

    @property
    def name(self) -> str:
        return self.definition.name

    @override
    def __repr__(self) -> str:
        return self.name

    def from_cache(self, cached_results: list[Result], results: ResultsMapType) -> list[Result]:
        return list(cached_results)


@dataclasses.dataclass(frozen=True)
class ClassAnalyzer(Analyzer, ABC):
    """Common base for class-level analyzers (static and dynamic).

    Subclasses share the file-filtering pipeline but differ in how the readable
    `original.name` is computed and in how many matches they may emit.
    """

    definition: ClassDefinition
    search_root: Path

    def _find_class_matches(self, results: ResultsMapType) -> tuple[list[Signature], set[Path]]:
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
        return signatures, class_matches

    @staticmethod
    def read_new_class(match: Path) -> Class:
        with match.open() as f:
            class_definition_line = f.readline().rstrip("\n")
        _, _, raw_class_name = class_definition_line.rpartition(" ")
        return Class.from_java_representation(raw_class_name)

    def _build_matched_class(self, match: Path, readable_name: str) -> MatchedClass:
        new_class = self.read_new_class(match)
        original_class = Class(name=readable_name, package=self.definition.package or new_class.package)
        return MatchedClass(
            original=original_class,
            new=new_class,
            smali_file=match,
            matched_methods=[],
            matched_fields=[],
            exports=[],
        )

    def _rebuild_cached_class(self, cached: MatchedClass, readable_name: str) -> MatchedClass:
        assert cached.smali_file is not None, "Cached MatchedClass must have a smali_file"
        original_class = Class(name=readable_name, package=self.definition.package or cached.new.package)
        return MatchedClass(
            original=original_class,
            new=cached.new,
            matched_methods=[],
            matched_fields=[],
            exports=[],
            smali_file=cached.smali_file,
        )


@dataclasses.dataclass(frozen=True)
class StaticClassAnalyzer(ClassAnalyzer):
    """A class analyzer whose `original.name` is the YAML `name` itself."""

    @override
    def analyze(self, results: ResultsMapType) -> list[Result]:
        signatures, class_matches = self._find_class_matches(results)
        self.check_match_count(class_matches, tuple(signatures))
        match = next(iter(class_matches))
        return [self._build_matched_class(match, self.definition.name)]

    @override
    def from_cache(self, cached_results: list[Result], results: ResultsMapType) -> list[Result]:
        rebuilt: list[Result] = []
        for cached_result in cached_results:
            assert isinstance(cached_result, MatchedClass)
            rebuilt.append(self._rebuild_cached_class(cached_result, self.definition.name))
        return rebuilt


@dataclasses.dataclass(frozen=True)
class DynamicClassAnalyzer(ClassAnalyzer):
    """A class analyzer whose `original.name` is captured from `(?P<class_name>...)`.

    Emits zero or more MatchedClass entries — one per (matching smali file, captured
    readable name) pair. Zero matches is a legitimate empty result list, not an error.
    """

    @override
    def analyze(self, results: ResultsMapType) -> list[Result]:
        signatures, class_matches = self._find_class_matches(results)
        if not any(
            isinstance(signature, BaseRegexSignature) and signature.has_class_name_group() for signature in signatures
        ):
            # The model-level validator only sees the full signature tuple. The runtime
            # subset is version-filtered; a definition with a non-capturing signature for
            # old versions and a capturing one for new versions can pass validation yet
            # have no class_name group applicable to the current run. Surface that as a
            # dedicated error instead of silently returning an empty match list.
            raise MissingDynamicCaptureGroupError(self.name, self.app_version, "class", "class_name")

        matched: list[Result] = []
        for smali_file in class_matches:
            raw_class = smali_file.read_text()
            captures: set[str] = set()
            for signature in signatures:
                if isinstance(signature, BaseRegexSignature):
                    captures.update(signature.capture_class_name(raw_class))
            # Surrounding whitespace in a capture is treated as insignificant: " Foo"
            # and "Foo" collapse to "Foo", and a capture that is empty / whitespace-only
            # is dropped. See the README "Dynamic Definitions" section.
            captures = {c.strip() for c in captures if c and c.strip()}
            for readable_name in captures:
                matched.append(self._build_matched_class(smali_file, readable_name))
        return matched

    @override
    def from_cache(self, cached_results: list[Result], results: ResultsMapType) -> list[Result]:
        rebuilt: list[Result] = []
        for cached_result in cached_results:
            assert isinstance(cached_result, MatchedClass)
            rebuilt.append(self._rebuild_cached_class(cached_result, cached_result.original.name))
        return rebuilt


@dataclasses.dataclass(frozen=True)
class ChildAnalyzer(Analyzer, ABC):
    parent: ClassAnalyzer

    @override
    def _get_dependencies(self) -> set[str]:
        return super()._get_dependencies() | {self.parent.name}

    @override
    def _get_cache_content_to_hash(self, results: ResultsMapType) -> bytes:
        parent_cache_key = self.parent.get_cache_key(results).encode()
        return super()._get_cache_content_to_hash(results) + parent_cache_key

    @abstractmethod
    def _update_parent_with_child_result(self, new_result: Result, parent_class_result: MatchedClass) -> None:
        raise NotImplementedError()

    @abstractmethod
    def _analyze_for_parent(self, parent_class_result: MatchedClass, signatures: tuple[Signature, ...]) -> Result:
        """Produce a single Result for one parent class match.

        Raises a SigmatcherError if this child cannot match against this parent — the
        outer template method `analyze` translates that into the all-or-nothing failure
        decision (see decision #6 in the redesign spec).
        """
        raise NotImplementedError()

    def _get_parent_matches(self, results: ResultsMapType) -> list[MatchedClass]:
        parent_class_results = results[self.parent.name]
        assert not isinstance(parent_class_results, Exception)
        parents: list[MatchedClass] = []
        for entry in parent_class_results:
            assert isinstance(entry, MatchedClass)
            parents.append(entry)
        return parents

    @override
    def analyze(self, results: ResultsMapType) -> list[Result]:
        parents = self._get_parent_matches(results)
        if not parents:
            # Parent dynamic def matched 0 entities → child runs 0 times. Decision #8.
            return []
        signatures = self._resolve_signatures_or_raise(results)
        # All-or-nothing across the N parent matches (decision #6): if any single
        # parent fails, the entire child result is one SigmatcherError, not a mixed
        # list. This keeps the result typing clean for downstream consumers.
        child_results: list[Result] = []
        for parent in parents:
            child_result = self._analyze_for_parent(parent, signatures)
            self._update_parent_with_child_result(child_result, parent)
            child_results.append(child_result)
        return child_results

    def _resolve_signatures_or_raise(self, results: ResultsMapType) -> tuple[Signature, ...]:
        signatures = self.get_resolved_signatures(results)
        if len(signatures) == 0:
            raise NoSignaturesError(self.name)
        return signatures

    @override
    def from_cache(self, cached_results: list[Result], results: ResultsMapType) -> list[Result]:
        parents_by_smali = {parent.new.to_java_representation(): parent for parent in self._get_parent_matches(results)}
        for cached_result in cached_results:
            # Cached child results store the parent's obfuscated java repr so we can
            # re-link them to the right parent after a multi-match parent.
            parent = self._parent_for_cached(cached_result, parents_by_smali)
            if parent is None:
                # Parent set changed between runs (e.g. a previously-cached parent is no
                # longer matched). Skip — the orchestrator will re-run the child rather
                # than serving a stale cache hit.
                continue
            self._update_parent_with_child_result(cached_result, parent)

        return super().from_cache(cached_results, results)

    def _parent_for_cached(
        self, cached_result: Result, parents_by_smali: dict[str, MatchedClass]
    ) -> MatchedClass | None:
        # Cached children carry the parent's obfuscated java repr via `smali_class`
        # (see MatchedField/MatchedMethod/MatchedExport). Use it as the parent_match_id
        # so we re-link correctly after a multi-match parent.
        smali_class = getattr(cached_result, "smali_class", None)
        if smali_class is not None:
            return parents_by_smali.get(smali_class.to_java_representation())  # pyright: ignore[reportAny]
        # Fallback for single-parent children — match the only available parent.
        if len(parents_by_smali) == 1:
            return next(iter(parents_by_smali.values()))
        return None


@dataclasses.dataclass(frozen=True)
class FieldAnalyzer(ChildAnalyzer):
    definition: FieldDefinition

    @override
    def _analyze_for_parent(self, parent_class_result: MatchedClass, signatures: tuple[Signature, ...]) -> Result:
        assert isinstance(parent_class_result.smali_file, Path)
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
        return MatchedField(original=original_field, new=new_field, smali_class=parent_class_result.new)

    @override
    def _update_parent_with_child_result(self, new_result: Result, parent_class_result: MatchedClass) -> None:
        assert isinstance(new_result, MatchedField)
        parent_class_result.matched_fields.append(new_result)

    @property
    @override
    def name(self) -> str:
        return f"{self.parent.name}.fields.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class MethodAnalyzer(ChildAnalyzer):
    definition: MethodDefinition

    @override
    def _analyze_for_parent(self, parent_class_result: MatchedClass, signatures: tuple[Signature, ...]) -> Result:
        assert isinstance(parent_class_result.smali_file, Path)

        raw_methods = parent_class_result.smali_file.read_text().split(".method")[1:]
        methods = {".method" + method for method in raw_methods}

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
        return MatchedMethod(original=original_method, new=new_method, smali_class=parent_class_result.new)

    @override
    def _update_parent_with_child_result(self, new_result: Result, parent_class_result: MatchedClass) -> None:
        assert isinstance(new_result, MatchedMethod)
        parent_class_result.matched_methods.append(new_result)

    @property
    @override
    def name(self) -> str:
        return f"{self.parent.name}.methods.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class ExportAnalyzer(ChildAnalyzer):
    definition: ExportDefinition

    @override
    def _analyze_for_parent(self, parent_class_result: MatchedClass, signatures: tuple[Signature, ...]) -> Result:
        assert isinstance(parent_class_result.smali_file, Path)
        if len(signatures) > 1:
            raise TooManySignaturesError(self.name, signatures)
        signature = signatures[0]

        raw_class = parent_class_result.smali_file.read_text()
        captured_names = signature.capture(raw_class)
        self.check_match_count(captured_names, signatures)
        export_value = next(iter(captured_names))

        return MatchedExport.from_value(self.definition.name, export_value, smali_class=parent_class_result.new)

    @override
    def _update_parent_with_child_result(self, new_result: Result, parent_class_result: MatchedClass) -> None:
        assert isinstance(new_result, MatchedExport)
        parent_class_result.exports.append(new_result)

    @property
    @override
    def name(self) -> str:
        return f"{self.parent.name}.exports.{self.definition.name}"


@dataclasses.dataclass(frozen=True)
class TopLevelDynamicAnalyzer(Analyzer, ABC):
    """Common base for top-level corpus-scanning method/field/export analyzers."""

    search_root: Path
    capture_group_name: ClassVar[str] = ""

    def _resolve_single_signature(self, results: ResultsMapType) -> Signature:
        signatures = self.get_resolved_signatures(results)
        if len(signatures) == 0:
            raise NoSignaturesError(self.name)
        if len(signatures) > 1:
            raise TooManySignaturesError(self.name, signatures)
        return signatures[0]

    def _capture_axis_name(self, match: "re.Match[str]") -> str | None:
        """Return the stripped axis-specific capture, or None if absent/empty.

        A named group inside an alternation that didn't participate in the match
        (e.g. `sentinel|(?P<method_name>FOO)` when the input matched `sentinel`)
        returns None from `match.group(...)`. None and empty/whitespace-only
        captures are treated as "no axis name" rather than raising.
        """
        try:
            captured_raw = match.group(self.capture_group_name)
        except IndexError:
            return None
        if captured_raw is None:
            return None
        captured = captured_raw.strip()
        return captured or None

    def _readable_name_for(self, match: "re.Match[str]", *, dynamic_name: bool) -> str | None:
        if not dynamic_name:
            return self.definition.name
        return self._capture_axis_name(match)


@dataclasses.dataclass(frozen=True)
class TopLevelDynamicMethodAnalyzer(TopLevelDynamicAnalyzer):
    """Scan the full smali corpus for methods matching a top-level method definition.

    The readable method name comes from a `(?P<method_name>...)` capture group. Each
    occurrence becomes its own MatchedMethod, tagged with the obfuscated parent class
    so output formats can synthesize a holder class entry.
    """

    definition: TopLevelMethodDefinition
    capture_group_name: ClassVar[str] = "method_name"

    @override
    def analyze(self, results: ResultsMapType) -> list[Result]:
        signature = self._resolve_single_signature(results)
        return list(self._scan_corpus(signature))

    def _scan_corpus(self, signature: Signature) -> Iterable[MatchedMethod]:
        if not isinstance(signature, BaseRegexSignature):
            return
        for smali_file in get_smali_files(self.search_root):
            smali_class = ClassAnalyzer.read_new_class(smali_file)
            for method_block in _iter_method_blocks(smali_file.read_text()):
                yield from self._yield_method_match(signature, method_block, smali_class)

    def _yield_method_match(
        self, signature: BaseRegexSignature, method_block: str, smali_class: Class
    ) -> Iterable[MatchedMethod]:
        regex = signature.signature
        method_definition_line, _, _ = method_block.partition("\n")
        _, _, raw_method_name = method_definition_line.rpartition(" ")
        new_method = Method.from_java_representation(raw_method_name)
        for match in regex.finditer(method_block):
            readable_name = self._readable_name_for(match, dynamic_name=self.definition.dynamic_name)
            if readable_name is None:
                continue
            original_method = Method(
                name=readable_name,
                argument_types=new_method.argument_types,
                return_type=new_method.return_type,
            )
            yield MatchedMethod(original=original_method, new=new_method, smali_class=smali_class)
            # One match per method block — additional captures inside the same method
            # body would re-emit the same MatchedMethod under different readable names,
            # which confuses downstream collision detection.
            return


@dataclasses.dataclass(frozen=True)
class TopLevelDynamicFieldAnalyzer(TopLevelDynamicAnalyzer):
    """Scan the full smali corpus for fields matching a top-level field definition."""

    definition: TopLevelFieldDefinition
    capture_group_name: ClassVar[str] = "field_name"

    @override
    def analyze(self, results: ResultsMapType) -> list[Result]:
        signature = self._resolve_single_signature(results)
        return list(self._scan_corpus(signature))

    def _scan_corpus(self, signature: Signature) -> Iterable[MatchedField]:
        if not isinstance(signature, BaseRegexSignature):
            return
        for smali_file in get_smali_files(self.search_root):
            smali_class = ClassAnalyzer.read_new_class(smali_file)
            for match in signature.signature.finditer(smali_file.read_text()):
                yielded = self._build_field(match, smali_class)
                if yielded is not None:
                    yield yielded

    def _build_field(self, match: "re.Match[str]", smali_class: Class) -> MatchedField | None:
        raw_field = _captured_match_or_full(match)
        new_field = Field.from_java_representation(raw_field)
        readable_name = self._readable_name_for(match, dynamic_name=self.definition.dynamic_name)
        if readable_name is None:
            return None
        original_field = Field(name=readable_name, type=new_field.type)
        return MatchedField(original=original_field, new=new_field, smali_class=smali_class)


@dataclasses.dataclass(frozen=True)
class TopLevelDynamicExportAnalyzer(TopLevelDynamicAnalyzer):
    """Scan the full smali corpus for exports matching a top-level export definition."""

    definition: TopLevelExportDefinition
    capture_group_name: ClassVar[str] = "export_name"

    @override
    def analyze(self, results: ResultsMapType) -> list[Result]:
        signature = self._resolve_single_signature(results)
        return list(self._scan_corpus(signature))

    def _scan_corpus(self, signature: Signature) -> Iterable[MatchedExport]:
        if not isinstance(signature, BaseRegexSignature):
            return
        for smali_file in get_smali_files(self.search_root):
            smali_class = ClassAnalyzer.read_new_class(smali_file)
            for match in signature.signature.finditer(smali_file.read_text()):
                yielded = self._build_export(match, smali_class)
                if yielded is not None:
                    yield yielded

    def _build_export(self, match: "re.Match[str]", smali_class: Class) -> MatchedExport | None:
        export_value = _captured_match_or_full(match)
        readable_name = self._readable_name_for(match, dynamic_name=self.definition.dynamic_name)
        if readable_name is None:
            return None
        return MatchedExport.from_value(readable_name, export_value, smali_class=smali_class)


def _iter_method_blocks(smali_text: str) -> Iterable[str]:
    """Split a smali file's contents into individual method blocks."""
    raw_methods = smali_text.split(".method")[1:]
    for raw_method in raw_methods:
        yield ".method" + raw_method


def _captured_match_or_full(match: "re.Match[str]") -> str:
    """Return `match.group("match")` if defined, else the full matched string."""
    try:
        return match.group("match")
    except IndexError:
        return match.group(0)


def _create_class_analyzers(
    class_definition: ClassDefinition, search_root: Path, app_version: str | None
) -> Iterable[tuple[str, Analyzer]]:
    class_analyzer: ClassAnalyzer
    if class_definition.dynamic_name:
        class_analyzer = DynamicClassAnalyzer(class_definition, app_version, search_root)
    else:
        class_analyzer = StaticClassAnalyzer(class_definition, app_version, search_root)
    yield class_definition.name, class_analyzer

    for method_definition in class_definition.methods:
        if method_definition.is_in_version_range(app_version):
            method_analyzer = MethodAnalyzer(method_definition, app_version, parent=class_analyzer)
            yield method_analyzer.name, method_analyzer

    for field_definition in class_definition.fields:
        if field_definition.is_in_version_range(app_version):
            field_analyzer = FieldAnalyzer(field_definition, app_version, parent=class_analyzer)
            yield field_analyzer.name, field_analyzer

    for export_definition in class_definition.exports:
        if export_definition.is_in_version_range(app_version):
            export_analyzer = ExportAnalyzer(export_definition, app_version, parent=class_analyzer)
            yield export_analyzer.name, export_analyzer


def _create_top_level_analyzer(
    top_level_definition: TopLevelDefinition, search_root: Path, app_version: str | None
) -> Analyzer:
    if isinstance(top_level_definition, TopLevelMethodDefinition):
        return TopLevelDynamicMethodAnalyzer(top_level_definition, app_version, search_root)
    if isinstance(top_level_definition, TopLevelFieldDefinition):
        return TopLevelDynamicFieldAnalyzer(top_level_definition, app_version, search_root)
    assert isinstance(top_level_definition, TopLevelExportDefinition)
    return TopLevelDynamicExportAnalyzer(top_level_definition, app_version, search_root)


def create_analyzers(
    definitions: Sequence[TopLevelDefinition], search_root: Path, app_version: str | None
) -> dict[str, Analyzer]:
    canonical_search_root = search_root.resolve()
    name_to_analyzer: dict[str, Analyzer] = {}
    for top_level_definition in definitions:
        if not top_level_definition.is_in_version_range(app_version):
            continue

        if isinstance(top_level_definition, ClassDefinition):
            for name, analyzer in _create_class_analyzers(top_level_definition, canonical_search_root, app_version):
                name_to_analyzer[name] = analyzer
        else:
            analyzer = _create_top_level_analyzer(top_level_definition, canonical_search_root, app_version)
            name_to_analyzer[analyzer.name] = analyzer

    return name_to_analyzer


def sort_analyzers(name_to_analyzer: dict[str, Analyzer], results: ResultsMapType) -> Iterable[str]:
    analyzers_set = set(name_to_analyzer.keys())

    sorter: graphlib.TopologicalSorter[str] = graphlib.TopologicalSorter()
    for analyzer in name_to_analyzer.values():
        dependencies = analyzer.dependencies
        nonexistent_dependencies = dependencies.difference(analyzers_set)
        if nonexistent_dependencies:
            results[analyzer.name] = MissingDependenciesError(analyzer.name, list(nonexistent_dependencies))
        else:
            sorter.add(analyzer.name, *dependencies)

    return sorter.static_order()


def analyze(
    definitions: Sequence[TopLevelDefinition],
    cache: Cache,
    app_version: str | None,
    progress_observer: ProgressObserver | None = None,
) -> ResultsMapType:
    results: ResultsMapType = {}
    name_to_analyzer = create_analyzers(definitions, cache.get_apktool_cache_dir(), app_version)
    sorted_analyzers = list(sort_analyzers(name_to_analyzer, results))

    previous_results_cache = cache.get_results_cache()
    new_results_cache: ResultsCacheType = {}

    excluded_results: list[str] = []

    if progress_observer is not None:
        progress_observer.on_start(total_analyzers=len(sorted_analyzers))

    for analyzer_name in sorted_analyzers:
        if progress_observer is not None:
            progress_observer.on_analyzer_start(analyzer_name)

        analyzer = name_to_analyzer[analyzer_name]
        try:
            analyzer.check_dependencies(results)

            cache_key = analyzer.get_cache_key(results)
            cached_result = previous_results_cache.get(cache_key)
            if cached_result is None:
                analyzer_results = analyzer.analyze(results)
            else:
                analyzer_results = analyzer.from_cache(cached_result, results)

            results[analyzer_name] = analyzer_results
            new_results_cache[cache_key] = analyzer_results

            if analyzer.definition.exclude:
                excluded_results.append(analyzer_name)
        except SigmatcherError as e:
            results[analyzer_name] = e

        if progress_observer is not None:
            progress_observer.on_analyzer_complete(analyzer_name)

    cache.write_results_cache(new_results_cache)

    for excluded_result_name in excluded_results:
        del results[excluded_result_name]

    return results
