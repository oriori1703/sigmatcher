import fnmatch
import re
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, Protocol, TypeAlias, TypeVar

import pydantic
from packaging.specifiers import SpecifierSet

from sigmatcher.grep import rip_regex

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


def is_in_version_range(app_version: str | None, version_range: str | list[str] | None) -> bool:
    if app_version is None or version_range is None:
        return True
    ranges = version_range if isinstance(version_range, list) else [version_range]
    return any(SpecifierSet(spec).contains(app_version) for spec in ranges)


@dataclass(frozen=True)
class MacroStatement:
    subject: str
    modifier: str


class CountRange(pydantic.BaseModel):
    min_count: int
    max_count: int

    def __contains__(self, value: int) -> bool:
        return self.min_count <= value <= self.max_count


class BaseSignature(ABC, pydantic.BaseModel, frozen=True, use_attribute_docstrings=True, extra="forbid"):  # pyright: ignore[reportUnsafeMultipleInheritance]
    version_range: str | list[str] | None = None
    """The version range in which the signature is valid."""
    count: Annotated[CountRange, pydantic.Field(json_schema_extra={"default": 1})] = CountRange(
        min_count=1, max_count=1
    )
    """The number of times the signature should match in order to be considered a match.
    Can be either an integer or a string of the form "min-max"."""

    @abstractmethod
    def check_files(self, search_paths: set[Path], search_root: Path) -> list[Path]:
        raise NotImplementedError()

    @abstractmethod
    def check_strings(self, strings: Iterable[str]) -> list[str]:
        raise NotImplementedError()

    @abstractmethod
    def capture(self, value: str) -> set[str]:
        raise NotImplementedError()

    @abstractmethod
    def get_dependencies(self) -> list[str]:
        raise NotImplementedError()

    @abstractmethod
    def get_macro_definitions(self) -> set[MacroStatement]:
        raise NotImplementedError()

    @abstractmethod
    def resolve_macro(self, macro_statement: MacroStatement, resolved_macro: str) -> Self:
        raise NotImplementedError()

    def is_in_version_range(self, app_version: str | None) -> bool:
        return is_in_version_range(app_version, self.version_range)

    @pydantic.field_validator("count", mode="before", json_schema_input_type=int | str)
    @classmethod
    def _parse_count(cls, v: str | int) -> CountRange:
        if isinstance(v, str):
            min_count, max_count = map(int, v.split("-"))
        else:
            min_count, max_count = v, v
        return CountRange(min_count=min_count, max_count=max_count)

    @pydantic.field_serializer("count", mode="plain")
    @staticmethod
    def _serialize_count(count: CountRange) -> int | str:
        if count.min_count == count.max_count:
            return count.min_count
        return f"{count.min_count}-{count.max_count}"


class BaseRegexSignature(BaseSignature, frozen=True):
    signature: "re.Pattern[str]" = pydantic.Field(
        json_schema_extra={"x-intellij-language-injection": {"language": "RegExp"}}
    )
    """
    A regular expression used to check the signature.

    When used for capturing strings, if there is more than one match,
    a named group called `match` should be used to specify what should be captured.

    Can include macros in the form of `${<result>.<property>}`.
    Results are actually objects from `sigmatcher.results` package.
    i.e. `Class`, `Field`, `Method`, `Export` objects.
    Property could be any python property that the objects holds.

    For example a macro could look like `${MyClass.fields.java}`, which would return something like
    `Lf9/s;->a:LX/Y/Z/A02;`
    """

    MACRO_REGEX: "ClassVar[re.Pattern[str]]" = re.compile(r"\${(.*?)}")

    @override
    def check_files(self, search_paths: set[Path], search_root: Path) -> list[Path]:
        # Limit the search to avoid too many arguments to ripgrep
        match_limit = 100
        if len(search_paths) > match_limit:
            search_paths_for_rg = {search_root}
        else:
            search_paths_for_rg = search_paths
        file_to_match_count = rip_regex(self.signature, search_paths_for_rg)
        if self.count.min_count > 0:
            # Optimization: do not iterate over files with 0 matches
            return [path.resolve() for path, match_count in file_to_match_count.items() if match_count in self.count]
        # rip_regex only includes files with count > 0 in the result.
        return [path.resolve() for path in search_paths if file_to_match_count.get(path, 0) in self.count]

    @override
    def check_strings(self, strings: Iterable[str]) -> list[str]:
        results: list[str] = []
        for string in strings:
            match_count = len(self.signature.findall(string))
            if match_count in self.count:
                results.append(string)
        return results

    @override
    def capture(self, value: str) -> set[str]:
        match = self.signature.search(value)
        if match is None:
            return set()
        try:
            return {match.group("match")}
        except IndexError:
            pass

        return set(match.groups())

    def has_class_name_group(self) -> bool:
        return "class_name" in self.signature.groupindex

    def capture_class_name(self, value: str) -> set[str]:
        captures: set[str] = set()
        for match in self.signature.finditer(value):
            try:
                captures.add(match.group("class_name"))
            except IndexError:
                continue
        return captures

    @override
    def get_dependencies(self) -> list[str]:
        return [macro.subject for macro in self.get_macro_definitions()]

    @override
    def get_macro_definitions(self) -> set[MacroStatement]:
        return self._cached_macro_definitions

    @cached_property
    def _cached_macro_definitions(self) -> set[MacroStatement]:
        macros: set[MacroStatement] = set()

        for raw_macro in self.MACRO_REGEX.findall(self.signature.pattern):  # pyright: ignore[reportAny]
            assert isinstance(raw_macro, str)
            macro_subject, _, macro_modifier = raw_macro.rpartition(".")
            macros.add(MacroStatement(macro_subject, macro_modifier))

        return macros

    @override
    def resolve_macro(self, macro_statement: MacroStatement, resolved_macro: str) -> Self:
        macro_string = f"{macro_statement.subject}.{macro_statement.modifier}"
        new_pattern = self.signature.pattern.replace(f"${{{macro_string}}}", re.escape(resolved_macro))

        return self.model_copy(update={"signature": re.compile(new_pattern)})


class RegexSignature(BaseRegexSignature, frozen=True):
    type: Literal["regex"] = "regex"
    """The type of the signature."""


class GlobSignature(BaseRegexSignature, frozen=True):
    type: Literal["glob"] = "glob"
    """The type of the signature."""

    @pydantic.field_validator("signature", mode="before")
    @classmethod
    def parse_glob(cls, v: str) -> str:
        # TODO: removing the atomic group, i.e. the "(?>" makes glob signature in the form of "*WORD*" slower then
        #  their regex counterparts
        return fnmatch.translate(v).replace("\\Z", "$").replace("(?>", "(?:")


class TreeSitterSignature(BaseSignature, frozen=True):
    signature: str
    """A TreeSitter s-query used to check the signature."""
    type: Literal["treesitter"] = "treesitter"
    """The type of the signature."""

    @override
    def check_files(self, search_paths: set[Path], search_root: Path) -> list[Path]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    @override
    def check_strings(self, strings: Iterable[str]) -> list[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    @override
    def capture(self, value: str) -> set[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    @override
    def get_dependencies(self) -> list[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    @override
    def get_macro_definitions(self) -> set[MacroStatement]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    @override
    def resolve_macro(self, macro_statement: MacroStatement, resolved_macro: str) -> Self:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")


Signature: TypeAlias = Annotated[
    RegexSignature | GlobSignature | TreeSitterSignature, pydantic.Field(discriminator="type")
]

SignatureMatch = TypeVar("SignatureMatch", str, Path)


class Definition(pydantic.BaseModel, frozen=True, use_attribute_docstrings=True, extra="forbid"):
    name: str
    """The name of the definition, i.e. the class, method, field, or export name."""
    signatures: tuple[Signature, ...]
    """A list of signatures that define the definition."""
    version_range: str | list[str] | None = None
    """The version range in which the definition is valid."""
    exclude: bool = False
    """Exclude this definition from the final results.
    This could be useful if the definition is only used to find something else using a macro"""

    def get_signatures_for_version(self, app_version: str | None) -> tuple[Signature, ...]:
        if app_version is None:
            return self.signatures
        return tuple(signature for signature in self.signatures if signature.is_in_version_range(app_version))

    def get_dependencies(self, app_version: str | None) -> set[str]:
        dependencies: set[str] = set()
        for signature in self.get_signatures_for_version(app_version):
            dependencies.update(signature.get_dependencies())
        return dependencies

    def is_in_version_range(self, app_version: str | None) -> bool:
        return is_in_version_range(app_version, self.version_range)


class ExportDefinition(Definition, frozen=True):
    pass


class FieldDefinition(Definition, frozen=True):
    pass


class MethodDefinition(Definition, frozen=True):
    pass


class _DynamicNameValidatable(Protocol):
    """Structural protocol describing the attributes the dynamic_name validator reads.

    Used purely for typing — the actual fields are declared on each concrete model.
    """

    @property
    def name(self) -> str: ...
    @property
    def dynamic_name(self) -> bool: ...
    @property
    def signatures(self) -> tuple[Signature, ...]: ...


def _validate_dynamic_name_group(model: _DynamicNameValidatable, axis_label: str, capture_group_name: str) -> None:
    """Enforce that `dynamic_name` matches the presence of the axis-specific named group.

    Each axis (class / method / field / export) uses a different named capture group
    (`class_name`, `method_name`, ...). Centralized so the four subclasses all share
    one set of error messages.
    """
    has_group = any(
        isinstance(sig, BaseRegexSignature) and capture_group_name in sig.signature.groupindex
        for sig in model.signatures
    )
    if model.dynamic_name and not has_group:
        raise ValueError(
            f"{type(model).__name__} {model.name!r} has dynamic_name=True but no signature "
            f"contains a (?P<{capture_group_name}>...) named group."
        )
    if not model.dynamic_name and has_group:
        raise ValueError(
            f"{type(model).__name__} {model.name!r} contains a (?P<{capture_group_name}>...) named group "
            f"but dynamic_name is not set. Set dynamic_name: true to enable capturing "
            f"the {axis_label} name from the signature."
        )


class ClassDefinition(Definition, frozen=True):
    type: Literal["class"] = "class"
    """The top-level definition kind. Defaults to "class" so existing signature
    files without a `type:` discriminator still validate."""
    package: str | None = None
    """The package of the class."""
    fields: tuple[FieldDefinition, ...] = ()
    """A list of field definitions."""
    methods: tuple[MethodDefinition, ...] = ()
    """A list of method definitions."""
    exports: tuple[ExportDefinition, ...] = ()
    """A list of export definitions."""
    dynamic_name: bool = False
    """If true, capture the readable class name from a `(?P<class_name>...)` named group
    in one of the signatures. The YAML `name` is the placeholder used for macros,
    caching, and dependency-graph identity; the captured value becomes the readable
    `original.name` in the result and is what shows up in output mapping formats."""

    @pydantic.model_validator(mode="after")
    def _check_dynamic_name_group(self) -> Self:
        _validate_dynamic_name_group(self, "class", "class_name")
        return self


def _require_dynamic_name_for_top_level(model: _DynamicNameValidatable, axis_label: str) -> None:
    """Top-level method/field/export defs only make sense in the dynamic_name=True shape.

    Static methods/fields/exports must be declared as children of a class definition —
    that's the documented path. A `dynamic_name=False` top-level def has no readable
    name to capture and no parent class to attach to, so it would silently produce no
    useful output. Reject it at validation time instead.
    """
    if not model.dynamic_name:
        raise ValueError(
            f"{type(model).__name__} {model.name!r} has dynamic_name=False. Top-level "
            f"{axis_label} definitions must set dynamic_name: true and include a "
            f"(?P<{axis_label}_name>...) capture group; static {axis_label}s should be "
            "declared as children of a class definition instead."
        )


class TopLevelMethodDefinition(MethodDefinition, frozen=True):
    """A top-level method definition. Scans the entire smali corpus and produces
    zero or more MatchedMethod results, one per occurrence. The readable name comes
    from a `(?P<method_name>...)` capture group; `dynamic_name` must be true."""

    type: Literal["method"] = "method"
    """The top-level definition kind."""
    dynamic_name: bool = False
    """If true, capture the readable method name from a `(?P<method_name>...)` named group.
    Top-level method definitions must set this to true — see the validator below."""

    @pydantic.model_validator(mode="after")
    def _check_dynamic_name_group(self) -> Self:
        _require_dynamic_name_for_top_level(self, "method")
        _validate_dynamic_name_group(self, "method", "method_name")
        return self


class TopLevelFieldDefinition(FieldDefinition, frozen=True):
    """A top-level field definition. Scans the entire smali corpus and produces
    zero or more MatchedField results. The readable name comes from a
    `(?P<field_name>...)` capture group; `dynamic_name` must be true."""

    type: Literal["field"] = "field"
    """The top-level definition kind."""
    dynamic_name: bool = False
    """If true, capture the readable field name from a `(?P<field_name>...)` named group.
    Top-level field definitions must set this to true — see the validator below."""

    @pydantic.model_validator(mode="after")
    def _check_dynamic_name_group(self) -> Self:
        _require_dynamic_name_for_top_level(self, "field")
        _validate_dynamic_name_group(self, "field", "field_name")
        return self


class TopLevelExportDefinition(ExportDefinition, frozen=True):
    """A top-level export definition. Scans the entire smali corpus and produces
    zero or more MatchedExport results. The readable name comes from a
    `(?P<export_name>...)` capture group; `dynamic_name` must be true."""

    type: Literal["export"] = "export"
    """The top-level definition kind."""
    dynamic_name: bool = False
    """If true, capture the readable export name from a `(?P<export_name>...)` named group.
    Top-level export definitions must set this to true — see the validator below."""

    @pydantic.model_validator(mode="after")
    def _check_dynamic_name_group(self) -> Self:
        _require_dynamic_name_for_top_level(self, "export")
        _validate_dynamic_name_group(self, "export", "export_name")
        return self


def _top_level_type_discriminator(value: Any) -> str:  # noqa: ANN401
    """Return the discriminator value for a top-level definition entry.

    Accepts dict input (from YAML parsing) or already-validated model instances.
    Missing `type` defaults to "class" so a bare list of class defs (the v1.x
    format) still validates.
    """
    if isinstance(value, dict):
        return str(value.get("type", "class"))
    return str(getattr(value, "type", "class"))


TopLevelDefinition: TypeAlias = Annotated[
    Annotated[ClassDefinition, pydantic.Tag("class")]
    | Annotated[TopLevelMethodDefinition, pydantic.Tag("method")]
    | Annotated[TopLevelFieldDefinition, pydantic.Tag("field")]
    | Annotated[TopLevelExportDefinition, pydantic.Tag("export")],
    pydantic.Discriminator(_top_level_type_discriminator),
]


DEFINITIONS_TYPE_ADAPTER = pydantic.TypeAdapter(list[TopLevelDefinition])
SIGNATURES_TYPE_ADAPTER = pydantic.TypeAdapter(tuple[Signature, ...])

TDefinition = TypeVar("TDefinition", bound=Definition)


def merge_definition(def1: TDefinition, def2: TDefinition) -> TDefinition:
    signatures = def2.signatures or def1.signatures

    if isinstance(def1, ClassDefinition):
        assert isinstance(def2, ClassDefinition)
        # Re-validate via model_validate so model-level validators (e.g. the
        # dynamic_name consistency check) run on the merged definition.
        # model_copy alone bypasses validators, which would let a merged
        # ClassDefinition end up with a `(?P<class_name>...)` group but
        # dynamic_name=False, silently disabling capture.
        merged = def1.model_copy(
            update={
                "signatures": signatures,
                "methods": merge_definitions_groups([def1.methods, def2.methods]),
                "fields": merge_definitions_groups([def1.fields, def2.fields]),
                "exports": merge_definitions_groups([def1.exports, def2.exports]),
            }
        )
        return type(def1).model_validate(  # pyrefly: ignore[bad-return] related to https://github.com/facebook/pyrefly/issues/1274
            merged, from_attributes=True
        )
    return def1.model_copy(update={"signatures": signatures})


def _collect_dynamic_definition_names(definitions: Sequence["TopLevelDefinition"]) -> set[str]:
    """Return the set of top-level definitions that have `dynamic_name=True`.

    Used by the load-time validator to forbid macros that reference dynamic definitions.
    """
    dynamic_names: set[str] = set()
    for definition in definitions:
        if getattr(definition, "dynamic_name", False):
            dynamic_names.add(definition.name)
    return dynamic_names


def _macro_subjects_for_definition(definition: "TopLevelDefinition") -> set[str]:
    """Collect every macro subject referenced anywhere inside a top-level definition.

    Includes the top-level definition's own signatures and, for class definitions, the
    signatures of nested method / field / export defs. Macro subjects are dotted
    accessor paths (`Parent.fields.foo`); we keep just the root identifier here since
    that is what the dynamic-name forbid rule cares about.
    """
    subjects: set[str] = set()

    def _add_from(defn: Definition) -> None:
        for signature in defn.signatures:
            for macro in signature.get_macro_definitions():
                root, _, _ = macro.subject.partition(".")
                subjects.add(root)

    _add_from(definition)
    if isinstance(definition, ClassDefinition):
        for nested in (*definition.methods, *definition.fields, *definition.exports):
            _add_from(nested)
    return subjects


def validate_definitions(definitions: Sequence["TopLevelDefinition"]) -> None:
    """Cross-definition validation that runs after merge_definitions_groups.

    Raises sigmatcher.errors.MacroPointsToDynamicError if any definition's signatures
    reference a dynamic definition via a macro — see decision #4 in the redesign.
    """
    # Local import to avoid a hard cycle (errors imports MacroStatement only behind
    # TYPE_CHECKING, so the runtime cycle is one-way: definitions -> errors).
    from sigmatcher.errors import MacroPointsToDynamicError  # noqa: PLC0415

    dynamic_names = _collect_dynamic_definition_names(definitions)
    if not dynamic_names:
        return
    for definition in definitions:
        for subject in _macro_subjects_for_definition(definition):
            if subject in dynamic_names:
                raise MacroPointsToDynamicError(definition.name, subject)


def merge_definitions_groups(definition_groups: Sequence[Sequence[TDefinition]]) -> tuple[TDefinition, ...]:
    """
    Merge multiple definition groups into a single group,
    e.g. merge all the methods and fields of 2 class definitions with the same name.
    When a definition is present in multiple groups, the signatures are taken from the last group.
    """
    final_definitions: dict[str, TDefinition] = {}
    for definition_group in definition_groups:
        for definition in definition_group:
            if definition.name in final_definitions:
                final_definitions[definition.name] = merge_definition(final_definitions[definition.name], definition)
            else:
                final_definitions[definition.name] = definition
    return tuple(final_definitions.values())
