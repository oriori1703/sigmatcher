import fnmatch
import re
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, ClassVar, Literal, TypeAlias, TypeVar

import pydantic
from packaging.specifiers import SpecifierSet

from sigmatcher.grep import rip_regex

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

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

    @override
    def get_dependencies(self) -> list[str]:
        return [macro.subject for macro in self.get_macro_definitions()]

    @override
    def get_macro_definitions(self) -> set[MacroStatement]:
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


class ClassDefinition(Definition, frozen=True):
    package: str | None = None
    """The package of the class."""
    fields: tuple[FieldDefinition, ...] = ()
    """A list of field definitions."""
    methods: tuple[MethodDefinition, ...] = ()
    """A list of method definitions."""
    exports: tuple[ExportDefinition, ...] = ()
    """A list of export definitions."""


DEFINITIONS_TYPE_ADAPTER = pydantic.TypeAdapter(list[ClassDefinition])


TDefinition = TypeVar("TDefinition", bound=Definition)


def merge_definition(def1: TDefinition, def2: TDefinition) -> TDefinition:
    signatures = def2.signatures if def2.signatures else def1.signatures

    if isinstance(def1, ClassDefinition):
        assert isinstance(def2, ClassDefinition)
        return (
            def1.model_copy(  # pyrefly: ignore[bad-return] related to https://github.com/facebook/pyrefly/issues/1274
                update={
                    "signatures": signatures,
                    "methods": merge_definitions_groups([def1.methods, def2.methods]),
                    "fields": merge_definitions_groups([def1.fields, def2.fields]),
                    "exports": merge_definitions_groups([def1.exports, def2.exports]),
                }
            )
        )
    return def1.model_copy(update={"signatures": signatures})


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
