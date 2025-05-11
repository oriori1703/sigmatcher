import fnmatch
import re
import sys
from abc import ABC, abstractmethod
from functools import cached_property
from pathlib import Path
from typing import ClassVar, Dict, List, Optional, Sequence, Set, Tuple, TypeVar, Union

if sys.version_info < (3, 9):
    from typing_extensions import Annotated
else:
    from typing import Annotated

if sys.version_info < (3, 10):
    from typing_extensions import Literal, TypeAlias
else:
    from typing import Literal, TypeAlias

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

import pydantic
from packaging.specifiers import SpecifierSet

from sigmatcher.grep import rip_regex
from sigmatcher.results import Result


class InvalidMacroModifierError(Exception):
    """
    Exception raised when an invalid macro modifier is encountered.
    """

    def __init__(self, modifier: str, class_name: str) -> None:
        self.modifier = modifier
        self.class_name = class_name
        super().__init__(f"Invalid macro modifier: '{modifier}' for class '{class_name}'")


def is_in_version_range(app_version: Optional[str], version_range: Union[str, List[str], None]) -> bool:
    if app_version is None or version_range is None:
        return True
    ranges = version_range if isinstance(version_range, list) else [version_range]
    return any(SpecifierSet(spec).contains(app_version) for spec in ranges)


class BaseSignature(ABC, pydantic.BaseModel, frozen=True, use_attribute_docstrings=True):
    version_range: Union[str, List[str], None] = None
    """The version range in which the signature is valid."""
    count: int = 1
    """The number of times the signature should match in order to be considered a match."""

    @abstractmethod
    def check_files(self, search_pathes: List[Path]) -> List[Path]:
        raise NotImplementedError()

    @abstractmethod
    def check_strings(self, strings: List[str]) -> List[str]:
        raise NotImplementedError()

    @abstractmethod
    def capture(self, value: str) -> Set[str]:
        raise NotImplementedError()

    @abstractmethod
    def get_dependencies(self) -> List[str]:
        raise NotImplementedError()

    def resolve_macro(
        self, results: Dict[str, Union[Result, Exception]], result_identifier: str, result_modifier: str
    ) -> str:
        result = results[result_identifier]
        assert not isinstance(result, Exception)

        try:
            resolved_macro = getattr(result.new, result_modifier)
        except AttributeError:
            raise InvalidMacroModifierError(result_modifier, result.new.__class__.__name__) from None

        assert isinstance(resolved_macro, str)
        return resolved_macro

    @abstractmethod
    def resolve_macros(self, results: Dict[str, Union[Result, Exception]]) -> Self:
        raise NotImplementedError()

    def is_in_version_range(self, app_version: Optional[str]) -> bool:
        return is_in_version_range(app_version, self.version_range)


class BaseRegexSignature(BaseSignature, pydantic.BaseModel, frozen=True):
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

    def check_files(self, search_pathes: List[Path]) -> List[Path]:
        return [
            path.resolve()
            for path, match_count in rip_regex(self.signature, search_pathes).items()
            if self.count in (match_count, 0)
        ]

    def check_strings(self, strings: List[str]) -> List[str]:
        results: List[str] = []
        for string in strings:
            match_count = len(self.signature.findall(string))
            if match_count == 0:
                continue
            if self.count in (match_count, 0):
                results.append(string)
        return results

    def capture(self, value: str) -> Set[str]:
        match = self.signature.search(value)
        if match is None:
            return set()
        try:
            return {match.group("match")}
        except IndexError:
            pass

        return set(match.groups())

    def get_dependencies(self) -> List[str]:
        return [macro.rpartition(".")[0] for macro in self._get_raw_macros]

    @cached_property
    def _get_raw_macros(self) -> Set[str]:
        return set(self.MACRO_REGEX.findall(self.signature.pattern))

    def resolve_macros(self, results: Dict[str, Union[Result, Exception]]) -> Self:
        if not self._get_raw_macros:
            return self

        new_pattern = self.signature.pattern
        for macro in self._get_raw_macros:
            result_identifier, _, result_modifier = macro.rpartition(".")
            resolved_macro = self.resolve_macro(results, result_identifier, result_modifier)
            new_pattern = new_pattern.replace(f"${{{macro}}}", re.escape(resolved_macro))

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


class TreeSitterSignature(BaseSignature, pydantic.BaseModel, frozen=True):
    signature: str
    """A TreeSitter s-query used to check the signature."""
    type: Literal["treesitter"] = "treesitter"
    """The type of the signature."""

    def check_files(self, search_pathes: List[Path]) -> List[Path]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def check_strings(self, strings: List[str]) -> List[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def capture(self, value: str) -> Set[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def get_dependencies(self) -> List[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def resolve_macros(self, results: Dict[str, Union[Result, Exception]]) -> Self:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")


Signature: TypeAlias = Annotated[
    Union[RegexSignature, GlobSignature, TreeSitterSignature], pydantic.Field(discriminator="type")
]


class Definition(pydantic.BaseModel, frozen=True, use_attribute_docstrings=True):
    name: str
    """The name of the definition, i.e. the class, method, field, or export name."""
    signatures: Tuple[Signature, ...]
    """A list of signatures that define the definition."""
    version_range: Union[str, List[str], None] = None
    """The version range in which the definition is valid."""

    def get_signatures_for_version(self, app_version: Optional[str]) -> Tuple[Signature, ...]:
        if app_version is None:
            return self.signatures
        return tuple(signature for signature in self.signatures if signature.is_in_version_range(app_version))

    def get_dependencies(self, app_version: Optional[str]) -> Set[str]:
        dependencies: Set[str] = set()
        for signature in self.get_signatures_for_version(app_version):
            dependencies.update(signature.get_dependencies())
        return dependencies

    def is_in_version_range(self, app_version: Optional[str]) -> bool:
        return is_in_version_range(app_version, self.version_range)


class ExportDefinition(Definition, frozen=True):
    pass


class FieldDefinition(Definition, frozen=True):
    pass


class MethodDefinition(Definition, frozen=True):
    pass


class ClassDefinition(Definition, frozen=True):
    package: Optional[str] = None
    """The package of the class."""
    fields: Tuple[FieldDefinition, ...] = ()
    """A list of field definitions."""
    methods: Tuple[MethodDefinition, ...] = ()
    """A list of method definitions."""
    exports: Tuple[ExportDefinition, ...] = ()
    """A list of export definitions."""


DEFINITIONS_TYPE_ADAPTER = pydantic.TypeAdapter(List[ClassDefinition])


TDefinition = TypeVar("TDefinition", bound=Definition)


def merge_definition(def1: TDefinition, def2: TDefinition) -> TDefinition:
    signatures = def2.signatures if def2.signatures else def1.signatures

    if isinstance(def1, ClassDefinition):
        assert isinstance(def2, ClassDefinition)
        fields_to_update = {
            "signatures": signatures,
            "methods": merge_definitions_groups([def1.methods, def2.methods]),
            "fields": merge_definitions_groups([def1.fields, def2.fields]),
            "exports": merge_definitions_groups([def1.exports, def2.exports]),
        }
    else:
        fields_to_update = {"signatures": signatures}

    return def1.model_copy(update=fields_to_update)


def merge_definitions_groups(definition_groups: Sequence[Sequence[TDefinition]]) -> Tuple[TDefinition, ...]:
    """
    Merge multiple definition groups into a single group,
    e.g. merge all the methods and fields of 2 class definitions with the same name.
    When a definition is present in multiple groups, the signatures are taken from the last group.
    """
    final_definitions: Dict[str, TDefinition] = {}
    for definition_group in definition_groups:
        for definition in definition_group:
            if definition.name in final_definitions:
                definition = merge_definition(final_definitions[definition.name], definition)
            final_definitions[definition.name] = definition
    return tuple(final_definitions.values())
