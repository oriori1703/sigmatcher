import fnmatch
import re
import sys
from abc import ABC, abstractmethod
from functools import cached_property
from pathlib import Path
from typing import ClassVar, Dict, List, Optional, Set, Tuple, Union

from sigmatcher.results import Result

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

from sigmatcher.grep import rip_regex


class InvalidMacroModifierError(Exception):
    """
    Exception raised when an invalid macro modifier is encountered.
    """

    def __init__(self, modifier: str, class_name: str) -> None:
        self.modifier = modifier
        self.class_name = class_name
        super().__init__(f"Invalid macro modifier: '{modifier}' for class '{class_name}'")


class BaseSignature(ABC):
    @abstractmethod
    def check_directory(self, directory: Path) -> List[Path]:
        raise NotImplementedError()

    @abstractmethod
    def check_strings(self, strings: List[str]) -> List[str]:
        raise NotImplementedError()

    @abstractmethod
    def capture(self, value: str) -> List[str]:
        raise NotImplementedError()

    @abstractmethod
    def get_dependencies(self) -> List[str]:
        raise NotImplementedError()

    def resolve_macro(
        self, results: Dict[str, Union[Result, Exception, None]], result_identifier: str, result_modifier: str
    ) -> str:
        result = results[result_identifier]
        assert result is not None
        assert not isinstance(result, Exception)

        try:
            resolved_macro = getattr(result.new, result_modifier)
        except AttributeError:
            raise InvalidMacroModifierError(result_modifier, result.new.__class__.__name__) from None

        assert isinstance(resolved_macro, str)
        return resolved_macro

    @abstractmethod
    def resolve_macros(self, results: Dict[str, Union[Result, Exception, None]]) -> Self:
        raise NotImplementedError()


class BaseRegexSignature(BaseSignature, pydantic.BaseModel, frozen=True):
    signature: re.Pattern[str]
    count: int = 1

    MACRO_REGEX: ClassVar[re.Pattern[str]] = re.compile(r"\${(.*?)}")

    def check_directory(self, directory: Path) -> List[Path]:
        return [
            path for path, match_count in rip_regex(self.signature, directory).items() if self.count in (match_count, 0)
        ]

    def check_strings(self, strings: List[str]) -> List[str]:
        return [string for string in strings if len(self.signature.findall(string)) == self.count]

    def capture(self, value: str) -> List[str]:
        return self.signature.findall(value)

    def get_dependencies(self) -> List[str]:
        return [macro.rpartition(".")[0] for macro in self._get_raw_macros]

    @cached_property
    def _get_raw_macros(self) -> Set[str]:
        return set(self.MACRO_REGEX.findall(self.signature.pattern))

    def resolve_macros(self, results: Dict[str, Union[Result, Exception, None]]) -> Self:
        if not self._get_raw_macros:
            return self

        new_pattern = self.signature.pattern
        for macro in self._get_raw_macros:
            result_identifier, _, result_modifier = macro.rpartition(".")
            resolved_macro = self.resolve_macro(results, result_identifier, result_modifier)
            new_pattern = new_pattern.replace(f"${{{macro}}}", resolved_macro)

        return self.model_copy(update={"signature": re.compile(new_pattern)})


class RegexSignature(BaseRegexSignature, frozen=True):
    type: Literal["regex"] = "regex"


class GlobSignature(BaseRegexSignature, frozen=True):
    type: Literal["glob"] = "glob"

    @pydantic.field_validator("signature", mode="before")
    @classmethod
    def parse_glob(cls, v: str) -> str:
        # TODO: removing the atomic group, i.e. the "(?>" makes glob signature in the form of "*WORD*" slower then
        #  their regex counterparts
        return fnmatch.translate(v).replace("\\Z", "$").replace("(?>", "(?:")


class TreeSitterSignature(BaseSignature, pydantic.BaseModel, frozen=True):
    signature: str
    count: int = 1
    type: Literal["treesitter"] = "treesitter"

    def check_directory(self, directory: Path) -> List[Path]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def check_strings(self, strings: List[str]) -> List[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def capture(self, value: str) -> List[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def get_dependencies(self) -> List[str]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")

    def resolve_macros(self, results: Dict[str, Union[Result, Exception, None]]) -> Self:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")


Signature: TypeAlias = Annotated[
    Union[RegexSignature, GlobSignature, TreeSitterSignature], pydantic.Field(discriminator="type")
]


class Definition(pydantic.BaseModel, frozen=True):
    name: str
    signatures: Tuple[Signature, ...]

    def get_dependencies(self) -> Set[str]:
        dependencies: Set[str] = set()
        for signature in self.signatures:
            dependencies.update(signature.get_dependencies())
        return dependencies


class ExportDefinition(Definition, frozen=True):
    pass


class FieldDefinition(Definition, frozen=True):
    pass


class MethodDefinition(Definition, frozen=True):
    pass


class ClassDefinition(Definition, frozen=True):
    package: Optional[str] = None
    fields: Tuple[FieldDefinition, ...] = ()
    methods: Tuple[MethodDefinition, ...] = ()
    exports: Tuple[ExportDefinition, ...] = ()


class Definitions(pydantic.BaseModel, frozen=True):
    defs: Tuple[ClassDefinition, ...]
