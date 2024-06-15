import fnmatch
import re
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, List, Optional, Set, Tuple, Union

if sys.version_info < (3, 9):
    from typing_extensions import Annotated
else:
    from typing import Annotated

if sys.version_info < (3, 10):
    from typing_extensions import Literal, TypeAlias
else:
    from typing import Literal, TypeAlias

import pydantic

from sigmatcher.grep import rip_regex


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
        return self.MACRO_REGEX.findall(self.signature.pattern)


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


class FieldDefinition(Definition, frozen=True):
    pass


class MethodDefinition(Definition, frozen=True):
    pass


class ClassDefinition(Definition, frozen=True):
    package: Optional[str] = None
    fields: Tuple[FieldDefinition, ...] = ()
    methods: Tuple[MethodDefinition, ...] = ()


class Definitions(pydantic.BaseModel, frozen=True):
    defs: Tuple[ClassDefinition, ...]
