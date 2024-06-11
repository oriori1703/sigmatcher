import fnmatch
import re
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple, Union

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


class BaseRegexSignature(BaseSignature, pydantic.BaseModel, frozen=True):
    signature: re.Pattern[str]
    count: int = 1

    def check_directory(self, directory: Path) -> List[Path]:
        return [path for path, match_count in rip_regex(self.signature, directory).items() if match_count == self.count]

    def check_strings(self, strings: List[str]) -> List[str]:
        return [string for string in strings if len(self.signature.findall(string)) == self.count]


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


Signature: TypeAlias = Annotated[
    Union[RegexSignature, GlobSignature, TreeSitterSignature], pydantic.Field(discriminator="type")
]


class FieldDefinition(pydantic.BaseModel, frozen=True):
    name: str
    signatures: Tuple[Signature, ...]


class MethodDefinition(pydantic.BaseModel, frozen=True):
    name: str
    signatures: Tuple[Signature, ...]


class ClassDefinition(pydantic.BaseModel, frozen=True):
    name: str
    package: Optional[str] = None
    signatures: Tuple[Signature, ...]
    fields: Tuple[FieldDefinition, ...] = ()
    methods: Tuple[MethodDefinition, ...] = ()


class Definitions(pydantic.BaseModel, frozen=True):
    defs: Tuple[ClassDefinition, ...]


Definition: TypeAlias = Union[ClassDefinition, MethodDefinition, FieldDefinition]
