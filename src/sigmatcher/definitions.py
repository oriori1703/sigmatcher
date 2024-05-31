import fnmatch
import re
from pathlib import Path
from typing import List, Literal, Optional, Tuple, TypeAlias, Union

import pydantic
from typing_extensions import Annotated

from sigmatcher.analysis import rip_regex


class BaseRegexSignature(pydantic.BaseModel, frozen=True):
    signature: re.Pattern[str]
    count: int = 1

    def check(self, directory: Path) -> List[Path]:
        return [path for path, match_count in rip_regex(self.signature, directory).items() if match_count == self.count]


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


class TreeSitterSignature(pydantic.BaseModel, frozen=True):
    signature: str
    count: int = 1
    type: Literal["treesitter"] = "treesitter"

    def check(self, directory: Path) -> List[Path]:
        raise NotImplementedError("TreeSitter signatures are not supported yet.")


Signature: TypeAlias = Annotated[
    Union[RegexSignature, GlobSignature, TreeSitterSignature], pydantic.Field(discriminator="type")
]


class FieldDefinition(pydantic.BaseModel, frozen=True):
    name: str
    signatures: Tuple[Signature]


class MethodDefinition(pydantic.BaseModel, frozen=True):
    name: str
    signatures: Tuple[Signature]


class ClassDefinition(pydantic.BaseModel, frozen=True):
    name: str
    package: Optional[str] = None
    signatures: Tuple[Signature]
    fields: Optional[FieldDefinition] = None
    methods: Optional[MethodDefinition] = None


class Definitions(pydantic.BaseModel, frozen=True):
    defs: Tuple[ClassDefinition]
