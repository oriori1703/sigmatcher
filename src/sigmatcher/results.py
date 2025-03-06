import sys
from pathlib import Path
from typing import List, Union

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

import pydantic


class Export(pydantic.BaseModel):
    value: str


class MatchedExport(pydantic.BaseModel):
    new: Export

    @classmethod
    def from_value(cls, value: str) -> "MatchedExport":
        return cls(new=Export(value=value))


class Field(pydantic.BaseModel):
    name: str
    type: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Field":
        name, _, field_type = java_representation.partition(":")
        return cls(name=name, type=field_type)

    def to_java_representation(self) -> str:
        return f"{self.name}:{self.type}"

    @property
    def java(self) -> str:
        return self.to_java_representation()


class MatchedField(pydantic.BaseModel):
    original: Field
    new: Field


class Method(pydantic.BaseModel):
    name: str
    argument_types: str
    return_type: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Method":
        name, _, types = java_representation.partition("(")
        argument_types, _, return_type = types.partition(")")
        return cls(name=name, argument_types=argument_types, return_type=return_type)

    def to_java_representation(self) -> str:
        return f"{self.name}({self.argument_types}){self.return_type}"

    @property
    def java(self) -> str:
        return self.to_java_representation()


class MatchedMethod(pydantic.BaseModel):
    original: Method
    new: Method


class Class(pydantic.BaseModel):
    name: str
    package: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Class":
        package, _, name = java_representation[1:-1].replace("/", ".").rpartition(".")
        return cls(name=name, package=package)

    def to_java_representation(self) -> str:
        return f"L{self.package}.{self.name};".replace(".", "/")

    @property
    def java(self) -> str:
        return self.to_java_representation()


class MatchedClass(pydantic.BaseModel):
    original: Class
    new: Class
    smali_file: Path = pydantic.Field(..., exclude=True)
    matched_methods: List[MatchedMethod]
    matched_fields: List[MatchedField]


Result: TypeAlias = Union[MatchedClass, MatchedField, MatchedMethod, MatchedExport]
