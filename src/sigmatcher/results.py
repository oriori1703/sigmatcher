import sys
from pathlib import Path
from typing import TypeAlias

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

import pydantic


class Export(pydantic.BaseModel, frozen=True):
    name: str
    value: str


class MatchedExport(pydantic.BaseModel, frozen=True):
    new: Export

    @classmethod
    def from_value(cls, name: str, value: str) -> "MatchedExport":
        return cls(new=Export(name=name, value=value))


class Field(pydantic.BaseModel, frozen=True):
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


class MatchedField(pydantic.BaseModel, frozen=True):
    original: Field
    new: Field


class Method(pydantic.BaseModel, frozen=True):
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


class MatchedMethod(pydantic.BaseModel, frozen=True):
    original: Method
    new: Method


class Class(pydantic.BaseModel, frozen=True):
    name: str
    package: str

    @classmethod
    def from_full_name(cls, full_name: str) -> "Class":
        package, _, name = full_name.rpartition(".")
        return cls(name=name, package=package)

    def to_full_name(self) -> str:
        return f"{self.package}.{self.name}"

    @property
    def full_name(self) -> str:
        return self.to_full_name()

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Class":
        package, _, name = java_representation[1:-1].replace("/", ".").rpartition(".")
        return cls(name=name, package=package)

    def to_java_representation(self) -> str:
        return f"L{self.to_full_name()};".replace(".", "/")

    @property
    def java(self) -> str:
        return self.to_java_representation()


class MatchedClass(pydantic.BaseModel):
    original: Class
    new: Class
    matched_methods: list[MatchedMethod]
    matched_fields: list[MatchedField]
    exports: list[MatchedExport]
    smali_file: Path | None = None

    @override
    def __hash__(self) -> int:
        return hash((self.original, self.new))


Result: TypeAlias = MatchedClass | MatchedField | MatchedMethod | MatchedExport
RESULTS_TYPE_ADAPTER = pydantic.TypeAdapter(list[Result])
