from pathlib import Path
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
    smali_file: Path | None = pydantic.Field(default=None, exclude=True)


Result: TypeAlias = MatchedClass | MatchedField | MatchedMethod | MatchedExport
