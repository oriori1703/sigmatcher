import dataclasses
from pathlib import Path
from typing import List, Union

from typing_extensions import TypeAlias


@dataclasses.dataclass
class Field:
    name: str
    type: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Field":
        name, _, field_type = java_representation.partition(":")
        return cls(name, field_type)

    def to_java_representation(self) -> str:
        return f"{self.name}:{self.type}"

    @property
    def java(self) -> str:
        return self.to_java_representation()


@dataclasses.dataclass
class MatchedField:
    original: Field
    new: Field


@dataclasses.dataclass
class Method:
    name: str
    argument_types: str
    return_type: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Method":
        name, _, types = java_representation.partition("(")
        argument_types, _, return_type = types.partition(")")
        return cls(name, argument_types, return_type)

    def to_java_representation(self) -> str:
        return f"{self.name}({self.argument_types}){self.return_type}"

    @property
    def java(self) -> str:
        return self.to_java_representation()


@dataclasses.dataclass
class MatchedMethod:
    original: Method
    new: Method


@dataclasses.dataclass
class Class:
    name: str
    pacakge: str

    @classmethod
    def from_java_representation(cls, java_representation: str) -> "Class":
        package, _, name = java_representation[1:-1].replace("/", ".").rpartition(".")
        return cls(name, package)

    def to_java_representation(self) -> str:
        return f"L{self.pacakge}.{self.name};".replace(".", "/")

    @property
    def java(self) -> str:
        return self.to_java_representation()


@dataclasses.dataclass
class MatchedClass:
    original: Class
    new: Class
    smali_file: Path
    matched_methods: List[MatchedMethod]
    matched_fields: List[MatchedField]


Result: TypeAlias = Union[MatchedClass, MatchedField, MatchedMethod]
