import enum
import json
from abc import ABC, abstractmethod
from io import StringIO
from typing import Dict, List, Literal, Optional, Tuple, Type

import pydantic
import pydantic.alias_generators

from sigmatcher.results import Class, Field, MatchedClass, MatchedField, MatchedMethod, Method


class Formatter(ABC):
    @abstractmethod
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        raise NotImplementedError()


class Parser(ABC):
    @abstractmethod
    def parse(self, raw_input: str) -> Dict[str, MatchedClass]:
        raise NotImplementedError()


class RawFormatter(Formatter):
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        return pydantic.RootModel[Dict[str, MatchedClass]](matched_classes).model_dump_json(indent=4)


class RawParser(Parser):
    def parse(self, raw_input: str) -> Dict[str, MatchedClass]:
        return pydantic.RootModel[Dict[str, MatchedClass]].model_validate_json(raw_input).root


class LegacyFormatter(Formatter):
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        return json.dumps(
            {
                matched_class.original.name: {
                    "className": f"{matched_class.new.package}.{matched_class.new.name}",
                    "methods": {method.original.name: method.new.name for method in matched_class.matched_methods},
                    "fields": {field.original.name: field.new.name for field in matched_class.matched_fields},
                }
                for matched_class in matched_classes.values()
            },
            indent=4,
            sort_keys=True,
        )


class EnigmaFormatter(Formatter):
    def convert_field(self, field: MatchedField) -> str:
        return f"\tFIELD {field.new.name} {field.original.name} {field.new.type}\n"

    def convert_method(self, method: MatchedMethod) -> str:
        return (
            f"\tMETHOD {method.new.name} {method.original.name} ({method.new.argument_types}){method.new.return_type}\n"
        )

    def convert_class(self, matched_class: MatchedClass) -> str:
        result = StringIO()
        new_class = matched_class.new.to_java_representation()[1:-1]
        original_class = matched_class.original.to_java_representation()[1:-1]
        result.write(f"CLASS {new_class} {original_class}\n")
        for field in matched_class.matched_fields:
            result.write(self.convert_field(field))
        for method in matched_class.matched_methods:
            result.write(self.convert_method(method))
        return result.getvalue()

    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        final = StringIO()
        for matched_class in matched_classes.values():
            final.write(self.convert_class(matched_class))
        return final.getvalue()


class EnigmaParser(Parser):
    def _parse_class(self, components: List[str]) -> MatchedClass:
        new_class = Class.from_java_representation(f"L{components[1]};")
        original_class = Class.from_java_representation(f"L{components[-1]};")
        return MatchedClass(new=new_class, original=original_class, matched_methods=[], matched_fields=[])

    def _parse_field(self, components: List[str]) -> MatchedField:
        new_field = Field(name=components[1], type=components[-1])
        original_field = Field(name=components[-2], type="")
        return MatchedField(new=new_field, original=original_field)

    def _parse_method(self, components: List[str]) -> MatchedMethod:
        method_types = components[-1]
        argument_type, return_type = method_types[1:].split(")")

        new_method = Method(name=components[1], argument_types=argument_type, return_type=return_type)
        original_method = Method(name=components[-2], argument_types="", return_type="")
        return MatchedMethod(new=new_method, original=original_method)

    def parse(self, raw_input: str) -> Dict[str, MatchedClass]:
        result: Dict[str, MatchedClass] = {}
        matched_class: Optional[MatchedClass] = None
        current_class = ""
        for line in raw_input.splitlines():
            components = line.split()
            if components[0] == "CLASS":
                matched_class = self._parse_class(components)
                current_class = matched_class.original.name
                result[current_class] = matched_class

            elif components[0] == "FIELD":
                result[current_class].matched_fields.append(self._parse_field(components))

            elif components[0] == "METHOD":
                result[current_class].matched_methods.append(self._parse_method(components))

        return result


class JadxNodeRef(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(alias_generator=pydantic.alias_generators.to_camel)
    ref_type: Literal["CLASS", "FIELD", "METHOD"]
    decl_class: str
    short_id: Optional[str] = None


class JadxRename(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(alias_generator=pydantic.alias_generators.to_camel)
    new_name: str
    node_ref: JadxNodeRef


class JadxParser(Parser):
    def _parse_class(self, jadx_rename: JadxRename) -> MatchedClass:
        new_package, _, new_name = jadx_rename.node_ref.decl_class.rpartition(".")
        orignal_package, _, original_name = jadx_rename.new_name.rpartition(".")
        return MatchedClass(
            new=Class(name=new_name, package=new_package),
            original=Class(name=original_name, package=orignal_package),
            matched_methods=[],
            matched_fields=[],
        )

    def _parse_holder_class(self, decl_class: str) -> MatchedClass:
        package, _, name = decl_class.rpartition(".")
        return MatchedClass(
            new=Class(name=name, package=package),
            original=Class(name=name, package=package),
            matched_methods=[],
            matched_fields=[],
        )

    def _parse_field(self, jadx_rename: JadxRename) -> Tuple[str, MatchedField]:
        assert jadx_rename.node_ref.short_id is not None
        new_field = Field.from_java_representation(jadx_rename.node_ref.short_id)
        original_field = Field(name=jadx_rename.new_name, type="")
        return (jadx_rename.node_ref.decl_class, MatchedField(new=new_field, original=original_field))

    def _parse_method(self, jadx_rename: JadxRename) -> Tuple[str, MatchedMethod]:
        assert jadx_rename.node_ref.short_id is not None
        new_method = Method.from_java_representation(jadx_rename.node_ref.short_id)
        original_method = Method(name=jadx_rename.new_name, argument_types="", return_type="")
        return (jadx_rename.node_ref.decl_class, MatchedMethod(new=new_method, original=original_method))

    def parse(self, raw_input: str) -> Dict[str, MatchedClass]:
        result: Dict[str, MatchedClass] = {}
        raw_jadx_dict = json.loads(raw_input)
        jadex_renames = pydantic.TypeAdapter(List[JadxRename]).validate_python(raw_jadx_dict["codeData"]["renames"])
        jadx_to_sigma_classes: Dict[str, MatchedClass] = {}
        jadx_to_sigma_field: List[Tuple[str, MatchedField]] = []
        jadx_to_sigma_method: List[Tuple[str, MatchedMethod]] = []

        for rename in jadex_renames:
            if rename.node_ref.ref_type == "CLASS":
                matched_class = self._parse_class(rename)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[rename.node_ref.decl_class] = matched_class
            elif rename.node_ref.ref_type == "FIELD":
                jadx_to_sigma_field.append(self._parse_field(rename))
            elif rename.node_ref.ref_type == "METHOD":
                jadx_to_sigma_method.append(self._parse_method(rename))

        for decl_class, matched_field in jadx_to_sigma_field:
            matched_class = jadx_to_sigma_classes.get(decl_class)
            if matched_class is None:
                matched_class = self._parse_holder_class(decl_class)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[decl_class] = matched_class
            matched_class.matched_fields.append(matched_field)

        for decl_class, matched_method in jadx_to_sigma_method:
            matched_class = jadx_to_sigma_classes.get(decl_class)
            if matched_class is None:
                matched_class = self._parse_holder_class(decl_class)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[decl_class] = matched_class
            matched_class.matched_methods.append(matched_method)
        return result


class MappingFormat(str, enum.Enum):
    RAW = "raw"
    ENIGMA = "enigma"
    JADX = "jadx"
    LEGACY = "legacy"


FORMAT_TO_FORMATTER: Dict[MappingFormat, Type[Formatter]] = {
    MappingFormat.RAW: RawFormatter,
    MappingFormat.ENIGMA: EnigmaFormatter,
    MappingFormat.LEGACY: LegacyFormatter,
}


def convert_to_format(matched_classes: Dict[str, MatchedClass], output_format: MappingFormat) -> str:
    return FORMAT_TO_FORMATTER[output_format]().convert(matched_classes)


FORMAT_TO_PARSER: Dict[MappingFormat, Type[Parser]] = {
    MappingFormat.RAW: RawParser,
    MappingFormat.ENIGMA: EnigmaParser,
    MappingFormat.JADX: JadxParser,
}


def parse_from_format(raw_input: str, input_format: MappingFormat) -> Dict[str, MatchedClass]:
    try:
        return FORMAT_TO_PARSER[input_format]().parse(raw_input)
    except KeyError:
        raise ValueError(
            f"The rovided input format is not supported yet: {input_format}."
            f"Supported formats are: {', '.join(FORMAT_TO_PARSER)}"
        ) from None
