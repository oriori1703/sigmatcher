import enum
import json
from abc import ABC, abstractmethod
from io import StringIO
from typing import Dict, Optional, Type

import pydantic

from sigmatcher.results import Class, Field, MatchedClass, MatchedField, MatchedMethod, Method


class MappingFormat(str, enum.Enum):
    RAW = "raw"
    ENIGMA = "enigma"
    LEGACY = "legacy"


class Formatter(ABC):
    @abstractmethod
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        raise NotImplementedError()


class RawFormatter(Formatter):
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        return pydantic.RootModel[Dict[str, MatchedClass]](matched_classes).model_dump_json(indent=4)


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


FORMAT_TO_FORMATTER: Dict[MappingFormat, Type[Formatter]] = {
    MappingFormat.RAW: RawFormatter,
    MappingFormat.ENIGMA: EnigmaFormatter,
    MappingFormat.LEGACY: LegacyFormatter,
}


def convert_to_format(matched_classes: Dict[str, MatchedClass], output_format: MappingFormat) -> str:
    return FORMAT_TO_FORMATTER[output_format]().convert(matched_classes)


class Parser(ABC):
    @abstractmethod
    def parse(self, raw_input: str) -> Dict[str, MatchedClass]:
        raise NotImplementedError()


class RawParser(Parser):
    def parse(self, raw_input: str) -> Dict[str, MatchedClass]:
        return pydantic.RootModel[Dict[str, MatchedClass]].model_validate_json(raw_input).root


class EnigmaParser(Parser):
    def _parse_class(self, components: list[str]) -> MatchedClass:
        new_class = Class.from_java_representation(f"L{components[1]};")
        original_class = Class.from_java_representation(f"L{components[-1]};")
        return MatchedClass(new=new_class, original=original_class, matched_methods=[], matched_fields=[])

    def _parse_field(self, components: list[str]) -> MatchedField:
        new_field = Field(name=components[1], type=components[-1])
        original_field = Field(name=components[-2], type="")
        return MatchedField(new=new_field, original=original_field)

    def _parse_method(self, components: list[str]) -> MatchedMethod:
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


FORMAT_TO_PARSER: Dict[MappingFormat, Type[Parser]] = {
    MappingFormat.RAW: RawParser,
    MappingFormat.ENIGMA: EnigmaParser,
}


def parse_from_format(raw_input: str, input_format: MappingFormat) -> Dict[str, MatchedClass]:
    try:
        return FORMAT_TO_PARSER[input_format]().parse(raw_input)
    except KeyError:
        raise ValueError(
            f"The rovided input format is not supported yet: {input_format}."
            f"Supported formats are: {', '.join(FORMAT_TO_PARSER)}"
        ) from None
