import enum
import json
from abc import ABC, abstractmethod
from io import StringIO
from typing import Dict, Type

import pydantic

from sigmatcher.results import MatchedClass, MatchedField, MatchedMethod


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


class OutputFormat(str, enum.Enum):
    RAW = "raw"
    ENIGMA = "enigma"
    LEGACY = "legacy"


FORMAT_TO_FORMATTER: Dict[OutputFormat, Type[Formatter]] = {
    OutputFormat.RAW: RawFormatter,
    OutputFormat.ENIGMA: EnigmaFormatter,
    OutputFormat.LEGACY: LegacyFormatter,
}


def convert_to_format(matched_classes: Dict[str, MatchedClass], output_format: OutputFormat) -> str:
    return FORMAT_TO_FORMATTER[output_format]().convert(matched_classes)
