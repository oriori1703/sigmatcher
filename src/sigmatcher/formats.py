import enum
import json
from abc import ABC, abstractmethod
from io import StringIO
from typing import Dict, Type

import pydantic

from sigmatcher.results import MatchedClass, MatchedField, MatchedMethod


class Formater(ABC):
    @abstractmethod
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        raise NotImplementedError()


class RawFormater(Formater):
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        return pydantic.RootModel[Dict[str, MatchedClass]](matched_classes).model_dump_json(indent=4)


class LegacyFormater(Formater):
    def convert(self, matched_classes: Dict[str, MatchedClass]) -> str:
        return json.dumps(
            {
                matched_class.original.name: {
                    "className": f"{matched_class.new.pacakge}.{matched_class.new.name}",
                    "methods": {method.original.name: method.new.name for method in matched_class.matched_methods},
                    "fields": {field.original.name: field.new.name for field in matched_class.matched_fields},
                }
                for matched_class in matched_classes.values()
            },
            indent=4,
            sort_keys=True,
        )


class EnigmaFormater(Formater):
    def convert_field(self, field: MatchedField) -> str:
        return f"\tFIELD {field.new.name} {field.original.name} {field.new.type}\n"

    def convert_method(self, method: MatchedMethod) -> str:
        return (
            f"\tMETHOD {method.new.name} {method.original.name} ({method.new.argument_types}){method.new.return_type}\n"
        )

    def convert_class(self, matched_class: MatchedClass) -> str:
        result = StringIO()
        result.write(
            f"CLASS {matched_class.new.to_java_representation()} {matched_class.original.to_java_representation()}\n"
        )
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


FORMAT_TO_FORMATTER: Dict[OutputFormat, Type[Formater]] = {
    OutputFormat.RAW: RawFormater,
    OutputFormat.ENIGMA: EnigmaFormater,
    OutputFormat.LEGACY: LegacyFormater,
}


def convert_to_format(matched_classes: Dict[str, MatchedClass], output_format: OutputFormat) -> str:
    return FORMAT_TO_FORMATTER[output_format]().convert(matched_classes)