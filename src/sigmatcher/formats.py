import enum
import json
import sys
from abc import ABC, abstractmethod
from io import StringIO
from typing import ClassVar, Literal

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

import pydantic
import pydantic.alias_generators

from sigmatcher.results import Class, Field, MatchedClass, MatchedField, MatchedMethod, Method


class Formatter(ABC):
    @abstractmethod
    def convert(self, matched_classes: dict[str, MatchedClass]) -> str:
        raise NotImplementedError()


class Parser(ABC):
    @abstractmethod
    def parse(self, raw_input: str) -> dict[str, MatchedClass]:
        raise NotImplementedError()


class RawFormatter(Formatter):
    @override
    def convert(self, matched_classes: dict[str, MatchedClass]) -> str:
        return pydantic.RootModel[dict[str, MatchedClass]](matched_classes).model_dump_json(indent=4)


class RawParser(Parser):
    @override
    def parse(self, raw_input: str) -> dict[str, MatchedClass]:
        return pydantic.RootModel[dict[str, MatchedClass]].model_validate_json(raw_input).root


class LegacyFormatter(Formatter):
    @override
    def convert(self, matched_classes: dict[str, MatchedClass]) -> str:
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
        _ = result.write(f"CLASS {new_class} {original_class}\n")
        for field in matched_class.matched_fields:
            _ = result.write(self.convert_field(field))
        for method in matched_class.matched_methods:
            _ = result.write(self.convert_method(method))
        return result.getvalue()

    @override
    def convert(self, matched_classes: dict[str, MatchedClass]) -> str:
        final = StringIO()
        for matched_class in matched_classes.values():
            _ = final.write(self.convert_class(matched_class))
        return final.getvalue()


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

    @override
    def parse(self, raw_input: str) -> dict[str, MatchedClass]:
        result: dict[str, MatchedClass] = {}
        matched_class: MatchedClass | None = None
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
    ref_type: Literal["CLASS", "FIELD", "METHOD"]
    decl_class: str
    short_id: str | None = None

    model_config: ClassVar[pydantic.ConfigDict] = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel, validate_by_name=True
    )


class JadxRename(pydantic.BaseModel):
    new_name: str
    node_ref: JadxNodeRef

    model_config: ClassVar[pydantic.ConfigDict] = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel, validate_by_name=True
    )


class JadxCodeData(pydantic.BaseModel):
    renames: list[JadxRename]

    model_config: ClassVar[pydantic.ConfigDict] = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel, validate_by_name=True
    )


class JadxProjectFile(pydantic.BaseModel):
    code_data: JadxCodeData

    model_config: ClassVar[pydantic.ConfigDict] = pydantic.ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel, validate_by_name=True
    )


class JadxFormatter(Formatter):
    @override
    def convert(self, matched_classes: dict[str, MatchedClass]) -> str:
        jadx_project = JadxProjectFile(code_data=JadxCodeData(renames=[]))
        for matched_class in matched_classes.values():
            class_node_ref = JadxNodeRef(ref_type="CLASS", decl_class=matched_class.new.to_full_name())
            class_rename = JadxRename(new_name=matched_class.original.to_full_name(), node_ref=class_node_ref)
            jadx_project.code_data.renames.append(class_rename)
            for matched_field in matched_class.matched_fields:
                field_node_ref = JadxNodeRef(
                    ref_type="FIELD",
                    decl_class=matched_class.new.to_full_name(),
                    short_id=matched_field.new.to_java_representation(),
                )
                field_rename = JadxRename(new_name=matched_field.original.name, node_ref=field_node_ref)
                jadx_project.code_data.renames.append(field_rename)
            for method in matched_class.matched_methods:
                method_node_ref = JadxNodeRef(
                    ref_type="METHOD",
                    decl_class=matched_class.new.to_full_name(),
                    short_id=method.new.to_java_representation(),
                )
                method_rename = JadxRename(new_name=method.original.name, node_ref=method_node_ref)
                jadx_project.code_data.renames.append(method_rename)
        return jadx_project.model_dump_json(indent=4, exclude_unset=True)


class JadxParser(Parser):
    def _parse_class(self, jadx_rename: JadxRename) -> MatchedClass:
        return MatchedClass(
            new=Class.from_full_name(jadx_rename.node_ref.decl_class),
            original=Class.from_full_name(jadx_rename.new_name),
            matched_methods=[],
            matched_fields=[],
        )

    def _parse_holder_class(self, decl_class: str) -> MatchedClass:
        clazz = Class.from_full_name(decl_class)
        return MatchedClass(new=clazz, original=clazz, matched_methods=[], matched_fields=[])

    def _parse_fields(
        self,
        result: dict[str, MatchedClass],
        jadx_to_sigma_classes: dict[str, MatchedClass],
        jadx_to_sigma_field: list[tuple[str, MatchedField]],
    ) -> None:
        for decl_class, matched_field in jadx_to_sigma_field:
            matched_class = jadx_to_sigma_classes.get(decl_class)
            if matched_class is None:
                matched_class = self._parse_holder_class(decl_class)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[decl_class] = matched_class
            matched_class.matched_fields.append(matched_field)

    def _parse_field(self, jadx_rename: JadxRename) -> tuple[str, MatchedField]:
        assert jadx_rename.node_ref.short_id is not None
        new_field = Field.from_java_representation(jadx_rename.node_ref.short_id)
        original_field = Field(name=jadx_rename.new_name, type="")
        return (jadx_rename.node_ref.decl_class, MatchedField(new=new_field, original=original_field))

    def _parse_methods(
        self,
        result: dict[str, MatchedClass],
        jadx_to_sigma_classes: dict[str, MatchedClass],
        jadx_to_sigma_method: list[tuple[str, MatchedMethod]],
    ) -> None:
        for decl_class, matched_method in jadx_to_sigma_method:
            matched_class = jadx_to_sigma_classes.get(decl_class)
            if matched_class is None:
                matched_class = self._parse_holder_class(decl_class)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[decl_class] = matched_class
            matched_class.matched_methods.append(matched_method)

    def _parse_method(self, jadx_rename: JadxRename) -> tuple[str, MatchedMethod]:
        assert jadx_rename.node_ref.short_id is not None
        new_method = Method.from_java_representation(jadx_rename.node_ref.short_id)
        original_method = Method(name=jadx_rename.new_name, argument_types="", return_type="")
        return (jadx_rename.node_ref.decl_class, MatchedMethod(new=new_method, original=original_method))

    @override
    def parse(self, raw_input: str) -> dict[str, MatchedClass]:
        result: dict[str, MatchedClass] = {}
        jadx_project = JadxProjectFile.model_validate_json(raw_input)

        jadx_to_sigma_classes: dict[str, MatchedClass] = {}
        jadx_to_sigma_field: list[tuple[str, MatchedField]] = []
        jadx_to_sigma_method: list[tuple[str, MatchedMethod]] = []

        for rename in jadx_project.code_data.renames:
            if rename.node_ref.ref_type == "CLASS":
                matched_class = self._parse_class(rename)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[rename.node_ref.decl_class] = matched_class
            elif rename.node_ref.ref_type == "FIELD":
                jadx_to_sigma_field.append(self._parse_field(rename))
            elif rename.node_ref.ref_type == "METHOD":
                jadx_to_sigma_method.append(self._parse_method(rename))

        self._parse_fields(result, jadx_to_sigma_classes, jadx_to_sigma_field)
        self._parse_methods(result, jadx_to_sigma_classes, jadx_to_sigma_method)
        return result


class MappingFormat(str, enum.Enum):
    RAW = "raw"
    ENIGMA = "enigma"
    JADX = "jadx"
    LEGACY = "legacy"


FORMAT_TO_FORMATTER: dict[MappingFormat, Formatter] = {
    MappingFormat.RAW: RawFormatter(),
    MappingFormat.ENIGMA: EnigmaFormatter(),
    MappingFormat.JADX: JadxFormatter(),
    MappingFormat.LEGACY: LegacyFormatter(),
}


def convert_to_format(matched_classes: dict[str, MatchedClass], output_format: MappingFormat) -> str:
    try:
        return FORMAT_TO_FORMATTER[output_format].convert(matched_classes)
    except KeyError:
        raise ValueError(
            f"The provided output format is not supported yet: {output_format}."
            + f"Supported formats are: {', '.join(FORMAT_TO_FORMATTER)}"
        ) from None


FORMAT_TO_PARSER: dict[MappingFormat, Parser] = {
    MappingFormat.RAW: RawParser(),
    MappingFormat.ENIGMA: EnigmaParser(),
    MappingFormat.JADX: JadxParser(),
}


def parse_from_format(raw_input: str, input_format: MappingFormat) -> dict[str, MatchedClass]:
    try:
        return FORMAT_TO_PARSER[input_format].parse(raw_input)
    except KeyError:
        raise ValueError(
            f"The provided input format is not supported yet: {input_format}."
            + f"Supported formats are: {', '.join(FORMAT_TO_PARSER)}"
        ) from None
