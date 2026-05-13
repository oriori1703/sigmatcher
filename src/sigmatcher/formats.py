import enum
import json
import sys
from abc import ABC, abstractmethod
from io import StringIO
from typing import ClassVar, Literal

import pydantic
import pydantic.alias_generators

from sigmatcher.errors import DuplicateCapturedNameError
from sigmatcher.results import (
    Class,
    Field,
    MatchedClass,
    MatchedExport,
    MatchedField,
    MatchedMethod,
    Method,
    Result,
)

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


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
        # Serialize each class on its own to exclude the smali_file field, instead of using a RootModel because of https://github.com/pydantic/pydantic/discussions/11383
        # Output keys come from the captured `original.name` (decision #9). The
        # caller (cli._output_results) builds the input dict via
        # flatten_analyzer_results which already keys by captured name.
        return json.dumps(
            {
                key: matched_class.model_dump(mode="dict", exclude={"smali_file"})
                for key, matched_class in matched_classes.items()
            },
            indent=4,
            sort_keys=True,
        )


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
                    "exports": {export.new.name: export.new.value for export in matched_class.exports},
                }
                for matched_class in matched_classes.values()
            },
            indent=4,
            sort_keys=True,
        )


class EnigmaFormatter(Formatter):
    @staticmethod
    def _convert_field(field: MatchedField) -> str:
        return f"\tFIELD {field.new.name} {field.original.name} {field.new.type}\n"

    @staticmethod
    def _convert_method(method: MatchedMethod) -> str:
        return (
            f"\tMETHOD {method.new.name} {method.original.name} ({method.new.argument_types}){method.new.return_type}\n"
        )

    def convert_class(self, matched_class: MatchedClass) -> str:
        result = StringIO()
        new_class = matched_class.new.to_java_representation()[1:-1]
        original_class = matched_class.original.to_java_representation()[1:-1]
        _ = result.write(f"CLASS {new_class} {original_class}\n")
        for field in matched_class.matched_fields:
            _ = result.write(self._convert_field(field))
        for method in matched_class.matched_methods:
            _ = result.write(self._convert_method(method))
        return result.getvalue()

    @override
    def convert(self, matched_classes: dict[str, MatchedClass]) -> str:
        final = StringIO()
        # Sort by readable `original.name` so the output is deterministic across runs
        # regardless of the analyzer dispatch order. Mirrors `RawFormatter`'s
        # sort_keys=True and `LegacyFormatter`'s ordering.
        for matched_class in sorted(matched_classes.values(), key=lambda mc: mc.original.name):
            _ = final.write(self.convert_class(matched_class))
        return final.getvalue()


class EnigmaParser(Parser):
    @staticmethod
    def _parse_class(components: list[str]) -> MatchedClass:
        new_class = Class.from_java_representation(f"L{components[1]};")
        original_class = Class.from_java_representation(f"L{components[-1]};")
        return MatchedClass(new=new_class, original=original_class, matched_methods=[], matched_fields=[], exports=[])

    @staticmethod
    def _parse_field(components: list[str]) -> MatchedField:
        new_field = Field(name=components[1], type=components[-1])
        original_field = Field(name=components[-2], type="")
        return MatchedField(new=new_field, original=original_field)

    @staticmethod
    def _parse_method(components: list[str]) -> MatchedMethod:
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
        # Sort by readable `original.name` so the output is deterministic across runs
        # regardless of the analyzer dispatch order. Mirrors `RawFormatter`'s
        # sort_keys=True and `LegacyFormatter`'s ordering.
        for matched_class in sorted(matched_classes.values(), key=lambda mc: mc.original.name):
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
    @staticmethod
    def _parse_class(jadx_rename: JadxRename) -> MatchedClass:
        return MatchedClass(
            new=Class.from_full_name(jadx_rename.node_ref.decl_class),
            original=Class.from_full_name(jadx_rename.new_name),
            matched_methods=[],
            matched_fields=[],
            exports=[],
        )

    @staticmethod
    def _parse_holder_class(decl_class: str) -> MatchedClass:
        clazz = Class.from_full_name(decl_class)
        return MatchedClass(new=clazz, original=clazz, matched_methods=[], matched_fields=[], exports=[])

    @staticmethod
    def _parse_fields(
        result: dict[str, MatchedClass],
        jadx_to_sigma_classes: dict[str, MatchedClass],
        jadx_to_sigma_field: list[tuple[str, MatchedField]],
    ) -> None:
        for decl_class, matched_field in jadx_to_sigma_field:
            matched_class = jadx_to_sigma_classes.get(decl_class)
            if matched_class is None:
                matched_class = JadxParser._parse_holder_class(decl_class)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[decl_class] = matched_class
            matched_class.matched_fields.append(matched_field)

    @staticmethod
    def _parse_field(jadx_rename: JadxRename) -> tuple[str, MatchedField]:
        assert jadx_rename.node_ref.short_id is not None
        new_field = Field.from_java_representation(jadx_rename.node_ref.short_id)
        original_field = Field(name=jadx_rename.new_name, type="")
        return (jadx_rename.node_ref.decl_class, MatchedField(new=new_field, original=original_field))

    @staticmethod
    def _parse_methods(
        result: dict[str, MatchedClass],
        jadx_to_sigma_classes: dict[str, MatchedClass],
        jadx_to_sigma_method: list[tuple[str, MatchedMethod]],
    ) -> None:
        for decl_class, matched_method in jadx_to_sigma_method:
            matched_class = jadx_to_sigma_classes.get(decl_class)
            if matched_class is None:
                matched_class = JadxParser._parse_holder_class(decl_class)
                result[matched_class.original.name] = matched_class
                jadx_to_sigma_classes[decl_class] = matched_class
            matched_class.matched_methods.append(matched_method)

    @staticmethod
    def _parse_method(jadx_rename: JadxRename) -> tuple[str, MatchedMethod]:
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


def flatten_analyzer_results(
    analyzer_results: "dict[str, list[Result]]",
    child_analyzer_names: set[str] | None = None,
) -> dict[str, MatchedClass]:
    """Flatten the per-analyzer list-of-results into the flat shape output formats use.

    - MatchedClass entries are keyed by `original.name` (the captured / static
      readable name).
    - Top-level MatchedMethod/MatchedField/MatchedExport entries (those produced by a
      top-level dynamic method/field/export analyzer) are folded into a synthesized
      holder-class entry keyed by the parent obfuscated class's readable form, so
      the format contract stays "one MatchedClass per top-level key" (decision #10).
      Nested children of a class analyzer carry the same Match* types but are
      already attached to their parent MatchedClass via the parent's
      `matched_methods` / `matched_fields` / `exports` lists — those are identified
      via the `child_analyzer_names` set (built by the orchestrator from the
      structural `Analyzer.is_child_analyzer` marker) and skipped.
    - If two analyzers produce MatchedClass entries with the same captured
      `original.name`, raise DuplicateCapturedNameError (decision #9).

    `child_analyzer_names` is optional: when None we fall back to a substring-based
    heuristic on the analyzer name. The CLI always passes the structural set; the
    heuristic exists for direct programmatic callers and legacy tests, and intentionally
    mis-handles user-authored top-level dynamic defs whose YAML name happens to contain
    `.methods.`/`.fields.`/`.exports.` (those are silently skipped) — so callers that
    care about that edge case must pass the set.
    """
    by_captured_name: dict[str, MatchedClass] = {}
    captured_name_origin: dict[str, str] = {}
    # Holder classes synthesized for top-level dynamic method/field/export results
    # are tracked separately so we can attach multiple top-level analyzers' results
    # to the same obfuscated class without re-triggering the duplicate-name check.
    holders_by_smali_java: dict[tuple[str, str], MatchedClass] = {}

    for analyzer_name, entries in analyzer_results.items():
        for entry in entries:
            if isinstance(entry, MatchedClass):
                _add_matched_class(entry, analyzer_name, by_captured_name, captured_name_origin)
            elif _is_child_analyzer_entry(analyzer_name, child_analyzer_names):
                # Nested child results are already attached to their parent MatchedClass
                # (see ChildAnalyzer._update_parent_with_child_result). Skipping them here
                # avoids duplicating them into a synthesized holder class.
                continue
            else:
                _attach_to_holder(entry, holders_by_smali_java)

    for holder in holders_by_smali_java.values():
        # Holders may share `original.name` with a captured class entry; in that case
        # we should fold the holder's child results into the existing entry rather
        # than re-keying. Decision #10 keeps the contract simple: one key per
        # readable class name.
        existing = by_captured_name.get(holder.original.name)
        if existing is None:
            by_captured_name[holder.original.name] = holder
            continue
        existing.matched_methods.extend(holder.matched_methods)
        existing.matched_fields.extend(holder.matched_fields)
        existing.exports.extend(holder.exports)

    return by_captured_name


def _add_matched_class(
    entry: MatchedClass,
    analyzer_name: str,
    by_captured_name: dict[str, MatchedClass],
    captured_name_origin: dict[str, str],
) -> None:
    captured = entry.original.name
    if captured in by_captured_name:
        # Same analyzer emitting multiple holders for the same captured name is fine
        # (e.g. a dynamic class def that matches multiple smali files but all collapse
        # to the same readable name) — that case is folded; cross-analyzer collisions
        # are the actual error.
        if captured_name_origin[captured] != analyzer_name:
            raise DuplicateCapturedNameError(captured, captured_name_origin[captured], analyzer_name)
        existing = by_captured_name[captured]
        existing.matched_methods.extend(entry.matched_methods)
        existing.matched_fields.extend(entry.matched_fields)
        existing.exports.extend(entry.exports)
        return
    by_captured_name[captured] = entry
    captured_name_origin[captured] = analyzer_name


def _is_child_analyzer_entry(analyzer_name: str, child_analyzer_names: set[str] | None) -> bool:
    """Return True if `analyzer_name` belongs to a nested child analyzer.

    Preferred path: caller passes `child_analyzer_names`, built from the structural
    `Analyzer.is_child_analyzer` marker by the orchestrator. That's an exact match —
    no false positives, no surprises for user-authored top-level dynamic defs whose
    YAML name contains `.methods.`/`.fields.`/`.exports.`.

    Fallback path: when no set is provided we substring-match the dotted name
    convention (`FieldAnalyzer.name`, `MethodAnalyzer.name`, `ExportAnalyzer.name`).
    This path exists so direct callers of `flatten_analyzer_results` (programmatic
    users, legacy tests) keep working, at the cost of mis-classifying the edge case
    above. The CLI always passes the structural set.
    """
    if child_analyzer_names is not None:
        return analyzer_name in child_analyzer_names
    return ".methods." in analyzer_name or ".fields." in analyzer_name or ".exports." in analyzer_name


def _attach_to_holder(entry: Result, holders_by_smali_java: dict[tuple[str, str], MatchedClass]) -> None:
    smali_class = getattr(entry, "smali_class", None)
    if smali_class is None:
        # Defensive: a non-MatchedClass top-level result without a smali_class has
        # nowhere to land. Skip rather than synthesize a "unknown" holder.
        return
    assert isinstance(smali_class, Class)
    # Key by (java repr, readable name) so a single smali file that yields multiple
    # readable names (e.g. a dynamic class def capturing two different names from one
    # file) ends up with one holder per distinct readable name rather than the
    # second overwriting the first.
    holder_key = (smali_class.to_java_representation(), smali_class.name)
    holder = holders_by_smali_java.get(holder_key)
    if holder is None:
        holder = MatchedClass(
            original=smali_class,
            new=smali_class,
            matched_methods=[],
            matched_fields=[],
            exports=[],
        )
        holders_by_smali_java[holder_key] = holder
    if isinstance(entry, MatchedMethod):
        holder.matched_methods.append(entry)
    elif isinstance(entry, MatchedField):
        holder.matched_fields.append(entry)
    elif isinstance(entry, MatchedExport):
        holder.exports.append(entry)


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
