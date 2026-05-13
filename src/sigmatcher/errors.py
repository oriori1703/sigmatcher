import sys
from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

if TYPE_CHECKING:
    from sigmatcher.definitions import MacroStatement, Signature

SignatureMatch = TypeVar("SignatureMatch", str, Path)


class SigmatcherError(Exception):
    def __init__(self, analyzer_name: str, *args: object) -> None:
        self.analyzer_name: str = analyzer_name
        super().__init__(analyzer_name, *args)

    def debug_message(self) -> str:
        return ""

    def short_message(self) -> str:
        return str(self)


class SignaturesCountError(SigmatcherError):
    pass


class NoSignaturesError(SignaturesCountError):
    @override
    def short_message(self) -> str:
        return "Found no signatures! Make sure your version ranges are correct"


class TooManySignaturesError(SignaturesCountError):
    def __init__(self, analyzer_name: str, signatures: "tuple[Signature, ...]", *args: object) -> None:
        self.signatures: tuple[Signature, ...] = signatures
        super().__init__(analyzer_name, signatures, *args)

    @override
    def short_message(self) -> str:
        return f"Found {len(self.signatures)} signatures. Field definitions should only have one"


class MatchError(SigmatcherError):
    def __init__(self, analyzer_name: str, signatures: "tuple[Signature,...] | None", *args: object) -> None:
        self.signatures: tuple[Signature, ...] | None = signatures
        super().__init__(analyzer_name, signatures, *args)

    @override
    def debug_message(self) -> str:
        if self.signatures is None:
            return ""

        signature_message = "\n ".join(
            signature.model_dump_json(exclude_defaults=True) for signature in self.signatures
        )
        return f"- Signatures:\n {signature_message}"


class NoMatchesError(MatchError):
    @override
    def short_message(self) -> str:
        return "Found no matches!"


class TooManyMatchesError(MatchError, Generic[SignatureMatch]):
    def __init__(
        self,
        analyzer_name: str,
        signatures: "tuple[Signature,...] | None",
        matches: "set[SignatureMatch]",
        *args: object,
    ) -> None:
        self.matches: set[SignatureMatch] = matches
        super().__init__(analyzer_name, signatures, matches, *args)

    @override
    def debug_message(self) -> str:
        matches_message = "\n ".join(str(match) for match in self.matches)
        return f"{super().debug_message()}\n- Matches:\n {matches_message}"

    @override
    def short_message(self) -> str:
        return "Found too many matches"


class DependencyError(SigmatcherError):
    def __init__(self, analyzer_name: str, failed_dependencies: list[str], *args: object) -> None:
        self.failed_dependencies: list[str] = failed_dependencies
        super().__init__(analyzer_name, failed_dependencies, *args)

    @override
    def debug_message(self) -> str:
        dependencies_message = "\n ".join(self.failed_dependencies)
        return f"- Dependencies: \n{dependencies_message}"


class MissingDependenciesError(DependencyError):
    @override
    def short_message(self) -> str:
        return "Skipped because of missing dependencies. Make sure you included all of the signature files"


class FailedDependencyError(DependencyError):
    def __init__(self, analyzer_name: str, failed_dependencies: list[str], *args: object) -> None:
        self.failed_dependencies: list[str] = failed_dependencies
        self.should_show_debug: bool = True
        super().__init__(analyzer_name, failed_dependencies, *args)

    @override
    def debug_message(self) -> str:
        if not self.should_show_debug:
            return ""
        return super().debug_message()

    @override
    def short_message(self) -> str:
        return "Skipped because of failed dependencies"


class DuplicateCapturedNameError(SigmatcherError):
    """
    Raised when emitting an output format and two different definitions produce
    MatchedClass entries with the same readable `original.name`.

    Output keys (raw/enigma/legacy/jadx) are derived from `original.name`, so a
    collision would silently overwrite one of the entries. The redesign locks this
    as a hard error (decision #9) so authors disambiguate explicitly.
    """

    def __init__(self, captured_name: str, first_analyzer: str, second_analyzer: str, *args: object) -> None:
        self.captured_name: str = captured_name
        self.first_analyzer: str = first_analyzer
        self.second_analyzer: str = second_analyzer
        super().__init__(first_analyzer, captured_name, second_analyzer, *args)

    @override
    def short_message(self) -> str:
        return (
            f"Two definitions captured the same readable name {self.captured_name!r}: "
            f"{self.first_analyzer!r} and {self.second_analyzer!r}. Tighten one of the "
            "signatures so the captures disambiguate."
        )


class MacroPointsToDynamicError(SigmatcherError):
    """
    Raised at signature-file load time when a macro `${X.<property>}` references a
    definition `X` whose `dynamic_name` flag is set.

    Dynamic definitions emit 0+ matches per run, so a macro that needs a single concrete
    value (`X.java`, `X.full_name`, etc.) cannot be resolved unambiguously. This is a
    hard error, not a per-analyzer failure, so authors see the problem at load time
    instead of after analysis runs.
    """

    def __init__(self, analyzer_name: str, dynamic_dependency: str, *args: object) -> None:
        self.dynamic_dependency: str = dynamic_dependency
        super().__init__(analyzer_name, dynamic_dependency, *args)

    @override
    def short_message(self) -> str:
        return (
            f"Definition {self.analyzer_name!r} references dynamic definition "
            f"{self.dynamic_dependency!r} via a macro, which is not allowed: dynamic "
            "definitions emit 0+ matches and cannot be macro-resolved to a single value."
        )


class MissingDynamicCaptureGroupError(SigmatcherError):
    """
    Raised when a definition has dynamic_name=True but none of the signatures
    applicable to the current app version carries the axis-specific named group
    (`class_name`, `method_name`, `field_name`, `export_name`) used to capture the
    readable name.

    This can happen even when the model-level validator passed, because the
    validator inspects all signatures while the analyzer iterates only the
    version-filtered subset.
    """

    def __init__(
        self, analyzer_name: str, app_version: str | None, axis_label: str, capture_group_name: str, *args: object
    ) -> None:
        self.app_version: str | None = app_version
        self.axis_label: str = axis_label
        self.capture_group_name: str = capture_group_name
        super().__init__(analyzer_name, app_version, axis_label, capture_group_name, *args)

    @override
    def short_message(self) -> str:
        return (
            f"Definition {self.analyzer_name!r} has dynamic_name=True but no signature "
            f"applicable to app version {self.app_version!r} contains a "
            f"(?P<{self.capture_group_name}>...) named group. Add a {self.capture_group_name} "
            f"capture to a {self.axis_label} signature whose version_range covers this version."
        )


class ChildFailedForParentError(SigmatcherError):
    """
    Raised when a child analyzer (method/field/export) fails for one specific
    parent class match among the N parents produced by a dynamic class def.

    The all-or-nothing rule (decision #6) treats a single per-parent failure as a
    failure of the whole child analyzer — every successful per-parent match is
    discarded. This error wraps the underlying SigmatcherError so callers see
    *which* parent caused the failure rather than a bare child-analyzer name.
    """

    def __init__(
        self,
        analyzer_name: str,
        parent_class_java: str,
        underlying_error: SigmatcherError,
        *args: object,
    ) -> None:
        self.parent_class_java: str = parent_class_java
        self.underlying_error: SigmatcherError = underlying_error
        super().__init__(analyzer_name, parent_class_java, underlying_error, *args)

    @override
    def short_message(self) -> str:
        return f"Failed for parent class {self.parent_class_java!r}: {self.underlying_error.short_message()}"

    @override
    def debug_message(self) -> str:
        underlying_debug = self.underlying_error.debug_message()
        prefix = f"Parent class: {self.parent_class_java}"
        if not underlying_debug:
            return prefix
        return f"{prefix}\n{underlying_debug}"


class UnexpectedMultiResultMacroError(SigmatcherError):
    """
    Raised when a macro tries to resolve against a result list that does not contain
    exactly one entry.

    Under normal operation the load-time `validate_definitions` pass forbids macros
    pointing at dynamic definitions, so every macro subject resolves to a singleton
    list. This error guards the programmatic API path (`sigmatcher.analysis.analyze`
    called directly without the CLI's `_read_definitions` wrapper), where the
    upstream validator was previously skipped — callers would otherwise crash with
    a bare `AssertionError` instead of a `SigmatcherError`.
    """

    def __init__(self, analyzer_name: str, macro_subject: str, result_count: int, *args: object) -> None:
        self.macro_subject: str = macro_subject
        self.result_count: int = result_count
        super().__init__(analyzer_name, macro_subject, result_count, *args)

    @override
    def short_message(self) -> str:
        return (
            f"Macro subject {self.macro_subject!r} resolved to {self.result_count} matches, "
            "expected exactly one. Macros against dynamic definitions are forbidden — "
            "make sure validate_definitions has been called on this definition set."
        )


class DuplicateTopLevelDefinitionError(SigmatcherError):
    """
    Raised when two signature files declare a top-level definition with the same
    `(kind, name)`. Class definitions are merged by `merge_definitions_groups`, but
    top-level method/field/export defs are not, so a duplicate would silently overwrite
    the first. Surface this as a hard load-time error instead.
    """

    def __init__(self, definition_name: str, definition_kind: str, *args: object) -> None:
        self.definition_kind: str = definition_kind
        super().__init__(definition_name, definition_kind, *args)

    @override
    def short_message(self) -> str:
        return (
            f"Duplicate top-level {self.definition_kind} definition {self.analyzer_name!r} found "
            "across signature files. Top-level method/field/export definitions are not merged — "
            "rename one or move them into the same file with merge-friendly semantics."
        )


class InvalidMacroModifierError(SigmatcherError):
    """
    Exception raised when an invalid macro modifier is encountered.
    """

    def __init__(self, analyzer_name: str, macro: "MacroStatement", result_class_name: str, *args: object) -> None:
        self.macro: MacroStatement = macro
        self.result_class_name: str = result_class_name
        super().__init__(analyzer_name, macro, result_class_name, *args)

    @override
    def debug_message(self) -> str:
        return (
            f"Macro Subject: {self.macro.subject}\nMacro Modifier: {self.macro.modifier}\n"
            + f"Subject Class: {self.result_class_name}"
        )

    @override
    def short_message(self) -> str:
        return "Invalid macro modifier"
