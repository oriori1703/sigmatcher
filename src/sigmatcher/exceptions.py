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
        return "Found no signatures! Make sure your version ranges are correct."


class TooManySignaturesError(SignaturesCountError):
    def __init__(self, analyzer_name: str, signatures: "tuple[Signature, ...]", *args: object) -> None:
        self.signatures: tuple[Signature, ...] = signatures
        super().__init__(analyzer_name, signatures, *args)

    @override
    def short_message(self) -> str:
        return f"Found {len(self.signatures)} signatures. Field definitions should only have one."


class MatchError(SigmatcherError):
    def __init__(self, analyzer_name: str, signatures: "tuple[Signature,...] | None", *args: object) -> None:
        self.signatures: tuple[Signature, ...] | None = signatures
        super().__init__(analyzer_name, signatures, *args)

    @override
    def debug_message(self) -> str:
        if self.signatures is None:
            return ""

        signature_mesage = "\n ".join(signature.model_dump_json(exclude_defaults=True) for signature in self.signatures)
        return f"- Signatures:\n {signature_mesage}"


class NoMatchesError(MatchError):
    @override
    def short_message(self) -> str:
        return "Found no matches!"


class TooManyMatchesError(MatchError, Generic[SignatureMatch]):
    def __init__(
        self,
        analyzer_name: str,
        matches: "set[SignatureMatch]",
        signatures: "tuple[Signature,...] | None",
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


class DependencyMatchError(SigmatcherError):
    def __init__(self, analyzer_name: str, missing_dependencies: list[str], *args: object) -> None:
        self.missing_dependencies: list[str] = missing_dependencies
        self.should_show_debug: bool = True
        super().__init__(analyzer_name, missing_dependencies, *args)

    @override
    def short_message(self) -> str:
        return "Skipped because of failed dependencies"

    @override
    def debug_message(self) -> str:
        if not self.should_show_debug:
            return ""
        dependencies_message = "\n ".join(self.missing_dependencies)
        return f"- Dependecies: \n{dependencies_message}"


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
