from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from sigmatcher.definitions import Signature

SignatureMatch = TypeVar("SignatureMatch", str, Path)


class SigmatcherError(Exception):
    def __init__(self, analyzer_name: str, *args: object) -> None:
        self.analyzer_name = analyzer_name
        super().__init__(analyzer_name, *args)

    def debug_message(self) -> str:
        return ""

    def short_message(self) -> str:
        return str(self)


class SignaturesCountError(SigmatcherError):
    pass


class NoSignaturesError(SignaturesCountError):
    def short_message(self) -> str:
        return "Found no signatures! Make sure your version ranges are correct."


class TooManySignaturesError(SignaturesCountError):
    def __init__(self, analyzer_name: str, signatures: "tuple[Signature, ...]", *args: object) -> None:
        self.signatures = signatures
        super().__init__(analyzer_name, signatures, *args)

    def short_message(self) -> str:
        return f"Found {len(self.signatures)} signatures. Field definitions should only have one."


class MatchError(SigmatcherError):
    def __init__(self, analyzer_name: str, signatures: "tuple[Signature,...] | None", *args: object) -> None:
        self.signatures = signatures
        super().__init__(analyzer_name, signatures, *args)

    def debug_message(self) -> str:
        if self.signatures is None:
            return ""

        signature_mesage = "\n ".join(signature.model_dump_json(exclude_defaults=True) for signature in self.signatures)
        return f"- Signatures:\n {signature_mesage}"


class NoMatchesError(MatchError):
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

    def debug_message(self) -> str:
        matches_message = "\n ".join(str(match) for match in self.matches)
        return f"{super().debug_message()}\n- Matches:\n {matches_message}"

    def short_message(self) -> str:
        return "Found too many matches"


class DependencyMatchError(SigmatcherError):
    def __init__(self, analyzer_name: str, missing_dependencies: list[str], *args: object) -> None:
        self.missing_dependencies = missing_dependencies
        self.should_show_debug = True
        super().__init__(analyzer_name, missing_dependencies, *args)

    def short_message(self) -> str:
        return "Skipped because of failed dependencies"

    def debug_message(self) -> str:
        if not self.should_show_debug:
            return ""
        dependencies_message = "\n ".join(self.missing_dependencies)
        return f"- Dependecies: \n{dependencies_message}"


class InvalidMacroModifierError(SigmatcherError):
    """
    Exception raised when an invalid macro modifier is encountered.
    """

    def __init__(self, modifier: str, class_name: str, *args: object) -> None:
        self.modifier = modifier
        self.class_name = class_name
        super().__init__("TODO")  # TODO: replace with real analyzer name, after refactor

    def debug_message(self) -> str:
        return f"Macro Subject: {self.macro.subject}\nMacro Modifier: {self.macro.modifier}\nSubject Class: {self.result_class_name}"

    def short_message(self) -> str:
        return "Invalid macro modifier"
