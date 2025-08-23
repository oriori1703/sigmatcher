from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from sigmatcher.definitions import Signature

SignatureMatch = TypeVar("SignatureMatch", str, Path)


class SigmatcherError(Exception):
    def __init__(self, analyzer_name: str, *args: object) -> None:
        self.analyzer_name = analyzer_name
        super().__init__(analyzer_name, *args)

    def long_message(self) -> str:
        return super().__str__()

    def short_message(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return self.long_message()


class SignaturesCountError(SigmatcherError):
    pass


class NoSignaturesError(SignaturesCountError):
    def long_message(self) -> str:
        return f"Found no signatures for {self.analyzer_name}! Make sure your version ranges are correct."

    def short_message(self) -> str:
        return "Found no signatures! Make sure your version ranges are correct."


class TooManySignaturesError(SignaturesCountError):
    def __init__(self, analyzer_name: str, signatures: "tuple[Signature, ...]", *args: object) -> None:
        self.signatures = signatures
        super().__init__(analyzer_name, signatures, *args)

    def long_message(self) -> str:
        return (
            f"Found {len(self.signatures)} signatures for {self.analyzer_name}. Field definitions should only have one."
        )

    def short_message(self) -> str:
        return f"Found {len(self.signatures)} signatures. Field definitions should only have one."


class MatchError(SigmatcherError):
    pass


class NoMatchesError(MatchError):
    pass


class TooManyMatchesError(MatchError, Generic[SignatureMatch]):
    def __init__(self, analyzer_name: str, matches: "set[SignatureMatch]", *args: object) -> None:
        self.matches: set[SignatureMatch] = matches
        super().__init__(analyzer_name, matches, *args)

    def log_message(self) -> str:
        if isinstance(next(iter(self.matches)), str):
            return f"Found too many matches for {self.analyzer_name}: {self.matches}"
        return f"Found too many matches for {self.analyzer_name}: {self.matches}"

    def short_message(self) -> str:
        return "Found too many matches"


class DependencyMatchError(SigmatcherError):
    def __init__(self, analyzer_name: str, missing_dependencies: list[str], *args: object) -> None:
        self.missing_dependencies = missing_dependencies
        super().__init__(analyzer_name, missing_dependencies, *args)

    def long_message(self) -> str:
        return f"Skipped {self.analyzer_name} because of the following dependencies failed: {self.missing_dependencies}"

    def short_message(self) -> str:
        return "Skipped because of failed dependencies"


class InvalidMacroModifierError(SigmatcherError):
    """
    Exception raised when an invalid macro modifier is encountered.
    """

    def __init__(self, analyzer_name: str, modifier: str, class_name: str, *args: object) -> None:
        self.modifier = modifier
        self.class_name = class_name
        super().__init__(analyzer_name, modifier, class_name, *args)

    def long_message(self) -> str:
        return f"Invalid macro modifier: '{self.modifier}' for class '{self.class_name}'"

    def short_message(self) -> str:
        return "Invalid macro modifier"
