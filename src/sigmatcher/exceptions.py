from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sigmatcher.definitions import Signature


class SigmatcherError(Exception):
    def __init__(self, analyzer_name: str) -> None:
        self.analyzer_name = analyzer_name

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
    def __init__(self, analyzer_name: str, signatures: "list[Signature]") -> None:
        self.signatures = signatures
        super().__init__(analyzer_name)

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


class TooManyMatchesError(MatchError):
    def __init__(self, analyzer_name: str, matches: set[str] | set[Path]) -> None:
        self.matches = matches
        super().__init__(analyzer_name)

    def log_message(self) -> str:
        return f"Found too many matches for {self.analyzer_name}: {self.matches}"

    def short_message(self) -> str:
        return "Found too many matches"


class DependencyMatchError(SigmatcherError):
    def __init__(self, analyzer_name: str, missing_dependencies: list[str]) -> None:
        self.missing_dependencies = missing_dependencies
        super().__init__(analyzer_name)

    def long_message(self) -> str:
        return f"Skipped {self.analyzer_name} because of the following dependencies failed: {self.missing_dependencies}"

    def short_message(self) -> str:
        return "Skipped because of failed dependencies"


class InvalidMacroModifierError(SigmatcherError):
    """
    Exception raised when an invalid macro modifier is encountered.
    """

    def __init__(self, modifier: str, class_name: str) -> None:
        self.modifier = modifier
        self.class_name = class_name
        super().__init__(f"Invalid macro modifier: '{modifier}' for class '{class_name}'")
