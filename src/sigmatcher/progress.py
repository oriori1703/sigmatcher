__lazy_modules__ = {"rich.progress"}

import sys

from rich.progress import Progress, TaskID

from sigmatcher.analysis import ProgressObserver

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


class RichProgressObserver(ProgressObserver):
    def __init__(self, progress: Progress) -> None:
        self.progress: Progress = progress
        self.task_id: TaskID | None = None

    @override
    def on_start(self, total_analyzers: int) -> None:
        self.task_id = self.progress.add_task("Starting analysis...", total=total_analyzers)

    @override
    def on_analyzer_start(self, analyzer_name: str) -> None:
        if self.task_id is not None:
            self.progress.update(self.task_id, description=f"Analyzing: {analyzer_name}")

    @override
    def on_analyzer_complete(self, analyzer_name: str) -> None:
        if self.task_id is not None:
            self.progress.update(self.task_id, advance=1)
