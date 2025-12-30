import hashlib
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

import platformdirs
from pydantic import TypeAdapter

from sigmatcher.results import Result

DEFAULT_CACHE_DIR_PATH = platformdirs.user_cache_path("sigmatcher", "oriori1703", ensure_exists=True)

ResultsCacheType: TypeAlias = dict[str, Result]


@dataclass
class Cache:
    cache_dir: Path

    @classmethod
    def get_from_apk(cls, base_cache_dir: Path, apk: Path) -> Self:
        apk_hash_hex = hashlib.sha256(apk.read_bytes()).hexdigest()
        return cls(base_cache_dir / f"v2_{apk_hash_hex}")

    @classmethod
    def get_from_inputs(cls, base_cache_dir: Path, inputs: Sequence[Path]) -> Self:
        """
        Create cache from input file(s).

        For a single file: hash that file.
        For multiple files: hash the sorted list of individual hashes.
        """
        if len(inputs) == 1:
            input_hash = hashlib.sha256(inputs[0].read_bytes()).hexdigest()
        else:
            # Sort for deterministic ordering
            sorted_inputs = sorted(inputs)
            combined = b"".join(hashlib.sha256(p.read_bytes()).digest() for p in sorted_inputs)
            input_hash = hashlib.sha256(combined).hexdigest()

        return cls(base_cache_dir / f"v2_{input_hash}")

    def get_apktool_cache_dir(self) -> Path:
        return self.cache_dir / "apktool"

    def get_results_cache_path(self) -> Path:
        return self.cache_dir / "results_cache.json"

    def get_results_cache(self) -> ResultsCacheType:
        cache_path = self.get_results_cache_path()
        if not cache_path.exists():
            return {}
        raw_cache = cache_path.read_bytes()
        return TypeAdapter(ResultsCacheType).validate_json(raw_cache)

    def write_results_cache(self, results: ResultsCacheType) -> None:
        cache_path = self.get_results_cache_path()
        _ = cache_path.write_bytes(TypeAdapter(ResultsCacheType).dump_json(results))
