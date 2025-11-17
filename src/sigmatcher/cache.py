import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

import platformdirs
from pydantic import BaseModel

from sigmatcher.definitions import Signature
from sigmatcher.results import Result

CACHE_DIR_PATH = platformdirs.user_cache_path("sigmatcher", "oriori1703", ensure_exists=True)


@dataclass
class Cache:
    cache_dir: Path

    @classmethod
    def get_from_apk(cls, apk: Path) -> Self:
        apk_hash_hex = hashlib.sha256(apk.read_bytes()).hexdigest()
        return cls(CACHE_DIR_PATH / f"{apk_hash_hex}_v2")

    def get_apktool_cache_dir(self) -> Path:
        return self.cache_dir / "apktool"

    def get_cache_file_path(self) -> Path:
        return self.cache_dir / "results_cache.json"


class ResultCache(BaseModel):
    signatures: tuple[Signature, ...]
    result: Result


ResultsCache: TypeAlias = dict[str, ResultCache]
