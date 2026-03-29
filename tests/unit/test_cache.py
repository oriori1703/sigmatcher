from pathlib import Path

from sigmatcher.cache import Cache, ResultsCacheType
from sigmatcher.results import Class, MatchedClass


def test_get_from_apk_and_cache_read_write(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _ = apk.write_bytes(b"dummy-apk-bytes")

    base_cache = tmp_path / "cache"
    base_cache.mkdir()

    cache = Cache.get_from_apk(base_cache, apk)
    assert cache.cache_dir.parent == base_cache
    assert cache.get_apktool_cache_dir() == cache.cache_dir / "apktool"

    matched = MatchedClass(
        original=Class(name="Original", package="com.example"),
        new=Class(name="New", package="com.example"),
        matched_methods=[],
        matched_fields=[],
        exports=[],
    )
    payload: ResultsCacheType = {"key": matched}

    cache.cache_dir.mkdir(parents=True)
    cache.write_results_cache(payload)

    loaded = cache.get_results_cache()
    assert loaded["key"].new.name == "New"
