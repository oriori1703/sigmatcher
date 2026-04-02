from pathlib import Path

from sigmatcher.cache import Cache, ResultsCacheType
from sigmatcher.results import Class, MatchedClass


def test_get_from_apk_and_cache_read_write(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    _ = apk.write_bytes(b"dummy-apk-bytes")

    base_cache = tmp_path / "cache"
    base_cache.mkdir()

    cache = Cache.get_from_input(base_cache, apk)
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


def test_get_from_input_directory_hash_changes_with_apk_content(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "bundle"
    nested = bundle_dir / "nested"
    nested.mkdir(parents=True)

    _ = (bundle_dir / "base.apk").write_bytes(b"base")
    split_apk = nested / "split_config.en.apk"
    _ = split_apk.write_bytes(b"split")

    base_cache = tmp_path / "cache"
    base_cache.mkdir()

    original_cache = Cache.get_from_input(base_cache, bundle_dir)
    same_cache = Cache.get_from_input(base_cache, bundle_dir)
    assert original_cache == same_cache

    _ = split_apk.write_bytes(b"split-changed")
    changed_cache = Cache.get_from_input(base_cache, bundle_dir)
    assert changed_cache.cache_dir != original_cache.cache_dir
