"""Extended tests for FileCrawler covering walk, batch processing, and nav extraction."""

import os
import stat
import pytest
from unittest.mock import patch, MagicMock

from sonar_catalog.config import CrawlerConfig, MetadataConfig, DatabaseConfig
from sonar_catalog.database import CatalogDB
from sonar_catalog.crawler import (
    FileCrawler, detect_sonar_format, get_file_type, get_mime_type_magic,
)
from sonar_catalog.mount_resolver import MountResolver, MountEntry


@pytest.fixture
def crawler_setup(tmp_path):
    """Set up a crawler with temp DB and test files."""
    db_path = str(tmp_path / "test.db")
    db_config = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
    db = CatalogDB(db_config)
    db.initialize()

    crawler_config = CrawlerConfig(
        hash_algorithm="sha256",
        partial_hash_size=64,
        hash_workers=1,
        batch_size=5,
        incremental=False,
    )
    meta_config = MetadataConfig(
        use_file_command=False,
        use_magic=False,
    )
    resolver = MountResolver()
    resolver._loaded = True

    crawler = FileCrawler(db, crawler_config, meta_config, resolver)
    return crawler, db, tmp_path


def _create_test_files(base_dir, count=5, ext=".xtf"):
    """Create test files in a directory."""
    paths = []
    for i in range(count):
        f = base_dir / f"file_{i:03d}{ext}"
        # Write XTF-like header for format detection
        if ext == ".xtf":
            f.write_bytes(b"\x01\x00" + b"x" * 100)
        elif ext == ".jsf":
            f.write_bytes(b"\x16\x16" + b"j" * 100)
        else:
            f.write_bytes(b"generic content " * 10)
        paths.append(str(f))
    return paths


class TestDetectSonarFormat:
    def test_detect_xtf_magic(self, tmp_path):
        f = tmp_path / "test.xtf"
        f.write_bytes(b"\x01\x00" + b"\x00" * 100)
        fmt = detect_sonar_format(str(f), ".xtf")
        assert fmt == "xtf"

    def test_detect_jsf_magic(self, tmp_path):
        f = tmp_path / "test.jsf"
        f.write_bytes(b"\x16\x16" + b"\x00" * 100)
        fmt = detect_sonar_format(str(f), ".jsf")
        assert fmt == "jsf"

    def test_detect_by_extension(self, tmp_path):
        f = tmp_path / "test.bag"
        f.write_bytes(b"\x00\x00\x00\x00" * 10)
        fmt = detect_sonar_format(str(f), ".bag")
        assert fmt == "bag"

    def test_detect_unknown(self, tmp_path):
        f = tmp_path / "test.xyz"
        f.write_bytes(b"\x00\x00\x00\x00" * 10)
        fmt = detect_sonar_format(str(f), ".nope")
        assert fmt is None

    def test_detect_unreadable_file(self):
        fmt = detect_sonar_format("/nonexistent/path/file.xtf", ".xtf")
        # Should fall back to extension
        assert fmt == "xtf"

    def test_detect_with_custom_magic(self, tmp_path):
        f = tmp_path / "test.custom"
        f.write_bytes(b"\xCA\xFE\xBA\xBE" + b"\x00" * 100)
        custom_magic = [
            {"format": "custom_sonar", "hex_bytes": "cafebabe",
             "byte_length": 4, "offset": 0}
        ]
        fmt = detect_sonar_format(str(f), ".custom", custom_magic=custom_magic)
        assert fmt == "custom_sonar"

    def test_detect_with_custom_ext_map(self, tmp_path):
        f = tmp_path / "test.myformat"
        f.write_bytes(b"\x00" * 100)
        custom_ext = {".myformat": "my_sonar"}
        fmt = detect_sonar_format(str(f), ".myformat", custom_ext_map=custom_ext)
        assert fmt == "my_sonar"


class TestGetFileType:
    def test_regular_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        result = get_file_type(str(f))
        assert result is not None
        assert "text" in result

    def test_nonexistent_file(self):
        result = get_file_type("/nonexistent/file")
        # file command may still return something or None
        assert isinstance(result, (str, type(None)))


class TestGetMimeTypeMagic:
    def test_magic_available_or_not(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = get_mime_type_magic(str(f))
        # Either returns MIME type or None if python-magic not installed
        assert result is None or isinstance(result, str)


class TestWalkFilesystem:
    def test_basic_walk(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        test_dir = tmp_path / "walk_test"
        test_dir.mkdir()
        _create_test_files(test_dir, count=3)

        entries = list(crawler._walk_filesystem(str(test_dir)))
        assert len(entries) == 3
        for entry in entries:
            assert "path" in entry
            assert "name" in entry
            assert "size" in entry
            assert "mtime" in entry
            assert "extension" in entry

    def test_walk_excludes_dirs(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        test_dir = tmp_path / "walk_excl"
        test_dir.mkdir()
        (test_dir / "good").mkdir()
        (test_dir / ".git").mkdir()

        (test_dir / "good" / "file.txt").write_text("good")
        (test_dir / ".git" / "file.txt").write_text("excluded")

        entries = list(crawler._walk_filesystem(str(test_dir)))
        assert len(entries) == 1
        assert "good" in entries[0]["path"]

    def test_walk_excludes_extensions(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        test_dir = tmp_path / "walk_ext"
        test_dir.mkdir()

        (test_dir / "keep.xtf").write_bytes(b"data")
        (test_dir / "skip.tmp").write_bytes(b"temp")

        entries = list(crawler._walk_filesystem(str(test_dir)))
        names = [e["name"] for e in entries]
        assert "keep.xtf" in names
        assert "skip.tmp" not in names

    def test_walk_min_size_filter(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        crawler.config.min_file_size = 50
        test_dir = tmp_path / "walk_size"
        test_dir.mkdir()

        (test_dir / "small.txt").write_bytes(b"x")
        (test_dir / "big.txt").write_bytes(b"x" * 100)

        entries = list(crawler._walk_filesystem(str(test_dir)))
        assert len(entries) == 1
        assert entries[0]["name"] == "big.txt"

    def test_walk_max_size_filter(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        crawler.config.max_file_size = 50
        test_dir = tmp_path / "walk_maxsz"
        test_dir.mkdir()

        (test_dir / "small.txt").write_bytes(b"x" * 10)
        (test_dir / "big.txt").write_bytes(b"x" * 100)

        entries = list(crawler._walk_filesystem(str(test_dir)))
        assert len(entries) == 1
        assert entries[0]["name"] == "small.txt"

    def test_walk_include_extensions(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        crawler.config.include_extensions = [".xtf", ".jsf"]
        test_dir = tmp_path / "walk_incl"
        test_dir.mkdir()

        (test_dir / "wanted.xtf").write_bytes(b"\x01\x00" + b"d" * 10)
        (test_dir / "also.jsf").write_bytes(b"\x16\x16" + b"d" * 10)
        (test_dir / "nope.csv").write_bytes(b"data")

        entries = list(crawler._walk_filesystem(str(test_dir)))
        names = [e["name"] for e in entries]
        assert "wanted.xtf" in names
        assert "also.jsf" in names
        assert "nope.csv" not in names


class TestCrawlLocal:
    def test_crawl_local_basic(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        test_dir = tmp_path / "crawl_test"
        test_dir.mkdir()
        _create_test_files(test_dir, count=3)

        stats = crawler.crawl_local(
            str(test_dir), hostname="testhost",
            ip_address="127.0.0.1", access_hostname="testhost",
        )
        assert stats["files_found"] == 3
        assert stats["files_new"] == 3
        assert stats["files_error"] == 0

        # Verify data in DB
        results = db.search_files(limit=100)
        assert len(results) == 3

    def test_crawl_nonexistent_path(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        stats = crawler.crawl_local(
            "/nonexistent/path", hostname="test",
        )
        assert "error" in stats

    def test_crawl_with_progress(self, crawler_setup):
        crawler, db, tmp_path = crawler_setup
        test_dir = tmp_path / "crawl_prog"
        test_dir.mkdir()
        _create_test_files(test_dir, count=2)

        progress_calls = []
        stats = crawler.crawl_local(
            str(test_dir), hostname="test",
            progress_callback=lambda s: progress_calls.append(s.copy()),
        )
        assert stats["files_found"] == 2


class TestDownsampleTrack:
    def test_no_downsample_needed(self):
        track = [[1.0, 2.0], [3.0, 4.0]]
        result = FileCrawler._downsample_track(track, 10)
        assert result == track

    def test_downsample(self):
        track = [[float(i), float(i)] for i in range(100)]
        result = FileCrawler._downsample_track(track, 10)
        assert len(result) <= 11  # may have a couple extra due to rounding
        assert result[0] == track[0]  # first preserved
        assert result[-1] == track[-1]  # last preserved

    def test_downsample_to_2(self):
        track = [[float(i), float(i)] for i in range(50)]
        result = FileCrawler._downsample_track(track, 2)
        assert len(result) == 2
        assert result[0] == track[0]
        assert result[-1] == track[-1]
