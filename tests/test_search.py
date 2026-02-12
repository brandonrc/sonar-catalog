"""Tests for the CatalogSearch class."""

import json
import pytest

from sonar_catalog.search import CatalogSearch, format_size
from sonar_catalog.demo import load_demo_data


@pytest.fixture
def populated_db(tmp_db):
    """A tmp_db populated with demo data."""
    load_demo_data(tmp_db, num_files=30, seed=42)
    return tmp_db


class TestFormatSize:
    def test_zero(self):
        assert format_size(0) == "0 B"

    def test_bytes(self):
        assert format_size(500) == "500.0 B"

    def test_kilobytes(self):
        assert format_size(1024) == "1.0 KB"

    def test_megabytes(self):
        assert format_size(1024 * 1024) == "1.0 MB"

    def test_gigabytes(self):
        assert format_size(1024 ** 3) == "1.0 GB"

    def test_terabytes(self):
        assert format_size(1024 ** 4) == "1.0 TB"

    def test_petabytes(self):
        assert format_size(1024 ** 5) == "1.0 PB"

    def test_fractional(self):
        assert format_size(1536) == "1.5 KB"


class TestCatalogSearch:
    def test_search_table_format(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.search(output_format="table", limit=10)
        assert "NFS Server" in result
        assert "results" in result

    def test_search_json_format(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.search(output_format="json", limit=5)
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_search_paths_format(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.search(output_format="paths", limit=5)
        lines = result.strip().split("\n")
        assert len(lines) <= 5
        for line in lines:
            assert ":" in line  # canonical path has server:path

    def test_search_no_results(self, tmp_db):
        searcher = CatalogSearch(tmp_db)
        result = searcher.search(output_format="table")
        assert "No results" in result

    def test_search_by_server(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.search(nfs_server="sonar-nas", output_format="json", limit=100)
        data = json.loads(result)
        for item in data:
            assert "sonar-nas" in item["nfs_server"]

    def test_search_by_format(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.search(sonar_format="xtf", output_format="json", limit=100)
        data = json.loads(result)
        for item in data:
            assert item["sonar_format"] == "xtf"

    def test_search_by_size(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.search(
            min_size=100_000_000,
            output_format="json",
            limit=100
        )
        data = json.loads(result)
        for item in data:
            assert item["file_size"] >= 100_000_000


class TestDuplicates:
    def test_duplicates_table(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.duplicates(min_count=2, output_format="table")
        # May or may not have duplicates depending on demo data
        assert isinstance(result, str)

    def test_duplicates_json(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.duplicates(min_count=2, output_format="json")
        data = json.loads(result)
        assert isinstance(data, list)

    def test_no_duplicates(self, tmp_db):
        searcher = CatalogSearch(tmp_db)
        result = searcher.duplicates()
        assert "No duplicates" in result


class TestWhereIs:
    def test_where_is_found(self, populated_db):
        # Get a known hash
        results = populated_db.search_files(limit=1)
        assert len(results) > 0
        content_hash = results[0]["content_hash"]

        searcher = CatalogSearch(populated_db)
        result = searcher.where_is(content_hash)
        assert "Locations for" in result

    def test_where_is_not_found(self, tmp_db):
        searcher = CatalogSearch(tmp_db)
        result = searcher.where_is("nonexistent_hash_value")
        assert "No file found" in result


class TestStats:
    def test_stats_table(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.stats(output_format="table")
        assert "Sonar Catalog Statistics" in result
        assert "Unique files" in result

    def test_stats_json(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.stats(output_format="json")
        data = json.loads(result)
        assert "unique_files" in data
        assert data["unique_files"] == 30


class TestHosts:
    def test_hosts_table(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.hosts(output_format="table")
        assert "IP" in result or "No hosts" in result

    def test_hosts_json(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.hosts(output_format="json")
        data = json.loads(result)
        assert isinstance(data, list)

    def test_no_hosts(self, tmp_db):
        searcher = CatalogSearch(tmp_db)
        result = searcher.hosts(output_format="table")
        assert "No hosts" in result


class TestFormatTable:
    def test_long_path_truncated(self, populated_db):
        searcher = CatalogSearch(populated_db)
        result = searcher.search(output_format="table", limit=5)
        # Just verify it returns valid table output
        assert isinstance(result, str)
        lines = result.split("\n")
        assert len(lines) > 2  # header + separator + at least one result
