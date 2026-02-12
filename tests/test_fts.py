"""Tests for FTS5 full-text search."""

from sonar_catalog.database import CatalogDB
from sonar_catalog.search import CatalogSearch


def _insert_test_data(db):
    """Insert sample files and locations for FTS testing."""
    files = [
        {"content_hash": "h1", "file_size": 5000, "partial_hash": "p1", "sonar_format": "xtf"},
        {"content_hash": "h2", "file_size": 200000, "partial_hash": "p2", "sonar_format": "jsf"},
        {"content_hash": "h3", "file_size": 50, "partial_hash": "p3", "sonar_format": "segy"},
    ]
    locations = [
        {
            "content_hash": "h1", "nfs_server": "sonar-server-01",
            "nfs_export": "/export/survey", "remote_path": "2024/line001.xtf",
            "canonical_path": "sonar-server-01:/export/survey/2024/line001.xtf",
            "is_local": False, "access_path": "/auto/nfs/sonar01/2024/line001.xtf",
            "access_hostname": "ws-01", "file_name": "line001.xtf",
            "directory": "/export/survey/2024", "sonar_format": "xtf",
        },
        {
            "content_hash": "h2", "nfs_server": "sonar-server-02",
            "nfs_export": "/data/sidescan", "remote_path": "track_A.jsf",
            "canonical_path": "sonar-server-02:/data/sidescan/track_A.jsf",
            "is_local": False, "access_path": "/mnt/sonar02/track_A.jsf",
            "access_hostname": "ws-01", "file_name": "track_A.jsf",
            "directory": "/data/sidescan", "sonar_format": "jsf",
        },
        {
            "content_hash": "h3", "nfs_server": "ws-01",
            "nfs_export": "", "remote_path": "/tmp/local_data.segy",
            "canonical_path": "ws-01:/tmp/local_data.segy",
            "is_local": True, "access_path": "/tmp/local_data.segy",
            "access_hostname": "ws-01", "file_name": "local_data.segy",
            "directory": "/tmp", "sonar_format": "segy",
        },
    ]
    db.insert_files_batch(files)
    db.insert_locations_batch(locations)


class TestFTS5:
    """Test FTS5 full-text search functionality."""

    def test_fts_table_created(self, tmp_db):
        """FTS virtual table should exist after init."""
        with tmp_db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='fts_locations'"
            )
            assert cur.fetchone() is not None

    def test_fts_populated_on_batch_insert(self, tmp_db):
        """FTS should have rows after insert_locations_batch."""
        _insert_test_data(tmp_db)
        with tmp_db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM fts_locations")
            assert cur.fetchone()[0] == 3

    def test_fts_search_by_filename(self, tmp_db):
        """Searching for a filename should return matching results."""
        _insert_test_data(tmp_db)
        results = tmp_db.search_files_fts("line001")
        assert len(results) == 1
        assert results[0]["file_name"] == "line001.xtf"

    def test_fts_search_by_server(self, tmp_db):
        """Searching for a server name should return its files."""
        _insert_test_data(tmp_db)
        results = tmp_db.search_files_fts("sonar-server-01")
        assert len(results) == 1
        assert results[0]["nfs_server"] == "sonar-server-01"

    def test_fts_search_by_path(self, tmp_db):
        """Searching for a directory fragment should match."""
        _insert_test_data(tmp_db)
        results = tmp_db.search_files_fts("sidescan")
        assert len(results) == 1
        assert results[0]["content_hash"] == "h2"

    def test_fts_search_by_format(self, tmp_db):
        """Searching for a sonar format should match."""
        _insert_test_data(tmp_db)
        results = tmp_db.search_files_fts("xtf")
        assert len(results) >= 1
        assert any(r["content_hash"] == "h1" for r in results)

    def test_fts_search_multiple_terms(self, tmp_db):
        """Multiple terms should narrow results (AND semantics)."""
        _insert_test_data(tmp_db)
        results = tmp_db.search_files_fts("survey line001")
        assert len(results) == 1
        assert results[0]["content_hash"] == "h1"

    def test_fts_search_no_match(self, tmp_db):
        """Non-matching query should return empty."""
        _insert_test_data(tmp_db)
        results = tmp_db.search_files_fts("nonexistent_file_xyz")
        assert len(results) == 0

    def test_fts_search_with_size_filter(self, tmp_db):
        """FTS search combined with min_size filter."""
        _insert_test_data(tmp_db)
        # h2 is 200000 bytes, should be the only one above 10000
        results = tmp_db.search_files_fts("sonar", min_size=10000)
        assert len(results) == 1
        assert results[0]["content_hash"] == "h2"

    def test_fts_search_with_server_filter(self, tmp_db):
        """FTS search combined with nfs_server filter."""
        _insert_test_data(tmp_db)
        # Search all but filter to server-01 only
        results = tmp_db.search_files_fts("sonar", nfs_server="server-01")
        assert len(results) == 1
        assert results[0]["nfs_server"] == "sonar-server-01"

    def test_rebuild_fts_index(self, tmp_db):
        """Rebuild should repopulate FTS from existing data."""
        _insert_test_data(tmp_db)

        # Clear FTS manually
        with tmp_db.get_connection() as conn:
            conn.cursor().execute("DELETE FROM fts_locations")
            conn.commit()

        # Verify FTS is empty
        results = tmp_db.search_files_fts("line001")
        assert len(results) == 0

        # Rebuild
        tmp_db.rebuild_fts_index()

        # Should find results again
        results = tmp_db.search_files_fts("line001")
        assert len(results) == 1

    def test_fts_via_catalog_search(self, tmp_db):
        """CatalogSearch.search() should use FTS on SQLite backend."""
        _insert_test_data(tmp_db)
        searcher = CatalogSearch(tmp_db)
        result = searcher.search(query="track_A", output_format="json")
        assert "track_A.jsf" in result
