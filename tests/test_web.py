"""Tests for the Flask web API."""

import json
import pytest

pytest.importorskip("flask")

from sonar_catalog.web import create_app
from sonar_catalog.config import Config, DatabaseConfig


@pytest.fixture
def app(tmp_path):
    """Create a test Flask app with a temp SQLite database."""
    db_path = str(tmp_path / "test.db")
    config = Config()
    config.database = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
    app = create_app(config)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def seeded_client(app):
    """Client with test data inserted."""
    get_db = app.config["GET_DB"]
    with get_db() as db:
        db.insert_files_batch([
            {"content_hash": "h1", "file_size": 5000, "partial_hash": "p1", "sonar_format": "xtf"},
            {"content_hash": "h2", "file_size": 200000, "partial_hash": "p2", "sonar_format": "jsf"},
        ])
        db.insert_locations_batch([
            {
                "content_hash": "h1", "nfs_server": "server-01",
                "nfs_export": "/export/survey", "remote_path": "2024/line001.xtf",
                "canonical_path": "server-01:/export/survey/2024/line001.xtf",
                "is_local": False, "access_path": "/auto/nfs/s01/2024/line001.xtf",
                "access_hostname": "ws-01", "file_name": "line001.xtf",
                "directory": "/export/survey/2024", "sonar_format": "xtf",
            },
            {
                "content_hash": "h2", "nfs_server": "server-02",
                "nfs_export": "/data/sidescan", "remote_path": "track_A.jsf",
                "canonical_path": "server-02:/data/sidescan/track_A.jsf",
                "is_local": False, "access_path": "/mnt/s02/track_A.jsf",
                "access_hostname": "ws-01", "file_name": "track_A.jsf",
                "directory": "/data/sidescan", "sonar_format": "jsf",
            },
        ])
    return app.test_client()


class TestWebAPI:
    def test_index_page(self, client):
        """Root should return the HTML page."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Sonar Catalog" in resp.data

    def test_search_empty(self, client):
        """Search with no data should return empty list."""
        resp = client.get("/api/search?q=test")
        assert resp.status_code == 200
        assert resp.json == []

    def test_search_with_data(self, seeded_client):
        """Search should return matching results."""
        resp = seeded_client.get("/api/search?q=line001")
        assert resp.status_code == 200
        data = resp.json
        assert len(data) == 1
        assert data[0]["file_name"] == "line001.xtf"

    def test_search_by_server_filter(self, seeded_client):
        """Server filter should narrow results."""
        resp = seeded_client.get("/api/search?q=server&server=server-01")
        assert resp.status_code == 200
        data = resp.json
        assert len(data) == 1
        assert data[0]["nfs_server"] == "server-01"

    def test_file_detail(self, seeded_client):
        """File detail endpoint should return file + locations."""
        resp = seeded_client.get("/api/files/h1")
        assert resp.status_code == 200
        data = resp.json
        assert data["file"]["content_hash"] == "h1"
        assert len(data["locations"]) >= 1

    def test_file_detail_not_found(self, seeded_client):
        """Non-existent hash should return 404."""
        resp = seeded_client.get("/api/files/nonexistent")
        assert resp.status_code == 404

    def test_duplicates_empty(self, client):
        """No duplicates when no data."""
        resp = client.get("/api/duplicates")
        assert resp.status_code == 200
        assert resp.json == []

    def test_stats(self, seeded_client):
        """Stats endpoint should return catalog statistics."""
        resp = seeded_client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json
        assert data["unique_files"] == 2
        assert data["total_locations"] == 2

    def test_hosts_empty(self, client):
        """Hosts should return empty list when no hosts discovered."""
        resp = client.get("/api/hosts")
        assert resp.status_code == 200
        assert resp.json == []

    def test_servers(self, seeded_client):
        """Servers endpoint should list distinct servers."""
        resp = seeded_client.get("/api/servers")
        assert resp.status_code == 200
        data = resp.json
        assert "server-01" in data
        assert "server-02" in data

    def test_formats(self, seeded_client):
        """Formats endpoint should list distinct sonar formats."""
        resp = seeded_client.get("/api/formats")
        assert resp.status_code == 200
        data = resp.json
        assert "xtf" in data
        assert "jsf" in data
