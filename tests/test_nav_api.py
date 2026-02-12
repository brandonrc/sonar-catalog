"""Tests for the geographic/navigation API endpoints."""

import pytest

pytest.importorskip("flask")

from sonar_catalog.web import create_app
from sonar_catalog.config import Config, DatabaseConfig


@pytest.fixture
def app(tmp_path):
    db_path = str(tmp_path / "test.db")
    config = Config()
    config.database = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
    app = create_app(config)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def seeded_client(app):
    """Client with test data + nav data."""
    get_db = app.config["GET_DB"]
    with get_db() as db:
        db.insert_files_batch([
            {"content_hash": "nav1", "file_size": 5000, "partial_hash": "p1",
             "sonar_format": "xtf"},
            {"content_hash": "nav2", "file_size": 8000, "partial_hash": "p2",
             "sonar_format": "jsf"},
            {"content_hash": "nonav", "file_size": 100, "partial_hash": "p3",
             "sonar_format": "csv"},
        ])
        db.insert_locations_batch([
            {
                "content_hash": "nav1", "nfs_server": "server-01",
                "nfs_export": "/data", "remote_path": "line.xtf",
                "canonical_path": "server-01:/data/line.xtf",
                "is_local": False, "access_path": "/mnt/s01/line.xtf",
                "access_hostname": "ws-01", "file_name": "line.xtf",
                "directory": "/data", "sonar_format": "xtf",
            },
            {
                "content_hash": "nav2", "nfs_server": "server-02",
                "nfs_export": "/data", "remote_path": "track.jsf",
                "canonical_path": "server-02:/data/track.jsf",
                "is_local": False, "access_path": "/mnt/s02/track.jsf",
                "access_hostname": "ws-01", "file_name": "track.jsf",
                "directory": "/data", "sonar_format": "jsf",
            },
        ])
        db.insert_nav_data_batch([
            {
                "content_hash": "nav1",
                "lat_min": 48.0, "lat_max": 48.5,
                "lon_min": 11.0, "lon_max": 11.5,
                "lat_center": 48.25, "lon_center": 11.25,
                "metadata": {
                    "track": [[48.0, 11.0], [48.25, 11.25], [48.5, 11.5]],
                    "source": "xtf_pingheader",
                    "point_count_original": 100,
                    "point_count_stored": 3,
                },
            },
            {
                "content_hash": "nav2",
                "lat_min": 34.0, "lat_max": 34.1,
                "lon_min": -118.3, "lon_max": -118.2,
                "lat_center": 34.05, "lon_center": -118.25,
                "metadata": {
                    "track": [[34.0, -118.3], [34.1, -118.2]],
                    "source": "jsf_nav",
                    "point_count_original": 50,
                    "point_count_stored": 2,
                },
            },
        ])
    return app.test_client()


class TestGeoAPI:
    def test_geo_points_all(self, seeded_client):
        resp = seeded_client.get("/api/geo/points")
        assert resp.status_code == 200
        data = resp.json
        assert len(data) == 2

    def test_geo_points_format_filter(self, seeded_client):
        resp = seeded_client.get("/api/geo/points?format=xtf")
        assert resp.status_code == 200
        data = resp.json
        assert len(data) == 1
        assert data[0]["sonar_format"] == "xtf"

    def test_geo_points_bbox_filter(self, seeded_client):
        resp = seeded_client.get("/api/geo/points?lat_min=40&lat_max=50")
        assert resp.status_code == 200
        data = resp.json
        assert len(data) == 1
        assert data[0]["content_hash"] == "nav1"

    def test_geo_track(self, seeded_client):
        resp = seeded_client.get("/api/geo/track/nav1")
        assert resp.status_code == 200
        data = resp.json
        assert len(data["track"]) == 3
        assert data["source"] == "xtf_pingheader"
        assert data["bbox"]["lat_min"] == 48.0

    def test_geo_track_not_found(self, seeded_client):
        resp = seeded_client.get("/api/geo/track/nonav")
        assert resp.status_code == 404

    def test_geo_bounds(self, seeded_client):
        resp = seeded_client.get("/api/geo/bounds")
        assert resp.status_code == 200
        data = resp.json
        assert data["lat_min"] == 34.0
        assert data["lat_max"] == 48.5
        assert data["file_count"] == 2

    def test_geo_bounds_empty(self, app):
        client = app.test_client()
        resp = client.get("/api/geo/bounds")
        assert resp.status_code == 404

    def test_globe_page(self, seeded_client):
        resp = seeded_client.get("/globe")
        assert resp.status_code == 200
        assert b"cesiumContainer" in resp.data
