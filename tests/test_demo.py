"""Tests for demo/simulation data generation."""

import pytest

from sonar_catalog.config import DatabaseConfig
from sonar_catalog.database import CatalogDB
from sonar_catalog.demo import generate_demo_data, load_demo_data, _make_hash, _generate_track


class TestMakeHash:
    def test_deterministic(self):
        h1 = _make_hash("seed_1")
        h2 = _make_hash("seed_1")
        assert h1 == h2

    def test_different_seeds(self):
        h1 = _make_hash("seed_a")
        h2 = _make_hash("seed_b")
        assert h1 != h2

    def test_returns_hex_string(self):
        h = _make_hash("test")
        assert isinstance(h, str)
        assert len(h) == 64  # 32 bytes = 64 hex chars
        int(h, 16)  # should not raise


class TestGenerateTrack:
    def test_returns_list_of_points(self):
        track = _generate_track(56.0, 3.0, 2.0, num_points=50)
        assert isinstance(track, list)
        assert len(track) > 0

    def test_points_are_lat_lon_pairs(self):
        track = _generate_track(28.0, -90.0, 3.0, num_points=20)
        for point in track:
            assert len(point) == 2
            lat, lon = point
            assert isinstance(lat, float)
            assert isinstance(lon, float)

    def test_points_near_center(self):
        lat, lon, radius = 36.0, 15.0, 2.5
        track = _generate_track(lat, lon, radius, num_points=30)
        for p in track:
            assert abs(p[0] - lat) < radius * 2  # generous bounds due to jitter
            assert abs(p[1] - lon) < radius * 2


class TestGenerateDemoData:
    def test_default_generation(self):
        data = generate_demo_data(num_files=10, seed=42)
        assert "files" in data
        assert "locations" in data
        assert "nav_data" in data
        assert "hosts" in data
        assert len(data["files"]) == 10
        assert len(data["hosts"]) == 4  # default

    def test_deterministic(self):
        d1 = generate_demo_data(num_files=10, seed=42)
        d2 = generate_demo_data(num_files=10, seed=42)
        assert [f["content_hash"] for f in d1["files"]] == [f["content_hash"] for f in d2["files"]]

    def test_different_seeds_different_data(self):
        d1 = generate_demo_data(num_files=10, seed=1)
        d2 = generate_demo_data(num_files=10, seed=2)
        assert d1["files"][0]["content_hash"] != d2["files"][0]["content_hash"]

    def test_file_records_structure(self):
        data = generate_demo_data(num_files=5, seed=42)
        for f in data["files"]:
            assert "content_hash" in f
            assert "file_size" in f
            assert "partial_hash" in f
            assert "hash_algorithm" in f
            assert "sonar_format" in f
            assert f["file_size"] >= 50_000
            assert f["file_size"] <= 2_000_000_000

    def test_location_records_structure(self):
        data = generate_demo_data(num_files=5, seed=42)
        assert len(data["locations"]) >= 5  # at least 1 per file
        for loc in data["locations"]:
            assert "content_hash" in loc
            assert "nfs_server" in loc
            assert "remote_path" in loc
            assert "canonical_path" in loc
            assert "access_path" in loc
            assert "file_name" in loc

    def test_nav_data_structure(self):
        data = generate_demo_data(num_files=50, seed=42)
        # At least some files should have nav data
        assert len(data["nav_data"]) > 0
        for nav in data["nav_data"]:
            assert "content_hash" in nav
            assert "lat_min" in nav
            assert "lat_max" in nav
            assert "lon_min" in nav
            assert "lon_max" in nav
            assert "lat_center" in nav
            assert "lon_center" in nav
            assert "metadata" in nav
            assert nav["lat_min"] <= nav["lat_max"]
            assert nav["lon_min"] <= nav["lon_max"]

    def test_hosts_structure(self):
        data = generate_demo_data(num_files=5, num_hosts=3, seed=42)
        assert len(data["hosts"]) == 3
        for host in data["hosts"]:
            assert "ip_address" in host
            assert "hostname" in host
            assert "discovery_method" in host

    def test_custom_num_hosts(self):
        data = generate_demo_data(num_files=5, num_hosts=2, seed=42)
        assert len(data["hosts"]) == 2


class TestLoadDemoData:
    def test_load_into_db(self, tmp_db):
        summary = load_demo_data(tmp_db, num_files=20, seed=42)
        assert summary["files"] == 20
        assert summary["locations"] > 0
        assert summary["hosts"] > 0

        # Verify data actually in DB
        stats = tmp_db.get_stats()
        assert stats["unique_files"] == 20
        assert stats["total_locations"] > 0

    def test_nav_data_loaded(self, tmp_db):
        summary = load_demo_data(tmp_db, num_files=50, seed=42)
        assert summary["nav_tracks"] > 0

        # Verify geo data accessible
        bounds = tmp_db.get_geo_bounds()
        assert bounds is not None
        assert bounds["file_count"] > 0

    def test_searchable_after_load(self, tmp_db):
        load_demo_data(tmp_db, num_files=20, seed=42)
        results = tmp_db.search_files(limit=100)
        assert len(results) > 0
