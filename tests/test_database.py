"""Tests for database module."""

import json

from sonar_catalog.database import CatalogDB
from sonar_catalog.search import CatalogSearch


class TestCatalogDB:
    """Test database operations with canonical location model."""

    def test_insert_and_query_file(self, tmp_db):
        tmp_db.insert_file(
            content_hash="hash_001",
            file_size=1024,
            partial_hash="partial_001",
            sonar_format="xtf",
        )
        assert tmp_db.file_exists("hash_001")
        assert not tmp_db.file_exists("nonexistent")

    def test_insert_location_canonical_dedup(self, tmp_db):
        """Inserting same canonical_path twice should upsert, not duplicate."""
        tmp_db.insert_file(content_hash="h1", file_size=100, partial_hash="p1")
        tmp_db.insert_location(
            content_hash="h1",
            nfs_server="server-01",
            nfs_export="/export/data",
            remote_path="file.xtf",
            canonical_path="server-01:/export/data/file.xtf",
            is_local=False,
            access_path="/mnt/s01/file.xtf",
            access_hostname="ws-01",
            mount_source="proc_mounts",
            file_name="file.xtf",
            directory="/export/data",
        )
        # Same canonical, different access info
        tmp_db.insert_location(
            content_hash="h1",
            nfs_server="server-01",
            nfs_export="/export/data",
            remote_path="file.xtf",
            canonical_path="server-01:/export/data/file.xtf",
            is_local=False,
            access_path="/auto/nfs/s01/file.xtf",
            access_hostname="ws-02",
            mount_source="autofs_map",
            file_name="file.xtf",
            directory="/export/data",
        )
        locs = tmp_db.get_locations_for_hash("h1")
        assert len(locs) == 1
        assert locs[0]["access_hostname"] == "ws-02"

    def test_batch_insert(self, tmp_db):
        files = [
            {"content_hash": "b1", "file_size": 10, "partial_hash": "p1"},
            {"content_hash": "b2", "file_size": 20, "partial_hash": "p2"},
        ]
        locs = [
            {
                "content_hash": "b1",
                "nfs_server": "s1",
                "nfs_export": "/exp",
                "remote_path": "a.dat",
                "canonical_path": "s1:/exp/a.dat",
                "is_local": False,
                "access_path": "/mnt/a.dat",
                "access_hostname": "ws",
                "file_name": "a.dat",
                "directory": "/exp",
            },
            {
                "content_hash": "b2",
                "nfs_server": "s1",
                "nfs_export": "/exp",
                "remote_path": "b.dat",
                "canonical_path": "s1:/exp/b.dat",
                "is_local": False,
                "access_path": "/mnt/b.dat",
                "access_hostname": "ws",
                "file_name": "b.dat",
                "directory": "/exp",
            },
        ]
        tmp_db.insert_files_batch(files)
        tmp_db.insert_locations_batch(locs)
        assert tmp_db.file_exists("b1")
        assert tmp_db.file_exists("b2")

    def test_find_duplicates(self, tmp_db):
        """File with locations on 2 servers should appear as duplicate."""
        tmp_db.insert_file(content_hash="dup1", file_size=5000, partial_hash="dp1")
        tmp_db.insert_location(
            content_hash="dup1", nfs_server="srv-a", nfs_export="/a",
            remote_path="f.dat", canonical_path="srv-a:/a/f.dat",
            is_local=False, access_path="/mnt/a/f.dat", access_hostname="ws",
            mount_source="test", file_name="f.dat", directory="/a",
        )
        tmp_db.insert_location(
            content_hash="dup1", nfs_server="srv-b", nfs_export="/b",
            remote_path="f.dat", canonical_path="srv-b:/b/f.dat",
            is_local=False, access_path="/mnt/b/f.dat", access_hostname="ws",
            mount_source="test", file_name="f.dat", directory="/b",
        )
        dupes = tmp_db.find_duplicates(min_count=2)
        assert len(dupes) == 1
        assert dupes[0]["server_count"] == 2

    def test_get_stats(self, tmp_db):
        tmp_db.insert_file(content_hash="s1", file_size=100, partial_hash="sp1")
        tmp_db.insert_location(
            content_hash="s1", nfs_server="srv", nfs_export="/e",
            remote_path="x.dat", canonical_path="srv:/e/x.dat",
            is_local=False, access_path="/mnt/x.dat", access_hostname="ws",
            mount_source="test", file_name="x.dat", directory="/e",
        )
        stats = tmp_db.get_stats()
        assert stats["unique_files"] == 1
        assert stats["total_locations"] == 1
        assert stats["nfs_locations"] == 1
        assert stats["local_locations"] == 0

    def test_search_by_server(self, tmp_db):
        tmp_db.insert_file(content_hash="sf1", file_size=42, partial_hash="sfp1")
        tmp_db.insert_location(
            content_hash="sf1", nfs_server="my-server", nfs_export="/data",
            remote_path="test.xtf", canonical_path="my-server:/data/test.xtf",
            is_local=False, access_path="/mnt/test.xtf", access_hostname="ws",
            mount_source="test", file_name="test.xtf", directory="/data",
        )
        results = tmp_db.search_files(nfs_server="my-server")
        assert len(results) == 1
        assert results[0]["nfs_server"] == "my-server"

    def test_known_fingerprints(self, tmp_db):
        tmp_db.insert_file(content_hash="fp1", file_size=999, partial_hash="abc")
        fps = tmp_db.get_known_fingerprints()
        assert "999:abc" in fps

    def test_scan_tracking(self, tmp_db):
        scan_id = tmp_db.start_scan("host1", "/data")
        assert isinstance(scan_id, int)
        tmp_db.update_scan(scan_id, status="complete", files_found=42)

    def test_upsert_host(self, tmp_db):
        tmp_db.upsert_host("10.0.0.1", hostname="srv1", ssh_accessible=True)
        tmp_db.upsert_host("10.0.0.1", hostname="srv1-updated")
        # Should not raise, hostname updated
