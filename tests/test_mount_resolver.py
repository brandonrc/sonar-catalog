"""Tests for mount_resolver module."""

import socket

from sonar_catalog.mount_resolver import MountResolver, MountEntry, CanonicalLocation


class TestMountResolver:
    """Test path resolution from local paths to canonical NFS origins."""

    def test_resolve_nfs_autofs_path(self, mock_resolver):
        loc = mock_resolver.resolve("/auto/nfs/sonar01/2024/line001.xtf")
        assert loc.nfs_server == "sonar-server-01"
        assert loc.nfs_export == "/export/survey"
        assert loc.relative_path == "2024/line001.xtf"
        assert loc.canonical_path == "sonar-server-01:/export/survey/2024/line001.xtf"
        assert loc.is_local is False
        assert loc.mount_source == "autofs_map"

    def test_resolve_nfs_proc_mounts_path(self, mock_resolver):
        loc = mock_resolver.resolve("/mnt/sonar02/survey_2024/track_A.jsf")
        assert loc.nfs_server == "sonar-server-02"
        assert loc.nfs_export == "/data/sidescan"
        assert loc.canonical_path == "sonar-server-02:/data/sidescan/survey_2024/track_A.jsf"
        assert loc.mount_source == "proc_mounts"

    def test_resolve_local_path(self, mock_resolver):
        loc = mock_resolver.resolve("/tmp/local_data.dat")
        assert loc.is_local is True
        assert loc.nfs_server == socket.gethostname()
        assert loc.mount_source == "local"

    def test_resolve_batch(self, mock_resolver):
        paths = [
            "/auto/nfs/sonar01/a.xtf",
            "/mnt/sonar02/b.jsf",
            "/tmp/c.dat",
        ]
        batch = mock_resolver.resolve_batch(paths)
        assert len(batch) == 3
        assert batch[paths[0]].nfs_server == "sonar-server-01"
        assert batch[paths[1]].nfs_server == "sonar-server-02"
        assert batch[paths[2]].is_local is True

    def test_longest_prefix_match(self):
        """Longer mount path should win over shorter one."""
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry(
            local_path="/mnt/data",
            remote_server="server-a",
            remote_path="/exports/data",
            fstype="nfs",
            source="fstab",
        ))
        resolver.add_mount(MountEntry(
            local_path="/mnt/data/deep",
            remote_server="server-b",
            remote_path="/exports/deep",
            fstype="nfs",
            source="fstab",
        ))
        loc = resolver.resolve("/mnt/data/deep/file.xtf")
        assert loc.nfs_server == "server-b"

    def test_get_nfs_mounts(self, mock_resolver):
        nfs = mock_resolver.get_nfs_mounts()
        assert len(nfs) == 2
        assert all(m.fstype in ("nfs", "nfs4") for m in nfs)

    def test_add_mount_reorders(self):
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry(
            local_path="/a",
            remote_server="s1",
            remote_path="/x",
            fstype="nfs",
            source="test",
        ))
        resolver.add_mount(MountEntry(
            local_path="/a/b/c",
            remote_server="s2",
            remote_path="/y",
            fstype="nfs",
            source="test",
        ))
        # Longest path should be first after sort
        assert resolver._mounts[0].local_path == "/a/b/c"
