"""Extended tests for MountResolver covering more parsing paths."""

import os
from unittest.mock import patch, mock_open, MagicMock

import pytest
import subprocess

from sonar_catalog.mount_resolver import MountResolver, MountEntry, CanonicalLocation


class TestMountResolverResolve:
    def test_resolve_nfs_file(self):
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry(
            local_path="/mnt/sonar01",
            remote_server="sonar-server-01",
            remote_path="/export/survey",
            fstype="nfs4",
            source="proc_mounts",
        ))

        loc = resolver.resolve("/mnt/sonar01/project/line_001.xtf")
        assert loc.nfs_server == "sonar-server-01"
        assert loc.nfs_export == "/export/survey"
        assert loc.relative_path == "project/line_001.xtf"
        assert loc.canonical_path == "sonar-server-01:/export/survey/project/line_001.xtf"
        assert loc.is_local is False
        assert loc.mount_source == "proc_mounts"

    def test_resolve_exact_mount_path(self):
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry(
            local_path="/mnt/data",
            remote_server="nas01",
            remote_path="/vol/data",
            fstype="nfs",
            source="fstab",
        ))

        loc = resolver.resolve("/mnt/data")
        assert loc.nfs_server == "nas01"
        assert loc.relative_path == ""

    def test_resolve_local_file(self):
        resolver = MountResolver()
        resolver._loaded = True
        # No NFS mounts loaded
        loc = resolver.resolve("/tmp/test.txt")
        assert loc.is_local is True
        assert loc.mount_source == "local"

    def test_resolve_longest_prefix_wins(self):
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry(
            local_path="/auto/nfs",
            remote_server="server-generic",
            remote_path="/export",
            fstype="nfs",
            source="autofs_map",
        ))
        resolver.add_mount(MountEntry(
            local_path="/auto/nfs/sonar01",
            remote_server="sonar-01",
            remote_path="/export/survey",
            fstype="nfs4",
            source="autofs_map",
        ))

        loc = resolver.resolve("/auto/nfs/sonar01/data/file.xtf")
        # Longest prefix (/auto/nfs/sonar01) should win
        assert loc.nfs_server == "sonar-01"

    def test_resolve_batch(self):
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry(
            local_path="/mnt/nfs",
            remote_server="nas",
            remote_path="/data",
            fstype="nfs",
            source="proc_mounts",
        ))
        result = resolver.resolve_batch([
            "/mnt/nfs/file1.txt",
            "/mnt/nfs/file2.txt",
            "/local/file3.txt",
        ])
        assert len(result) == 3
        assert result["/mnt/nfs/file1.txt"].is_local is False
        assert result["/local/file3.txt"].is_local is True

    def test_auto_load_on_resolve(self):
        """Resolver should auto-load if not yet loaded."""
        resolver = MountResolver()
        assert resolver._loaded is False
        # Resolve triggers load
        loc = resolver.resolve("/tmp/test.txt")
        assert resolver._loaded is True
        assert loc.is_local is True


class TestMountResolverGetMounts:
    def test_get_nfs_mounts(self):
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry("/mnt/nfs", "server", "/data", "nfs", "proc"))
        resolver.add_mount(MountEntry("/mnt/local", "", "", "ext4", "proc"))

        nfs = resolver.get_nfs_mounts()
        assert len(nfs) == 1
        assert nfs[0].fstype == "nfs"

    def test_get_all_mounts(self):
        resolver = MountResolver()
        resolver._loaded = True
        resolver.add_mount(MountEntry("/mnt/nfs", "server", "/data", "nfs", "proc"))
        resolver.add_mount(MountEntry("/mnt/local", "", "", "ext4", "proc"))

        all_mounts = resolver.get_all_mounts()
        assert len(all_mounts) == 2


class TestParseProcMounts:
    @patch("sonar_catalog.mount_resolver.Path")
    def test_parse_nfs_mount(self, mock_path_cls):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path_cls.return_value = mock_path

        proc_content = (
            "server01:/export/survey /mnt/sonar nfs4 rw,relatime 0 0\n"
            "/dev/sda1 / ext4 rw,relatime 0 0\n"
            "proc /proc proc rw 0 0\n"
            "tmpfs /tmp tmpfs rw 0 0\n"
        )

        resolver = MountResolver()
        with patch("builtins.open", mock_open(read_data=proc_content)):
            resolver._load_proc_mounts()

        nfs = [m for m in resolver._mounts if m.fstype == "nfs4"]
        assert len(nfs) == 1
        assert nfs[0].remote_server == "server01"
        assert nfs[0].remote_path == "/export/survey"
        assert nfs[0].local_path == "/mnt/sonar"

    @patch("sonar_catalog.mount_resolver.Path")
    def test_no_proc_mounts_falls_back(self, mock_path_cls):
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        mock_path_cls.return_value = mock_path

        resolver = MountResolver()
        with patch.object(resolver, '_load_mount_command') as mock_cmd:
            resolver._load_proc_mounts()
            mock_cmd.assert_called_once()


class TestParseMountCommand:
    @patch("sonar_catalog.mount_resolver.subprocess.run")
    def test_parse_nfs(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "nas01:/vol/data on /mnt/data type nfs (rw)\n"
                "/dev/disk1s1 on / type apfs (rw)\n"
            ),
        )
        resolver = MountResolver()
        resolver._load_mount_command()
        nfs = [m for m in resolver._mounts if m.fstype == "nfs"]
        assert len(nfs) == 1
        assert nfs[0].remote_server == "nas01"
        assert nfs[0].local_path == "/mnt/data"

    @patch("sonar_catalog.mount_resolver.subprocess.run")
    def test_mount_command_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        resolver = MountResolver()
        resolver._load_mount_command()
        assert len(resolver._mounts) == 0


class TestParseAutofsMaps:
    @patch("sonar_catalog.mount_resolver.Path")
    @patch("sonar_catalog.mount_resolver.subprocess.run")
    def test_automount_m(self, mock_run, mock_path_cls):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="/auto/nfs\n  sonar01  server1:/export/data\n",
        )
        resolver = MountResolver()
        resolver._load_autofs_maps()
        mounts = [m for m in resolver._mounts if m.source == "autofs_map"]
        assert len(mounts) == 1
        assert mounts[0].remote_server == "server1"

    @patch("sonar_catalog.mount_resolver.subprocess.run")
    def test_automount_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        resolver = MountResolver()
        # Should fall back to parsing map files
        with patch.object(resolver, '_parse_auto_master_for_mounts'):
            resolver._load_autofs_maps()


class TestLoadFstab:
    @patch("sonar_catalog.mount_resolver.Path")
    def test_parse_fstab(self, mock_path_cls):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path_cls.return_value = mock_path

        fstab_content = (
            "# NFS mount\n"
            "nas01:/export/data /mnt/data nfs rw,noatime 0 0\n"
            "/dev/sda1 / ext4 defaults 0 1\n"
            "\n"
        )

        resolver = MountResolver()
        with patch("builtins.open", mock_open(read_data=fstab_content)):
            resolver._load_fstab()

        nfs = [m for m in resolver._mounts if m.fstype == "nfs"]
        assert len(nfs) == 1
        assert nfs[0].remote_server == "nas01"
        assert nfs[0].source == "fstab"
