"""Tests for the host and mount discovery engine."""

import socket
from unittest.mock import patch, MagicMock
import subprocess

import pytest

from sonar_catalog.config import DiscoveryConfig
from sonar_catalog.discovery import (
    DiscoveryEngine, DiscoveredHost, MountPoint,
)


@pytest.fixture
def config():
    return DiscoveryConfig(
        ssh_user="testuser",
        ssh_timeout=1,
        use_autofs=False,
        use_ip_neigh=False,
        use_showmount=False,
        use_subnet_scan=False,
    )


@pytest.fixture
def engine(config):
    return DiscoveryEngine(config)


class TestDiscoveredHost:
    def test_defaults(self):
        h = DiscoveredHost(ip="192.168.1.1")
        assert h.hostname is None
        assert h.ssh_accessible is False
        assert h.nfs_exports == []

    def test_with_values(self):
        h = DiscoveredHost(
            ip="10.0.0.1", hostname="sonar-01",
            discovery_method="autofs", ssh_accessible=True,
        )
        assert h.hostname == "sonar-01"
        assert h.ssh_accessible is True


class TestMountPoint:
    def test_defaults(self):
        mp = MountPoint(local_path="/mnt/data")
        assert mp.remote_host is None
        assert mp.source == ""

    def test_nfs_mount(self):
        mp = MountPoint(
            local_path="/auto/nfs/sonar01",
            remote_host="sonar01",
            remote_path="/export/data",
            source="autofs",
            fstype="nfs",
        )
        assert mp.remote_host == "sonar01"


class TestParseAutomountM:
    def test_parse_basic(self, engine):
        output = """/auto/nfs
  sonar01  server1:/export/data1
  sonar02  server2:/export/data2
"""
        mounts = engine._parse_automount_m_output(output)
        assert len(mounts) == 2
        assert mounts[0].local_path == "/auto/nfs/sonar01"
        assert mounts[0].remote_host == "server1"
        assert mounts[0].remote_path == "/export/data1"

    def test_parse_mount_point_prefix(self, engine):
        output = """Mount point: /auto/sonar
  data  -fstype=nfs,rw  nas01:/export/sonar
"""
        mounts = engine._parse_automount_m_output(output)
        assert len(mounts) == 1
        assert mounts[0].local_path == "/auto/sonar/data"
        assert mounts[0].remote_host == "nas01"

    def test_parse_direct_path(self, engine):
        output = """/mnt/direct
  /mnt/direct  nas:/vol/direct
"""
        mounts = engine._parse_automount_m_output(output)
        assert len(mounts) == 1
        assert mounts[0].local_path == "/mnt/direct"

    def test_parse_empty(self, engine):
        mounts = engine._parse_automount_m_output("")
        assert mounts == []


class TestHostAllowed:
    def test_no_filters(self, engine):
        assert engine._host_allowed("192.168.1.1") is True

    def test_whitelist_match(self, config):
        config.host_whitelist = ["192.168.1.1"]
        engine = DiscoveryEngine(config)
        assert engine._host_allowed("192.168.1.1") is True
        assert engine._host_allowed("10.0.0.1") is False

    def test_whitelist_hostname_glob(self, config):
        config.host_whitelist = ["sonar-*"]
        engine = DiscoveryEngine(config)
        assert engine._host_allowed("10.0.0.1", "sonar-01") is True
        assert engine._host_allowed("10.0.0.2", "web-01") is False

    def test_blacklist(self, config):
        config.host_blacklist = ["192.168.1.99"]
        engine = DiscoveryEngine(config)
        assert engine._host_allowed("192.168.1.99") is False
        assert engine._host_allowed("192.168.1.1") is True

    def test_blacklist_hostname_glob(self, config):
        config.host_blacklist = ["bad-*"]
        engine = DiscoveryEngine(config)
        assert engine._host_allowed("10.0.0.1", "bad-host") is False
        assert engine._host_allowed("10.0.0.1", "good-host") is True

    def test_hostname_patterns(self, config):
        config.hostname_patterns = ["sonar-*", "nas-*"]
        engine = DiscoveryEngine(config)
        assert engine._host_allowed("10.0.0.1", "sonar-01") is True
        assert engine._host_allowed("10.0.0.1", "nas-02") is True
        assert engine._host_allowed("10.0.0.1", "web-01") is False
        # No hostname - patterns don't apply
        assert engine._host_allowed("10.0.0.1") is True


class TestResolveHost:
    def test_ip_passthrough(self):
        assert DiscoveryEngine._resolve_host("192.168.1.1") == "192.168.1.1"

    def test_hostname_resolution(self):
        result = DiscoveryEngine._resolve_host("localhost")
        assert result == "127.0.0.1"

    def test_unresolvable_hostname(self):
        result = DiscoveryEngine._resolve_host("nonexistent.invalid.tld")
        assert result is None


class TestReverseLookup:
    def test_localhost(self):
        result = DiscoveryEngine._reverse_lookup("127.0.0.1")
        assert result is not None  # should resolve to localhost or similar

    def test_unresolvable(self):
        result = DiscoveryEngine._reverse_lookup("240.0.0.1")
        assert result is None


class TestBuildSshCmd:
    def test_key_auth(self, config):
        config.ssh_auth_method = "key"
        engine = DiscoveryEngine(config)
        cmd = engine._build_ssh_cmd("192.168.1.1", "hostname")
        assert "ssh" in cmd
        assert "BatchMode=yes" in " ".join(cmd)
        assert f"testuser@192.168.1.1" in cmd
        assert "hostname" in cmd

    def test_key_auth_with_keyfile(self, config):
        config.ssh_auth_method = "key"
        config.ssh_key_path = "/home/user/.ssh/id_rsa"
        engine = DiscoveryEngine(config)
        cmd = engine._build_ssh_cmd("10.0.0.1", "ls")
        assert "-i" in cmd
        assert "/home/user/.ssh/id_rsa" in cmd

    def test_sshpass_file_auth(self, config):
        config.ssh_auth_method = "sshpass_file"
        config.ssh_password_file = "/etc/ssh_password"
        engine = DiscoveryEngine(config)
        cmd = engine._build_ssh_cmd("10.0.0.1", "hostname")
        assert cmd[0] == "sshpass"
        assert "-f" in cmd
        assert "/etc/ssh_password" in cmd

    def test_sshpass_file_no_password_file_raises(self, config):
        config.ssh_auth_method = "sshpass_file"
        config.ssh_password_file = None
        engine = DiscoveryEngine(config)
        with pytest.raises(ValueError, match="ssh_password_file"):
            engine._build_ssh_cmd("10.0.0.1", "hostname")

    def test_sshpass_env_auth(self, config):
        config.ssh_auth_method = "sshpass_env"
        engine = DiscoveryEngine(config)
        cmd = engine._build_ssh_cmd("10.0.0.1", "hostname")
        assert cmd[0] == "sshpass"
        assert "-e" in cmd

    def test_strict_host_key(self, config):
        config.ssh_host_key_policy = "yes"
        engine = DiscoveryEngine(config)
        cmd = engine._build_ssh_cmd("10.0.0.1", "hostname")
        assert "StrictHostKeyChecking=yes" in " ".join(cmd)
        assert "UserKnownHostsFile=/dev/null" not in " ".join(cmd)


class TestAddHost:
    def test_add_host_by_ip(self, engine):
        engine._add_host("192.168.1.10", "manual")
        assert "192.168.1.10" in engine.hosts
        assert engine.hosts["192.168.1.10"].discovery_method == "manual"

    def test_add_host_deduplication(self, engine):
        engine._add_host("192.168.1.10", "autofs")
        engine._add_host("192.168.1.10", "showmount")
        assert len(engine.hosts) == 1
        # First discovery method should be preserved
        assert engine.hosts["192.168.1.10"].discovery_method == "autofs"

    def test_add_host_unresolvable(self, engine):
        engine._add_host("unresolvable.invalid.tld", "test")
        assert len(engine.hosts) == 0


class TestExtractHostsFromMounts:
    def test_extract(self, engine):
        mounts = [
            MountPoint("/mnt/a", "server1", "/data", "autofs", "nfs"),
            MountPoint("/mnt/b", "server2", "/data", "autofs", "nfs"),
            MountPoint("/mnt/c", None, "", "autofs", "ext4"),
        ]
        engine._extract_hosts_from_mounts(mounts, "autofs")
        # server1 and server2 should be resolved and added if resolvable
        # The actual result depends on DNS resolution


class TestDiscoverSubnetScan:
    def test_no_subnets(self, engine):
        engine._discover_subnet_scan()
        # No error, no hosts added

    def test_invalid_subnet(self, config):
        config.use_subnet_scan = True
        config.scan_subnets = ["not_a_subnet"]
        engine = DiscoveryEngine(config)
        engine._discover_subnet_scan()
        # Should log warning but not crash


class TestRunFullDiscovery:
    def test_minimal_discovery(self, config):
        """All discovery methods disabled."""
        engine = DiscoveryEngine(config)
        hosts, mounts = engine.run_full_discovery()
        assert isinstance(hosts, dict)
        assert isinstance(mounts, list)

    @patch("sonar_catalog.discovery.subprocess.run")
    def test_discovery_with_ip_neigh(self, mock_run, config):
        config.use_ip_neigh = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
                   "192.168.1.11 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n",
        )
        engine = DiscoveryEngine(config)
        hosts, mounts = engine.run_full_discovery()
        # Hosts depend on SSH probe results
        assert isinstance(hosts, dict)


class TestSshProbeHost:
    @patch("sonar_catalog.discovery.subprocess.run")
    def test_successful_probe(self, mock_run, engine):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="sonar-01\n", stderr=""
        )
        host = DiscoveredHost(ip="192.168.1.10")
        engine._ssh_probe_host(host)
        assert host.ssh_accessible is True
        assert host.hostname == "sonar-01"
        assert host.ssh_tested_at is not None

    @patch("sonar_catalog.discovery.subprocess.run")
    def test_failed_probe(self, mock_run, engine):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="Connection refused"
        )
        host = DiscoveredHost(ip="192.168.1.10")
        engine._ssh_probe_host(host)
        assert host.ssh_accessible is False
        assert host.ssh_tested_at is not None

    @patch("sonar_catalog.discovery.subprocess.run")
    def test_timeout_probe(self, mock_run, engine):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ssh", timeout=3)
        host = DiscoveredHost(ip="192.168.1.10")
        engine._ssh_probe_host(host)
        assert host.ssh_accessible is False


class TestDiscoverIpNeigh:
    @patch("sonar_catalog.discovery.subprocess.run")
    def test_parse_ip_neigh(self, mock_run, config):
        config.use_ip_neigh = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
                "192.168.1.11 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
                "192.168.1.12 dev eth0 lladdr 00:00:00:00:00:00 FAILED\n"
                "fe80::1 dev eth0 lladdr ff:ff:ff:ff:ff:ff REACHABLE\n"  # IPv6, skipped
            ),
        )
        engine = DiscoveryEngine(config)
        engine._discover_ip_neigh()
        # 192.168.1.10 and 192.168.1.11 should be added (FAILED and IPv6 skipped)
        assert "192.168.1.10" in engine.hosts
        assert "192.168.1.11" in engine.hosts
        assert "192.168.1.12" not in engine.hosts

    @patch("sonar_catalog.discovery.subprocess.run")
    def test_ip_not_found(self, mock_run, config):
        config.use_ip_neigh = True
        mock_run.side_effect = FileNotFoundError
        engine = DiscoveryEngine(config)
        engine._discover_ip_neigh()
        assert len(engine.hosts) == 0


class TestDiscoverShowmount:
    @patch("sonar_catalog.discovery.subprocess.run")
    def test_showmount(self, mock_run, config):
        config.use_showmount = True
        engine = DiscoveryEngine(config)
        # Add a host and mount manually
        engine.hosts["192.168.1.10"] = DiscoveredHost(ip="192.168.1.10")
        engine.mounts = [
            MountPoint("/mnt/data", "192.168.1.10", "/export", "autofs", "nfs")
        ]

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Export list for 192.168.1.10:\n/export/data   (everyone)\n/export/survey (everyone)\n",
        )
        engine._discover_showmount()
        # Showmount should have been called
        assert mock_run.called
