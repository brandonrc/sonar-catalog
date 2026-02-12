"""
Host and mount point discovery engine.

Discovery methods (in priority order):
1. automount -m  — dump fully resolved autofs maps (primary)
2. Parse /etc/auto.master + map files (fallback if automount -m unavailable)
3. showmount -e <server> — enumerate NFS exports from known servers
4. ip neigh — ARP neighbor table for local network hosts
5. Optional subnet scan — broader network sweep

All discovered hosts are validated via SSH probe before crawling.
"""

import logging
import re
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatch
from ipaddress import IPv4Network, IPv4Address
from pathlib import Path
from typing import Optional

from .config import DiscoveryConfig

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredHost:
    """A host discovered on the network."""
    ip: str
    hostname: Optional[str] = None
    discovery_method: str = ""  # "autofs", "showmount", "ip_neigh", "subnet_scan", "manual"
    ssh_accessible: bool = False
    ssh_tested_at: Optional[datetime] = None
    nfs_exports: list = field(default_factory=list)
    autofs_mounts: list = field(default_factory=list)


@dataclass
class MountPoint:
    """A discovered mount point / NFS export."""
    local_path: str
    remote_host: Optional[str] = None
    remote_path: Optional[str] = None
    source: str = ""  # "autofs", "fstab", "showmount"
    fstype: str = ""
    options: str = ""


class DiscoveryEngine:
    """Discovers hosts and mount points across the network."""

    def __init__(self, config: DiscoveryConfig):
        self.config = config
        self.hosts: dict[str, DiscoveredHost] = {}  # ip -> host
        self.mounts: list[MountPoint] = []

    def run_full_discovery(self) -> tuple[dict[str, DiscoveredHost], list[MountPoint]]:
        """Run all enabled discovery methods and return results."""
        logger.info("Starting full discovery...")

        # Phase 1: Discover mount points and extract server IPs
        if self.config.use_autofs:
            self._discover_autofs()

        self._discover_fstab()

        # Phase 2: Discover network hosts
        if self.config.use_ip_neigh:
            self._discover_ip_neigh()

        if self.config.use_subnet_scan:
            self._discover_subnet_scan()

        # Phase 3: Query showmount on discovered NFS servers
        if self.config.use_showmount:
            self._discover_showmount()

        # Phase 4: SSH probe all discovered hosts
        self._ssh_probe_all()

        accessible = sum(1 for h in self.hosts.values() if h.ssh_accessible)
        logger.info(
            f"Discovery complete: {len(self.hosts)} hosts found, "
            f"{accessible} SSH-accessible, {len(self.mounts)} mount points"
        )

        return self.hosts, self.mounts

    # ---------------------------------------------------------------
    # AutoFS discovery
    # ---------------------------------------------------------------

    def _discover_autofs(self):
        """Discover autofs mounts using automount -m (primary) or map file parsing (fallback)."""
        logger.info("Discovering autofs mounts...")

        # Primary: automount -m dumps the full resolved map
        mounts = self._autofs_via_automount_m()
        if mounts:
            self.mounts.extend(mounts)
            self._extract_hosts_from_mounts(mounts, "autofs")
            return

        # Fallback: parse map files directly
        logger.info("automount -m not available, falling back to map file parsing")
        mounts = self._autofs_via_map_files()
        if mounts:
            self.mounts.extend(mounts)
            self._extract_hosts_from_mounts(mounts, "autofs")

    def _autofs_via_automount_m(self) -> list[MountPoint]:
        """Parse output of 'automount -m' to get all autofs mount maps."""
        mounts = []
        try:
            result = subprocess.run(
                ["automount", "-m"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.debug(f"automount -m failed: {result.stderr.strip()}")
                return []

            output = result.stdout
            logger.info(f"automount -m returned {len(output)} bytes")
            mounts = self._parse_automount_m_output(output)
            logger.info(f"Parsed {len(mounts)} mounts from automount -m")

        except FileNotFoundError:
            logger.debug("automount command not found")
        except subprocess.TimeoutExpired:
            logger.warning("automount -m timed out")
        except Exception as e:
            logger.warning(f"automount -m error: {e}")

        return mounts

    def _parse_automount_m_output(self, output: str) -> list[MountPoint]:
        """
        Parse automount -m output. Format varies but generally:

        Mount point: /auto/nfs
          source(s): /etc/auto.nfs
            key: server1  host1:/export/data1
            key: server2  host2:/export/data2

        Or for direct maps:
          /mnt/data  -fstype=nfs,rw  host:/export/data
        """
        mounts = []
        current_mountpoint = None

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Match "Mount point: /some/path" or just a top-level path
            mp_match = re.match(r"^(?:Mount point:\s+)?(/\S+)", line)
            if mp_match and not line.startswith(" ") and not line.startswith("\t"):
                current_mountpoint = mp_match.group(1)
                continue

            if not current_mountpoint:
                continue

            # Match lines like: key  -options  host:/remote/path
            # or: key  host:/remote/path
            nfs_match = re.match(
                r"\s+(?:\S+:\s+)?(\S+)\s+(?:-([^\s]+)\s+)?(\S+):(/\S+)",
                line
            )
            if nfs_match:
                key = nfs_match.group(1)
                options = nfs_match.group(2) or ""
                remote_host = nfs_match.group(3)
                remote_path = nfs_match.group(4)

                # The local path is the mount point + key
                if key.startswith("/"):
                    local_path = key  # direct map
                else:
                    local_path = f"{current_mountpoint}/{key}"

                mounts.append(MountPoint(
                    local_path=local_path,
                    remote_host=remote_host,
                    remote_path=remote_path,
                    source="autofs",
                    fstype="nfs",
                    options=options,
                ))
                continue

            # Also try to match simpler key lines: key  host:/path
            simple_match = re.match(r"\s+(\S+)\s+(\S+):(/\S+)", line)
            if simple_match:
                key = simple_match.group(1)
                remote_host = simple_match.group(2)
                remote_path = simple_match.group(3)

                if key.startswith("/"):
                    local_path = key
                else:
                    local_path = f"{current_mountpoint}/{key}"

                mounts.append(MountPoint(
                    local_path=local_path,
                    remote_host=remote_host,
                    remote_path=remote_path,
                    source="autofs",
                    fstype="nfs",
                    options="",
                ))

        return mounts

    def _autofs_via_map_files(self) -> list[MountPoint]:
        """Parse /etc/auto.master and referenced map files."""
        mounts = []
        auto_master = Path("/etc/auto.master")

        if not auto_master.exists():
            # Try auto.master.d directory
            auto_master_d = Path("/etc/auto.master.d")
            if auto_master_d.is_dir():
                for f in auto_master_d.iterdir():
                    if f.suffix in (".autofs", ".conf", ""):
                        mounts.extend(self._parse_auto_master_file(f))
            return mounts

        mounts = self._parse_auto_master_file(auto_master)
        return mounts

    def _parse_auto_master_file(self, master_path: Path) -> list[MountPoint]:
        """Parse a single auto.master-format file."""
        mounts = []
        try:
            with open(master_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    mount_point = parts[0]
                    map_source = parts[1]

                    # Skip +auto.master includes for now
                    if mount_point.startswith("+"):
                        continue

                    # If map_source is a file path, parse it
                    map_path = Path(map_source)
                    if map_path.exists() and map_path.is_file():
                        mounts.extend(
                            self._parse_auto_map_file(mount_point, map_path)
                        )
        except PermissionError:
            logger.warning(f"Permission denied reading {master_path}")
        except Exception as e:
            logger.warning(f"Error parsing {master_path}: {e}")

        return mounts

    def _parse_auto_map_file(self, mount_point: str, map_path: Path) -> list[MountPoint]:
        """Parse an individual autofs map file (e.g., /etc/auto.nfs)."""
        mounts = []
        try:
            with open(map_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Format: key [-options] host:/remote/path
                    nfs_match = re.match(
                        r"(\S+)\s+(?:-([^\s]+)\s+)?(\S+):(/\S+)", line
                    )
                    if nfs_match:
                        key = nfs_match.group(1)
                        options = nfs_match.group(2) or ""
                        remote_host = nfs_match.group(3)
                        remote_path = nfs_match.group(4)

                        if key.startswith("/"):
                            local_path = key
                        else:
                            local_path = f"{mount_point}/{key}"

                        mounts.append(MountPoint(
                            local_path=local_path,
                            remote_host=remote_host,
                            remote_path=remote_path,
                            source="autofs",
                            fstype="nfs",
                            options=options,
                        ))
        except Exception as e:
            logger.warning(f"Error parsing map file {map_path}: {e}")

        return mounts

    # ---------------------------------------------------------------
    # fstab discovery
    # ---------------------------------------------------------------

    def _discover_fstab(self):
        """Parse /etc/fstab for NFS mounts."""
        logger.info("Checking /etc/fstab for NFS mounts...")
        fstab = Path("/etc/fstab")
        if not fstab.exists():
            return

        try:
            with open(fstab) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()
                    if len(parts) < 3:
                        continue

                    device, mount_point, fstype = parts[0], parts[1], parts[2]
                    options = parts[3] if len(parts) > 3 else ""

                    if fstype in ("nfs", "nfs4"):
                        # device is host:/path
                        if ":" in device:
                            host, remote_path = device.split(":", 1)
                            mp = MountPoint(
                                local_path=mount_point,
                                remote_host=host,
                                remote_path=remote_path,
                                source="fstab",
                                fstype=fstype,
                                options=options,
                            )
                            self.mounts.append(mp)
                            self._add_host(host, "fstab")
        except Exception as e:
            logger.warning(f"Error parsing /etc/fstab: {e}")

    # ---------------------------------------------------------------
    # showmount discovery
    # ---------------------------------------------------------------

    def _discover_showmount(self):
        """Run showmount -e on all discovered NFS servers to find exports."""
        logger.info("Querying showmount on discovered NFS servers...")
        nfs_servers = set()
        for mp in self.mounts:
            if mp.remote_host:
                nfs_servers.add(mp.remote_host)

        for host in self.hosts.values():
            if host.nfs_exports:
                nfs_servers.add(host.ip)

        for server in nfs_servers:
            self._showmount_host(server)

    def _showmount_host(self, host: str):
        """Run showmount -e on a single host."""
        try:
            result = subprocess.run(
                ["showmount", "-e", host],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.debug(f"showmount -e {host} failed: {result.stderr.strip()}")
                return

            for line in result.stdout.splitlines()[1:]:  # skip header
                parts = line.strip().split()
                if parts:
                    export_path = parts[0]
                    ip = self._resolve_host(host)
                    if ip and ip in self.hosts:
                        self.hosts[ip].nfs_exports.append(export_path)
                    logger.debug(f"showmount: {host} exports {export_path}")

        except FileNotFoundError:
            logger.debug("showmount command not found")
        except subprocess.TimeoutExpired:
            logger.debug(f"showmount -e {host} timed out")
        except Exception as e:
            logger.debug(f"showmount -e {host} error: {e}")

    # ---------------------------------------------------------------
    # ip neigh (ARP table) discovery
    # ---------------------------------------------------------------

    def _discover_ip_neigh(self):
        """Use 'ip neigh' to find hosts on the local network."""
        logger.info("Discovering hosts via ip neigh (ARP table)...")
        try:
            result = subprocess.run(
                ["ip", "neigh"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.warning(f"ip neigh failed: {result.stderr.strip()}")
                return

            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue

                ip = parts[0]
                state = parts[-1]

                # Skip failed/incomplete entries
                if state in ("FAILED", "INCOMPLETE"):
                    continue

                # Only consider IPv4
                try:
                    IPv4Address(ip)
                except ValueError:
                    continue

                self._add_host(ip, "ip_neigh")

        except FileNotFoundError:
            logger.debug("ip command not found")
        except Exception as e:
            logger.warning(f"ip neigh error: {e}")

    # ---------------------------------------------------------------
    # Subnet scan discovery
    # ---------------------------------------------------------------

    def _discover_subnet_scan(self):
        """Scan configured subnets for reachable hosts."""
        if not self.config.scan_subnets:
            return

        logger.info(f"Scanning subnets: {self.config.scan_subnets}")
        for subnet_str in self.config.scan_subnets:
            try:
                network = IPv4Network(subnet_str, strict=False)
                for ip in network.hosts():
                    ip_str = str(ip)
                    if ip_str not in self.hosts:
                        self._add_host(ip_str, "subnet_scan")
            except ValueError as e:
                logger.warning(f"Invalid subnet {subnet_str}: {e}")

    # ---------------------------------------------------------------
    # SSH command builder
    # ---------------------------------------------------------------

    def _build_ssh_cmd(self, target_ip: str, remote_command: str) -> list[str]:
        """
        Build a full SSH command list with proper auth method.

        Supports:
          - "key"          : SSH key auth (ssh-agent or explicit key file)
          - "sshpass_file" : Password from a file via sshpass -f
          - "sshpass_env"  : Password from $SSHPASS env var via sshpass -e

        Host key policy:
          - "accept-new"   : Accept first-time keys, reject changes (recommended)
          - "no"           : Accept everything (legacy, less safe)
          - "yes"          : Strict — reject unknown hosts
        """
        auth = self.config.ssh_auth_method
        host_key = self.config.ssh_host_key_policy

        ssh_args = [
            "ssh",
            "-o", f"ConnectTimeout={self.config.ssh_timeout}",
            "-o", f"StrictHostKeyChecking={host_key}",
            "-o", "LogLevel=ERROR",
        ]

        # For key-based auth, BatchMode=yes prevents password prompts entirely.
        # For sshpass auth, BatchMode must be OFF so sshpass can feed the password.
        if auth == "key":
            ssh_args.extend(["-o", "BatchMode=yes"])
            if host_key in ("no", "accept-new"):
                ssh_args.extend(["-o", "UserKnownHostsFile=/dev/null"])
            if self.config.ssh_key_path:
                ssh_args.extend(["-i", self.config.ssh_key_path])
        else:
            # sshpass modes — BatchMode must be off
            ssh_args.extend(["-o", "BatchMode=no"])
            if host_key in ("no", "accept-new"):
                ssh_args.extend(["-o", "UserKnownHostsFile=/dev/null"])

        target = f"{self.config.ssh_user}@{target_ip}"
        ssh_args.extend([target, remote_command])

        # Wrap with sshpass if using password auth
        if auth == "sshpass_file":
            pw_file = self.config.ssh_password_file
            if not pw_file:
                raise ValueError(
                    "ssh_auth_method='sshpass_file' but ssh_password_file is not set"
                )
            return ["sshpass", "-f", pw_file] + ssh_args
        elif auth == "sshpass_env":
            return ["sshpass", "-e"] + ssh_args
        else:
            return ssh_args

    # ---------------------------------------------------------------
    # SSH probing
    # ---------------------------------------------------------------

    def _ssh_probe_all(self):
        """SSH probe all discovered hosts in parallel."""
        untested = [
            h for h in self.hosts.values()
            if not h.ssh_tested_at
        ]

        if not untested:
            logger.info("No hosts to SSH probe")
            return

        logger.info(f"SSH probing {len(untested)} hosts as user '{self.config.ssh_user}'...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._ssh_probe_host, host): host
                for host in untested
            }
            for future in as_completed(futures):
                host = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.debug(f"SSH probe error for {host.ip}: {e}")

    def _ssh_probe_host(self, host: DiscoveredHost):
        """Test SSH access to a single host."""
        ssh_cmd = self._build_ssh_cmd(host.ip, "hostname")

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True, text=True,
                timeout=self.config.ssh_timeout + 2
            )
            host.ssh_tested_at = datetime.now()

            if result.returncode == 0:
                host.ssh_accessible = True
                hostname = result.stdout.strip()
                if hostname:
                    host.hostname = hostname
                logger.info(f"SSH OK: {host.ip} ({hostname})")
            else:
                host.ssh_accessible = False
                logger.debug(f"SSH failed for {host.ip}: {result.stderr.strip()}")

        except subprocess.TimeoutExpired:
            host.ssh_tested_at = datetime.now()
            host.ssh_accessible = False
            logger.debug(f"SSH timeout for {host.ip}")

    def ssh_discover_remote_mounts(self, host: DiscoveredHost) -> list[MountPoint]:
        """SSH into a host and discover its autofs/fstab mounts."""
        if not host.ssh_accessible:
            return []

        mounts = []

        # Try automount -m on remote host
        try:
            ssh_cmd = self._build_ssh_cmd(host.ip, "automount -m")
            result = subprocess.run(
                ssh_cmd,
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                parsed = self._parse_automount_m_output(result.stdout)
                for mp in parsed:
                    mp.source = f"autofs@{host.hostname or host.ip}"
                mounts.extend(parsed)
                logger.info(
                    f"Found {len(parsed)} autofs mounts on {host.hostname or host.ip}"
                )
        except Exception as e:
            logger.debug(f"Remote automount -m failed on {host.ip}: {e}")

        # Also check remote fstab
        try:
            ssh_cmd = self._build_ssh_cmd(host.ip, "cat /etc/fstab")
            result = subprocess.run(
                ssh_cmd,
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] in ("nfs", "nfs4"):
                        if ":" in parts[0]:
                            rhost, rpath = parts[0].split(":", 1)
                            mounts.append(MountPoint(
                                local_path=parts[1],
                                remote_host=rhost,
                                remote_path=rpath,
                                source=f"fstab@{host.hostname or host.ip}",
                                fstype=parts[2],
                                options=parts[3] if len(parts) > 3 else "",
                            ))
        except Exception as e:
            logger.debug(f"Remote fstab read failed on {host.ip}: {e}")

        return mounts

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------

    def _add_host(self, host_or_ip: str, method: str):
        """Add a host to the discovered hosts dict, resolving hostname if needed."""
        ip = self._resolve_host(host_or_ip)
        if not ip:
            return

        # Apply whitelist/blacklist
        if not self._host_allowed(ip, host_or_ip):
            return

        if ip not in self.hosts:
            hostname = self._reverse_lookup(ip) if ip == host_or_ip else host_or_ip
            self.hosts[ip] = DiscoveredHost(
                ip=ip,
                hostname=hostname,
                discovery_method=method,
            )
            logger.debug(f"Discovered host: {ip} ({hostname}) via {method}")

    def _host_allowed(self, ip: str, hostname: str = "") -> bool:
        """Check if host passes whitelist/blacklist filters."""
        # If whitelist is set, host must match
        if self.config.host_whitelist:
            matched = False
            for pattern in self.config.host_whitelist:
                if ip == pattern or fnmatch(hostname or "", pattern):
                    matched = True
                    break
            if not matched:
                return False

        # Check blacklist
        for pattern in self.config.host_blacklist:
            if ip == pattern or fnmatch(hostname or "", pattern):
                return False

        # Check hostname patterns if set
        if self.config.hostname_patterns and hostname:
            matched = any(
                fnmatch(hostname, p) for p in self.config.hostname_patterns
            )
            if not matched:
                return False

        return True

    def _extract_hosts_from_mounts(self, mounts: list[MountPoint], method: str):
        """Extract and register remote hosts from mount point definitions."""
        for mp in mounts:
            if mp.remote_host:
                self._add_host(mp.remote_host, method)

    @staticmethod
    def _resolve_host(host: str) -> Optional[str]:
        """Resolve a hostname to an IP address."""
        try:
            IPv4Address(host)
            return host  # already an IP
        except ValueError:
            pass

        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror:
            logger.debug(f"Could not resolve hostname: {host}")
            return None

    @staticmethod
    def _reverse_lookup(ip: str) -> Optional[str]:
        """Reverse DNS lookup for an IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
