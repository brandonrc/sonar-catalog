"""
Mount resolver — maps local filesystem paths back to their canonical
NFS server:export origin.

Given a file at /auto/nfs/sonar01/survey/line001.xtf, this resolves
it to its authoritative location: sonar01:/export/survey/line001.xtf

Resolution sources (checked in order):
1. /proc/mounts  — currently mounted filesystems (most accurate)
2. Parsed autofs maps  — for indirect autofs mounts not yet triggered
3. showmount -e  — NFS exports from known servers
4. mount command output  — fallback

This is a catalog of pointers, not a data warehouse. No data is copied.
"""

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CanonicalLocation:
    """The resolved origin of a file — where it actually lives on the network."""
    nfs_server: str           # hostname or IP of the NFS server
    nfs_export: str           # export path on the server (e.g. /export/survey)
    relative_path: str        # path within the export (e.g. line001.xtf)
    canonical_path: str       # full path: server:/export/survey/line001.xtf
    access_path: str          # local path used to reach the file (e.g. /auto/nfs/sonar01/survey/line001.xtf)
    mount_source: str         # how we know this: "proc_mounts", "autofs_map", "fstab", "local"
    is_local: bool = False    # True if the file is on a local filesystem (not NFS)


@dataclass
class MountEntry:
    """A single mount point mapping."""
    local_path: str       # where it's mounted locally
    remote_server: str    # NFS server hostname/IP (empty for local)
    remote_path: str      # export path on the server (empty for local)
    fstype: str           # nfs, nfs4, ext4, xfs, etc.
    source: str           # where we learned this: "proc_mounts", "autofs_map", "fstab"


class MountResolver:
    """Resolves local filesystem paths to their canonical NFS origin."""

    def __init__(self):
        self._mounts: list[MountEntry] = []
        self._loaded = False

    def load(self):
        """Load mount information from all sources."""
        self._mounts = []

        # Primary: /proc/mounts (what's actually mounted right now)
        self._load_proc_mounts()

        # Secondary: parsed autofs maps (for mounts not yet triggered)
        self._load_autofs_maps()

        # Tertiary: /etc/fstab
        self._load_fstab()

        # Sort by path length descending so longest-prefix match wins
        self._mounts.sort(key=lambda m: len(m.local_path), reverse=True)

        self._loaded = True
        nfs_count = sum(1 for m in self._mounts if m.fstype in ("nfs", "nfs4"))
        logger.info(
            f"Mount resolver loaded: {len(self._mounts)} mounts "
            f"({nfs_count} NFS)"
        )

    def resolve(self, local_path: str) -> CanonicalLocation:
        """
        Resolve a local path to its canonical NFS origin.

        If the file is on a local filesystem (not NFS), returns a
        CanonicalLocation with is_local=True and the local hostname.
        """
        if not self._loaded:
            self.load()

        local_path = os.path.abspath(local_path)

        # Find the longest mount prefix that matches
        for mount in self._mounts:
            if local_path.startswith(mount.local_path + "/") or local_path == mount.local_path:
                # Strip the mount point to get the relative path
                if local_path == mount.local_path:
                    relative = ""
                else:
                    relative = local_path[len(mount.local_path):].lstrip("/")

                if mount.fstype in ("nfs", "nfs4") and mount.remote_server:
                    # NFS mount — resolve to server:export/relative
                    full_remote = os.path.join(mount.remote_path, relative) if relative else mount.remote_path
                    return CanonicalLocation(
                        nfs_server=mount.remote_server,
                        nfs_export=mount.remote_path,
                        relative_path=relative,
                        canonical_path=f"{mount.remote_server}:{full_remote}",
                        access_path=local_path,
                        mount_source=mount.source,
                        is_local=False,
                    )

        # No NFS mount found — this is a local file
        import socket
        hostname = socket.gethostname()
        return CanonicalLocation(
            nfs_server=hostname,
            nfs_export="",
            relative_path=local_path,
            canonical_path=f"{hostname}:{local_path}",
            access_path=local_path,
            mount_source="local",
            is_local=True,
        )

    def resolve_batch(self, paths: list[str]) -> dict[str, CanonicalLocation]:
        """Resolve a batch of paths. Returns {path: CanonicalLocation}."""
        return {p: self.resolve(p) for p in paths}

    def get_nfs_mounts(self) -> list[MountEntry]:
        """Return all known NFS mount entries."""
        if not self._loaded:
            self.load()
        return [m for m in self._mounts if m.fstype in ("nfs", "nfs4")]

    def get_all_mounts(self) -> list[MountEntry]:
        """Return all mount entries."""
        if not self._loaded:
            self.load()
        return list(self._mounts)

    def add_mount(self, mount: MountEntry):
        """Manually add a mount entry (e.g., from remote discovery)."""
        self._mounts.append(mount)
        self._mounts.sort(key=lambda m: len(m.local_path), reverse=True)

    # ---------------------------------------------------------------
    # Loaders
    # ---------------------------------------------------------------

    def _load_proc_mounts(self):
        """Parse /proc/mounts for currently mounted filesystems."""
        proc_mounts = Path("/proc/mounts")
        if not proc_mounts.exists():
            # macOS: use mount command instead
            self._load_mount_command()
            return

        try:
            with open(proc_mounts) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue

                    device = parts[0]
                    mount_point = parts[1]
                    fstype = parts[2]

                    if fstype in ("nfs", "nfs4"):
                        # device = server:/export/path
                        if ":" in device:
                            server, export_path = device.split(":", 1)
                            self._mounts.append(MountEntry(
                                local_path=mount_point,
                                remote_server=server,
                                remote_path=export_path,
                                fstype=fstype,
                                source="proc_mounts",
                            ))
                    else:
                        # Local filesystem — record it so we know it's local
                        if mount_point.startswith("/") and fstype not in (
                            "proc", "sysfs", "devtmpfs", "tmpfs", "cgroup",
                            "cgroup2", "pstore", "securityfs", "debugfs",
                            "configfs", "fusectl", "mqueue", "hugetlbfs",
                            "autofs", "rpc_pipefs", "nfsd",
                        ):
                            self._mounts.append(MountEntry(
                                local_path=mount_point,
                                remote_server="",
                                remote_path="",
                                fstype=fstype,
                                source="proc_mounts",
                            ))
        except Exception as e:
            logger.warning(f"Error reading /proc/mounts: {e}")

    def _load_mount_command(self):
        """Fallback: parse 'mount' command output."""
        try:
            result = subprocess.run(
                ["mount"], capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return

            for line in result.stdout.splitlines():
                # Format: device on mount_point type fstype (options)
                match = re.match(r"(\S+)\s+on\s+(\S+)\s+type\s+(\S+)", line)
                if match:
                    device = match.group(1)
                    mount_point = match.group(2)
                    fstype = match.group(3)

                    if fstype in ("nfs", "nfs4") and ":" in device:
                        server, export_path = device.split(":", 1)
                        self._mounts.append(MountEntry(
                            local_path=mount_point,
                            remote_server=server,
                            remote_path=export_path,
                            fstype=fstype,
                            source="mount_cmd",
                        ))
        except Exception as e:
            logger.debug(f"mount command failed: {e}")

    def _load_autofs_maps(self):
        """
        Parse autofs maps for mounts that may not be triggered yet.

        With indirect autofs, /auto/nfs/sonar01 won't appear in
        /proc/mounts until someone cd's into it. But the map file
        tells us it would mount sonar01:/export if accessed.
        """
        # Try automount -m first
        try:
            result = subprocess.run(
                ["automount", "-m"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                self._parse_automount_m_for_mounts(result.stdout)
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: parse auto.master + map files
        self._parse_auto_master_for_mounts()

    def _parse_automount_m_for_mounts(self, output: str):
        """Parse automount -m output into MountEntry records."""
        current_mountpoint = None

        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Match mount point declarations
            mp_match = re.match(r"^(?:Mount point:\s+)?(/\S+)", line)
            if mp_match and not line.startswith(" ") and not line.startswith("\t"):
                current_mountpoint = mp_match.group(1)
                continue

            if not current_mountpoint:
                continue

            # Match NFS entries: key [-options] host:/remote/path
            nfs_match = re.match(
                r"\s+(?:\S+:\s+)?(\S+)\s+(?:-[^\s]+\s+)?(\S+):(/\S+)", line
            )
            if nfs_match:
                key = nfs_match.group(1)
                remote_host = nfs_match.group(2)
                remote_path = nfs_match.group(3)

                if key.startswith("/"):
                    local_path = key
                else:
                    local_path = f"{current_mountpoint}/{key}"

                self._mounts.append(MountEntry(
                    local_path=local_path,
                    remote_server=remote_host,
                    remote_path=remote_path,
                    fstype="nfs",
                    source="autofs_map",
                ))
                continue

            # Simpler format: key host:/path
            simple_match = re.match(r"\s+(\S+)\s+(\S+):(/\S+)", line)
            if simple_match:
                key = simple_match.group(1)
                remote_host = simple_match.group(2)
                remote_path = simple_match.group(3)

                if key.startswith("/"):
                    local_path = key
                else:
                    local_path = f"{current_mountpoint}/{key}"

                self._mounts.append(MountEntry(
                    local_path=local_path,
                    remote_server=remote_host,
                    remote_path=remote_path,
                    fstype="nfs",
                    source="autofs_map",
                ))

    def _parse_auto_master_for_mounts(self):
        """Parse /etc/auto.master and referenced map files."""
        auto_master = Path("/etc/auto.master")
        if not auto_master.exists():
            return

        try:
            with open(auto_master) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("+"):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    mount_point = parts[0]
                    map_source = parts[1]

                    map_path = Path(map_source)
                    if map_path.exists() and map_path.is_file():
                        self._parse_auto_map_for_mounts(mount_point, map_path)
        except Exception as e:
            logger.debug(f"Error parsing auto.master: {e}")

    def _parse_auto_map_for_mounts(self, mount_point: str, map_path: Path):
        """Parse an autofs map file into MountEntry records."""
        try:
            with open(map_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    nfs_match = re.match(
                        r"(\S+)\s+(?:-[^\s]+\s+)?(\S+):(/\S+)", line
                    )
                    if nfs_match:
                        key = nfs_match.group(1)
                        remote_host = nfs_match.group(2)
                        remote_path = nfs_match.group(3)

                        if key.startswith("/"):
                            local_path = key
                        else:
                            local_path = f"{mount_point}/{key}"

                        self._mounts.append(MountEntry(
                            local_path=local_path,
                            remote_server=remote_host,
                            remote_path=remote_path,
                            fstype="nfs",
                            source="autofs_map",
                        ))
        except Exception as e:
            logger.debug(f"Error parsing map file {map_path}: {e}")

    def _load_fstab(self):
        """Parse /etc/fstab for NFS mounts (may not be mounted yet)."""
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

                    if fstype in ("nfs", "nfs4") and ":" in device:
                        server, export_path = device.split(":", 1)
                        # Only add if not already known from proc_mounts
                        existing = any(
                            m.local_path == mount_point and m.source == "proc_mounts"
                            for m in self._mounts
                        )
                        if not existing:
                            self._mounts.append(MountEntry(
                                local_path=mount_point,
                                remote_server=server,
                                remote_path=export_path,
                                fstype=fstype,
                                source="fstab",
                            ))
        except Exception as e:
            logger.debug(f"Error parsing fstab: {e}")
