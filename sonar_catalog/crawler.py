"""
File crawler and metadata extraction.

Walks filesystems (local or remote via SSH), extracts file metadata,
hashes files for deduplication, and stores results in the catalog.
"""

import grp
import logging
import os
import pwd
import re
import stat
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

from .config import CrawlerConfig, MetadataConfig
from .database import CatalogDB
from .hasher import FileHasher, FileHash
from .mount_resolver import MountResolver

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------
# Sonar format detection
# ---------------------------------------------------------------

# Magic bytes / signatures for common sonar formats
SONAR_SIGNATURES = {
    # XTF (eXtended Triton Format) - starts with header type byte
    b"\x01\x00": "xtf",
    # JSF (EdgeTech) - JSTAR header
    b"\x16\x16": "jsf",
    # s7k (Reson/Teledyne) - record start
    b"\xff\xff": "s7k",
    # Kongsberg .all - datagram start
    b"\x02\x00": "all",
    # SEG-Y - textual header starts with "C 1" or binary header
    b"C 1 ": "segy",
    b"C  1": "segy",
}

# Extension-based format detection (fallback)
EXTENSION_TO_FORMAT = {
    ".xtf": "xtf",
    ".jsf": "jsf",
    ".s7k": "s7k",
    ".all": "all",
    ".wcd": "wcd",
    ".kmall": "kmall",
    ".db": "humminbird",
    ".sl2": "lowrance",
    ".sl3": "lowrance",
    ".son": "garmin",
    ".sgy": "segy",
    ".segy": "segy",
    ".bag": "bag",
    ".raw": "raw_sonar",
    ".csv": "csv",
    ".xyz": "xyz_points",
    ".tif": "geotiff",
    ".tiff": "geotiff",
}


def detect_sonar_format(
    path: str,
    extension: str,
    custom_magic: list = None,
    custom_ext_map: dict = None,
) -> Optional[str]:
    """
    Detect sonar file format from magic bytes or extension.

    Checks custom user-defined magic bytes first (from config),
    then built-in signatures, then custom extension map, then built-in extensions.
    """
    try:
        with open(path, "rb") as f:
            # Read enough for the longest possible signature
            max_read = 64  # generous default
            if custom_magic:
                max_read = max(
                    max_read,
                    max(
                        (e.get("offset", 0) + e.get("byte_length", 0))
                        for e in custom_magic
                    ) + 1
                )
            header = f.read(max_read)

            # Check custom magic bytes first (user-defined take priority)
            if custom_magic and len(header) >= 1:
                for entry in custom_magic:
                    offset = entry.get("offset", 0)
                    hex_bytes = entry.get("hex_bytes", "")
                    fmt = entry.get("format", "unknown")
                    try:
                        sig = bytes.fromhex(hex_bytes)
                        if len(header) >= offset + len(sig):
                            if header[offset:offset + len(sig)] == sig:
                                return fmt
                    except (ValueError, TypeError):
                        continue

            # Check built-in magic signatures
            if len(header) >= 4:
                for sig, fmt in SONAR_SIGNATURES.items():
                    if header.startswith(sig):
                        return fmt

    except (PermissionError, OSError):
        pass

    # Fall back to extension (custom map first, then built-in)
    ext = extension.lower()
    if custom_ext_map and ext in custom_ext_map:
        return custom_ext_map[ext]
    return EXTENSION_TO_FORMAT.get(ext)


def get_file_type(path: str) -> Optional[str]:
    """Run file(1) command to get file type description."""
    try:
        result = subprocess.run(
            ["file", "-b", "--mime-type", path],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def get_mime_type_magic(path: str) -> Optional[str]:
    """Use python-magic for MIME type detection."""
    try:
        import magic
        mime = magic.from_file(path, mime=True)
        return mime
    except ImportError:
        return None
    except Exception:
        return None


class FileCrawler:
    """Crawls filesystems and catalogs files."""

    def __init__(
        self,
        db: CatalogDB,
        crawler_config: CrawlerConfig,
        metadata_config: MetadataConfig,
        mount_resolver: MountResolver,
    ):
        self.db = db
        self.config = crawler_config
        self.meta_config = metadata_config
        self.mount_resolver = mount_resolver
        self.hasher = FileHasher(
            algorithm=crawler_config.hash_algorithm,
            partial_size=crawler_config.partial_hash_size,
            workers=crawler_config.hash_workers,
        )

    def crawl_local(
        self,
        base_path: str,
        hostname: str,
        ip_address: str = "",
        access_hostname: str = "",
        progress_callback: Optional[Callable] = None,
    ) -> dict:
        """
        Crawl a local filesystem path and catalog all files.

        Returns dict with scan statistics.
        """
        base = Path(base_path)
        if not base.exists():
            logger.error(f"Path does not exist: {base_path}")
            return {"error": f"Path does not exist: {base_path}"}

        # Start scan record
        scan_id = self.db.start_scan(hostname, base_path)
        logger.info(f"Starting scan {scan_id}: {hostname}:{base_path}")

        # Load known files for incremental scanning
        known_files = {}
        if self.config.incremental:
            known_files = self.db.get_known_files_for_host(hostname)
            logger.info(f"Loaded {len(known_files)} known files for incremental scan")

        # Load known fingerprints for dedup
        known_fps = self.db.get_known_fingerprints()
        logger.info(f"Loaded {len(known_fps)} known fingerprints")

        stats = {
            "files_found": 0,
            "files_new": 0,
            "files_skipped": 0,
            "files_error": 0,
            "bytes_hashed": 0,
        }

        # Collect files in batches
        batch_paths = []
        batch_info = {}  # path -> {mtime, size, ...}

        try:
            for entry in self._walk_filesystem(base_path):
                stats["files_found"] += 1

                path = entry["path"]
                file_size = entry["size"]

                # Incremental: skip if mtime+size unchanged
                if self.config.incremental and path in known_files:
                    known_hash, known_mtime = known_files[path]
                    if known_mtime and entry.get("mtime"):
                        if str(known_mtime) == str(entry["mtime"]):
                            stats["files_skipped"] += 1
                            continue

                batch_paths.append(path)
                batch_info[path] = entry

                # Process batch when full
                if len(batch_paths) >= self.config.batch_size:
                    new, errors, hashed_bytes = self._process_batch(
                        batch_paths, batch_info, known_fps,
                        hostname, ip_address, scan_id, access_hostname
                    )
                    stats["files_new"] += new
                    stats["files_error"] += errors
                    stats["bytes_hashed"] += hashed_bytes
                    batch_paths = []
                    batch_info = {}

                    # Checkpoint
                    self.db.update_scan(
                        scan_id,
                        files_found=stats["files_found"],
                        files_new=stats["files_new"],
                        files_skipped=stats["files_skipped"],
                        checkpoint_path=path,
                    )

                    if progress_callback:
                        progress_callback(stats)

            # Process remaining batch
            if batch_paths:
                new, errors, hashed_bytes = self._process_batch(
                    batch_paths, batch_info, known_fps,
                    hostname, ip_address, scan_id, access_hostname
                )
                stats["files_new"] += new
                stats["files_error"] += errors
                stats["bytes_hashed"] += hashed_bytes

        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            self.db.update_scan(
                scan_id,
                status="interrupted",
                **{k: v for k, v in stats.items() if k != "bytes_hashed"},
                bytes_hashed=stats["bytes_hashed"],
            )
            return stats

        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.db.update_scan(
                scan_id,
                status="error",
                error_message=str(e),
                **stats,
            )
            return stats

        # Mark scan complete
        self.db.update_scan(
            scan_id,
            status="complete",
            finished_at=datetime.now().isoformat(),
            **stats,
        )

        logger.info(
            f"Scan {scan_id} complete: {stats['files_found']} found, "
            f"{stats['files_new']} new, {stats['files_skipped']} skipped, "
            f"{stats['files_error']} errors"
        )
        return stats

    def crawl_remote(
        self,
        host_ip: str,
        hostname: str,
        remote_path: str,
        ssh_user: str,
        ssh_key: str = None,
        progress_callback: Optional[Callable] = None,
    ) -> dict:
        """
        Crawl a remote filesystem via SSH and catalog files.
        Uses 'find' over SSH to list files, then hashes via NFS or SSH.
        """
        scan_id = self.db.start_scan(hostname, remote_path)
        logger.info(f"Starting remote scan {scan_id}: {hostname}:{remote_path}")

        ssh_base = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
        ]
        if ssh_key:
            ssh_base.extend(["-i", ssh_key])

        target = f"{ssh_user}@{host_ip}"

        # Use find to list all files with stat info
        # Output: size\tmtime_epoch\tpath
        find_cmd = (
            f"find {remote_path} -type f "
            f"-printf '%s\\t%T@\\t%p\\n' 2>/dev/null"
        )

        try:
            result = subprocess.run(
                ssh_base + [target, find_cmd],
                capture_output=True, text=True, timeout=300
            )

            if result.returncode != 0:
                error = f"Remote find failed: {result.stderr.strip()}"
                logger.error(error)
                self.db.update_scan(scan_id, status="error", error_message=error)
                return {"error": error}

            # Parse find output
            files = []
            for line in result.stdout.splitlines():
                parts = line.split("\t", 2)
                if len(parts) == 3:
                    try:
                        size = int(parts[0])
                        mtime = datetime.fromtimestamp(float(parts[1]))
                        path = parts[2]
                        files.append({
                            "path": path,
                            "size": size,
                            "mtime": mtime.isoformat(),
                        })
                    except (ValueError, OSError):
                        continue

            logger.info(f"Remote find returned {len(files)} files")

            # For now, record remote files with size-based fingerprinting
            # Full hashing would be done when the NFS mount is accessible
            stats = {
                "files_found": len(files),
                "files_new": 0,
                "files_skipped": 0,
                "files_error": 0,
                "bytes_hashed": 0,
            }

            # TODO: If NFS-accessible locally, hash via local path
            # Otherwise, could stream via SSH for hashing (slower)

            self.db.update_scan(scan_id, status="complete", **stats)
            return stats

        except subprocess.TimeoutExpired:
            error = "Remote find timed out"
            logger.error(error)
            self.db.update_scan(scan_id, status="error", error_message=error)
            return {"error": error}

    def _walk_filesystem(self, base_path: str):
        """
        Walk a filesystem and yield file info dicts.
        Handles permission errors and excluded directories gracefully.
        """
        for dirpath, dirnames, filenames in os.walk(base_path, followlinks=False):
            # Filter excluded directories (in-place to prevent os.walk from descending)
            dirnames[:] = [
                d for d in dirnames
                if d not in self.config.exclude_dirs
            ]

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)

                # Check extension filters
                _, ext = os.path.splitext(filename)
                if self.config.include_extensions:
                    if ext.lower() not in self.config.include_extensions:
                        continue
                if ext.lower() in self.config.exclude_extensions:
                    continue

                try:
                    st = os.lstat(filepath)

                    # Skip non-regular files (symlinks, devices, etc.)
                    if not stat.S_ISREG(st.st_mode):
                        continue

                    # Size filters
                    if self.config.min_file_size and st.st_size < self.config.min_file_size:
                        continue
                    if self.config.max_file_size and st.st_size > self.config.max_file_size:
                        continue

                    # Get owner info
                    try:
                        owner = pwd.getpwuid(st.st_uid).pw_name
                    except (KeyError, OverflowError):
                        owner = str(st.st_uid)

                    yield {
                        "path": filepath,
                        "name": filename,
                        "directory": dirpath,
                        "extension": ext,
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        "atime": datetime.fromtimestamp(st.st_atime).isoformat(),
                        "ctime": datetime.fromtimestamp(st.st_ctime).isoformat(),
                        "mode": stat.filemode(st.st_mode),
                        "owner": owner,
                    }

                except PermissionError:
                    logger.debug(f"Permission denied: {filepath}")
                except OSError as e:
                    logger.debug(f"OS error for {filepath}: {e}")

    def _process_batch(
        self,
        paths: list[str],
        info: dict,
        known_fps: set[str],
        hostname: str,
        ip_address: str,
        scan_id: int,
        access_hostname: str = "",
    ) -> tuple[int, int, int]:
        """Process a batch of files: hash, detect type, store in DB."""
        new_count = 0
        error_count = 0
        bytes_hashed = 0

        # Hash all files in batch
        hashes = self.hasher.hash_files_batch(paths, known_fps)

        file_records = []
        location_records = []

        # Resolve all paths through mount resolver to get canonical locations
        canonical_locs = self.mount_resolver.resolve_batch(paths)

        for fh in hashes:
            file_info = info.get(fh.path, {})
            canonical_loc = canonical_locs.get(fh.path)

            # Detect file type / MIME
            mime_type = None
            file_type = None
            sonar_format = None

            if self.meta_config.use_file_command:
                mime_type = get_file_type(fh.path)

            if self.meta_config.use_magic:
                magic_mime = get_mime_type_magic(fh.path)
                if magic_mime:
                    mime_type = magic_mime

            # Detect sonar format
            ext = file_info.get("extension", "")
            sonar_format = detect_sonar_format(
                fh.path, ext,
                custom_magic=self.meta_config.custom_magic_bytes,
                custom_ext_map=self.meta_config.custom_extension_map,
            )

            file_records.append({
                "content_hash": fh.full_hash,
                "file_size": fh.size,
                "partial_hash": fh.partial_hash,
                "hash_algorithm": fh.algorithm,
                "mime_type": mime_type,
                "file_type": file_type,
                "sonar_format": sonar_format,
            })

            location_records.append({
                "content_hash": fh.full_hash,
                "nfs_server": canonical_loc.nfs_server if canonical_loc else None,
                "nfs_export": canonical_loc.nfs_export if canonical_loc else None,
                "remote_path": canonical_loc.relative_path if canonical_loc else None,
                "canonical_path": canonical_loc.canonical_path if canonical_loc else None,
                "is_local": canonical_loc.is_local if canonical_loc else False,
                "access_path": canonical_loc.access_path if canonical_loc else fh.path,
                "access_hostname": access_hostname,
                "mount_source": canonical_loc.mount_source if canonical_loc else None,
                "file_name": file_info.get("name", os.path.basename(fh.path)),
                "directory": file_info.get("directory", os.path.dirname(fh.path)),
                "mtime": file_info.get("mtime"),
                "scan_id": scan_id,
            })

            new_count += 1
            bytes_hashed += fh.size

        # Batch insert
        try:
            self.db.insert_files_batch(file_records)
            self.db.insert_locations_batch(location_records)
        except Exception as e:
            logger.error(f"Batch insert error: {e}")
            error_count += len(file_records)
            new_count = 0

        return new_count, error_count, bytes_hashed
