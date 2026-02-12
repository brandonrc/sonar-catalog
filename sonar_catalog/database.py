"""
Database layer for the Sonar Catalog.

Supports PostgreSQL (recommended) and SQLite (single-machine fallback).

Schema design:
- files: One row per unique content hash (deduplicated)
- locations: Maps each content hash to its canonical NFS origin + access path
- hosts: Discovered hosts and their status
- scans: Scan history for incremental crawling
- file_metadata: Extended metadata extracted from file contents

KEY CONCEPT: No data is copied. The catalog stores POINTERS — each location
record stores the canonical NFS server:path origin AND the local access path
used to reach the file. If 10 systems export the same file, there's one row
in files and one row in locations per unique canonical path.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Iterator

from .config import DatabaseConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------

SCHEMA_POSTGRES = """
-- Unique files keyed by content hash
CREATE TABLE IF NOT EXISTS files (
    content_hash    TEXT PRIMARY KEY,
    file_size       BIGINT NOT NULL,
    partial_hash    TEXT NOT NULL,
    hash_algorithm  TEXT NOT NULL DEFAULT 'blake3',
    mime_type       TEXT,
    file_type       TEXT,
    sonar_format    TEXT,
    first_seen      TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Every location where a file exists — stores CANONICAL origin + access path
CREATE TABLE IF NOT EXISTS locations (
    id              BIGSERIAL PRIMARY KEY,
    content_hash    TEXT NOT NULL REFERENCES files(content_hash),
    -- Canonical origin: the NFS server and path where the data actually lives
    nfs_server      TEXT NOT NULL,         -- NFS server hostname (or local hostname)
    nfs_export      TEXT NOT NULL DEFAULT '',  -- server export path (e.g. /export/survey)
    remote_path     TEXT NOT NULL,         -- full path on origin (export + relative)
    canonical_path  TEXT NOT NULL,         -- server:/full/path (the authoritative pointer)
    is_local        BOOLEAN DEFAULT FALSE, -- true if on local disk, not NFS
    -- Access info: how we reach the file from the crawling machine
    access_path     TEXT NOT NULL,         -- local path used to reach the file
    access_hostname TEXT NOT NULL,         -- hostname of crawling machine
    mount_source    TEXT,                  -- resolution method: proc_mounts, autofs_map, fstab, local
    -- File info
    file_name       TEXT NOT NULL,
    directory       TEXT NOT NULL,         -- parent directory on origin server
    mtime           TIMESTAMP,
    file_mode       TEXT,
    owner           TEXT,
    scan_id         BIGINT,
    discovered_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (canonical_path)
);

-- Discovered hosts
CREATE TABLE IF NOT EXISTS hosts (
    ip_address      TEXT PRIMARY KEY,
    hostname        TEXT,
    discovery_method TEXT,
    ssh_accessible  BOOLEAN DEFAULT FALSE,
    first_seen      TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMP NOT NULL DEFAULT NOW(),
    last_scan_at    TIMESTAMP,
    scan_status     TEXT DEFAULT 'pending'
);

-- Scan history
CREATE TABLE IF NOT EXISTS scans (
    id              BIGSERIAL PRIMARY KEY,
    hostname        TEXT NOT NULL,
    base_path       TEXT NOT NULL,
    started_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMP,
    files_found     BIGINT DEFAULT 0,
    files_new       BIGINT DEFAULT 0,
    files_skipped   BIGINT DEFAULT 0,
    files_error     BIGINT DEFAULT 0,
    bytes_hashed    BIGINT DEFAULT 0,
    status          TEXT DEFAULT 'running',
    error_message   TEXT,
    checkpoint_path TEXT
);

-- Extended metadata (JSONB for flexible per-format fields)
CREATE TABLE IF NOT EXISTS file_metadata (
    content_hash    TEXT PRIMARY KEY REFERENCES files(content_hash),
    metadata        JSONB NOT NULL DEFAULT '{}',
    extracted_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_locations_hash ON locations(content_hash);
CREATE INDEX IF NOT EXISTS idx_locations_server ON locations(nfs_server);
CREATE INDEX IF NOT EXISTS idx_locations_canonical ON locations(canonical_path);
CREATE INDEX IF NOT EXISTS idx_locations_access_host ON locations(access_hostname);
CREATE INDEX IF NOT EXISTS idx_locations_directory ON locations(directory);
CREATE INDEX IF NOT EXISTS idx_locations_filename ON locations(file_name);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(file_size);
CREATE INDEX IF NOT EXISTS idx_files_mime ON files(mime_type);
CREATE INDEX IF NOT EXISTS idx_files_sonar ON files(sonar_format);
CREATE INDEX IF NOT EXISTS idx_files_partial ON files(partial_hash);
"""

SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS files (
    content_hash    TEXT PRIMARY KEY,
    file_size       INTEGER NOT NULL,
    partial_hash    TEXT NOT NULL,
    hash_algorithm  TEXT NOT NULL DEFAULT 'blake3',
    mime_type       TEXT,
    file_type       TEXT,
    sonar_format    TEXT,
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS locations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash    TEXT NOT NULL REFERENCES files(content_hash),
    nfs_server      TEXT NOT NULL,
    nfs_export      TEXT NOT NULL DEFAULT '',
    remote_path     TEXT NOT NULL,
    canonical_path  TEXT NOT NULL,
    is_local        INTEGER DEFAULT 0,
    access_path     TEXT NOT NULL,
    access_hostname TEXT NOT NULL,
    mount_source    TEXT,
    file_name       TEXT NOT NULL,
    directory       TEXT NOT NULL,
    mtime           TEXT,
    file_mode       TEXT,
    owner           TEXT,
    scan_id         INTEGER,
    discovered_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (canonical_path)
);

CREATE TABLE IF NOT EXISTS hosts (
    ip_address      TEXT PRIMARY KEY,
    hostname        TEXT,
    discovery_method TEXT,
    ssh_accessible  INTEGER DEFAULT 0,
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    last_scan_at    TEXT,
    scan_status     TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        TEXT NOT NULL,
    base_path       TEXT NOT NULL,
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    files_found     INTEGER DEFAULT 0,
    files_new       INTEGER DEFAULT 0,
    files_skipped   INTEGER DEFAULT 0,
    files_error     INTEGER DEFAULT 0,
    bytes_hashed    INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'running',
    error_message   TEXT,
    checkpoint_path TEXT
);

CREATE TABLE IF NOT EXISTS file_metadata (
    content_hash    TEXT PRIMARY KEY REFERENCES files(content_hash),
    metadata        TEXT NOT NULL DEFAULT '{}',
    extracted_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_locations_hash ON locations(content_hash);
CREATE INDEX IF NOT EXISTS idx_locations_server ON locations(nfs_server);
CREATE INDEX IF NOT EXISTS idx_locations_canonical ON locations(canonical_path);
CREATE INDEX IF NOT EXISTS idx_locations_access_host ON locations(access_hostname);
CREATE INDEX IF NOT EXISTS idx_locations_directory ON locations(directory);
CREATE INDEX IF NOT EXISTS idx_locations_filename ON locations(file_name);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(file_size);
CREATE INDEX IF NOT EXISTS idx_files_mime ON files(mime_type);
CREATE INDEX IF NOT EXISTS idx_files_sonar ON files(sonar_format);
CREATE INDEX IF NOT EXISTS idx_files_partial ON files(partial_hash);
"""


class CatalogDB:
    """Database interface for the Sonar Catalog."""

    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.backend = config.backend
        self._pg_pool = None
        self._sqlite_conn = None

    def initialize(self):
        """Create tables and indexes."""
        if self.backend == "postgresql":
            self._init_postgres()
        else:
            self._init_sqlite()

    def _init_postgres(self):
        """Initialize PostgreSQL database."""
        try:
            import psycopg2
            import psycopg2.pool
        except ImportError:
            raise RuntimeError(
                "psycopg2 not installed. Install with: pip install psycopg2-binary"
            )

        self._pg_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2, maxconn=10,
            host=self.config.pg_host,
            port=self.config.pg_port,
            database=self.config.pg_database,
            user=self.config.pg_user,
            password=self.config.pg_password,
        )

        with self.get_connection() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
                except Exception:
                    logger.info("pg_trgm extension not available")
                    conn.rollback()

                for statement in SCHEMA_POSTGRES.split(";"):
                    stmt = statement.strip()
                    if stmt:
                        cur.execute(stmt + ";")
                conn.commit()

        logger.info("PostgreSQL database initialized")

    def _init_sqlite(self):
        """Initialize SQLite database."""
        db_path = Path(self.config.sqlite_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self._sqlite_conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._sqlite_conn.execute("PRAGMA journal_mode=WAL;")
        self._sqlite_conn.execute("PRAGMA synchronous=NORMAL;")
        self._sqlite_conn.execute("PRAGMA cache_size=-64000;")

        for statement in SCHEMA_SQLITE.split(";"):
            stmt = statement.strip()
            if stmt:
                self._sqlite_conn.execute(stmt + ";")
        self._sqlite_conn.commit()

        logger.info(f"SQLite database initialized at {db_path}")

    @contextmanager
    def get_connection(self):
        """Get a database connection (context manager)."""
        if self.backend == "postgresql":
            conn = self._pg_pool.getconn()
            try:
                yield conn
            finally:
                self._pg_pool.putconn(conn)
        else:
            yield self._sqlite_conn

    # ---------------------------------------------------------------
    # File operations
    # ---------------------------------------------------------------

    def get_known_fingerprints(self) -> set[str]:
        """Get all known partial hash fingerprints for dedup check."""
        fps = set()
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT file_size, partial_hash FROM files")
            for row in cur.fetchall():
                fps.add(f"{row[0]}:{row[1]}")
        return fps

    def file_exists(self, content_hash: str) -> bool:
        """Check if a content hash is already cataloged."""
        ph = "%s" if self.backend == "postgresql" else "?"
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT 1 FROM files WHERE content_hash = {ph}", (content_hash,))
            return cur.fetchone() is not None

    def insert_file(
        self,
        content_hash: str,
        file_size: int,
        partial_hash: str,
        hash_algorithm: str = "blake3",
        mime_type: str = None,
        file_type: str = None,
        sonar_format: str = None,
    ):
        """Insert a new unique file record."""
        ph = "%s" if self.backend == "postgresql" else "?"
        ts = "NOW()" if self.backend == "postgresql" else "datetime('now')"
        sql = f"""
            INSERT INTO files (content_hash, file_size, partial_hash, hash_algorithm,
                              mime_type, file_type, sonar_format)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            ON CONFLICT (content_hash) DO UPDATE SET last_seen = {ts}
        """
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, (
                content_hash, file_size, partial_hash, hash_algorithm,
                mime_type, file_type, sonar_format,
            ))
            conn.commit()

    def insert_location(
        self,
        content_hash: str,
        nfs_server: str,
        nfs_export: str,
        remote_path: str,
        canonical_path: str,
        is_local: bool,
        access_path: str,
        access_hostname: str,
        mount_source: str,
        file_name: str,
        directory: str,
        mtime: Optional[str] = None,
        file_mode: str = None,
        owner: str = None,
        scan_id: int = None,
    ):
        """Insert a canonical location record."""
        ph = "%s" if self.backend == "postgresql" else "?"
        ts = "NOW()" if self.backend == "postgresql" else "datetime('now')"
        local_val = is_local if self.backend == "postgresql" else (1 if is_local else 0)

        sql = f"""
            INSERT INTO locations (content_hash, nfs_server, nfs_export, remote_path,
                                  canonical_path, is_local, access_path, access_hostname,
                                  mount_source, file_name, directory, mtime,
                                  file_mode, owner, scan_id)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            ON CONFLICT (canonical_path) DO UPDATE SET
                content_hash = EXCLUDED.content_hash,
                access_path = EXCLUDED.access_path,
                access_hostname = EXCLUDED.access_hostname,
                mtime = EXCLUDED.mtime,
                scan_id = EXCLUDED.scan_id,
                discovered_at = {ts}
        """
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, (
                content_hash, nfs_server, nfs_export, remote_path,
                canonical_path, local_val, access_path, access_hostname,
                mount_source, file_name, directory, mtime,
                file_mode, owner, scan_id,
            ))
            conn.commit()

    def insert_files_batch(self, file_records: list[dict]):
        """Batch insert file records."""
        if not file_records:
            return

        ph = "%s" if self.backend == "postgresql" else "?"
        ts = "NOW()" if self.backend == "postgresql" else "datetime('now')"

        sql = f"""
            INSERT INTO files (content_hash, file_size, partial_hash, hash_algorithm,
                              mime_type, file_type, sonar_format)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            ON CONFLICT (content_hash) DO UPDATE SET last_seen = {ts}
        """

        with self.get_connection() as conn:
            cur = conn.cursor()
            for rec in file_records:
                cur.execute(sql, (
                    rec["content_hash"], rec["file_size"], rec["partial_hash"],
                    rec.get("hash_algorithm", "blake3"),
                    rec.get("mime_type"), rec.get("file_type"), rec.get("sonar_format"),
                ))
            conn.commit()

    def insert_locations_batch(self, location_records: list[dict]):
        """Batch insert canonical location records."""
        if not location_records:
            return

        ph = "%s" if self.backend == "postgresql" else "?"
        ts = "NOW()" if self.backend == "postgresql" else "datetime('now')"

        sql = f"""
            INSERT INTO locations (content_hash, nfs_server, nfs_export, remote_path,
                                  canonical_path, is_local, access_path, access_hostname,
                                  mount_source, file_name, directory, mtime, scan_id)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            ON CONFLICT (canonical_path) DO UPDATE SET
                content_hash = EXCLUDED.content_hash,
                access_path = EXCLUDED.access_path,
                access_hostname = EXCLUDED.access_hostname,
                mtime = EXCLUDED.mtime,
                scan_id = EXCLUDED.scan_id,
                discovered_at = {ts}
        """

        with self.get_connection() as conn:
            cur = conn.cursor()
            for rec in location_records:
                local_val = rec.get("is_local", False)
                if self.backend != "postgresql":
                    local_val = 1 if local_val else 0
                cur.execute(sql, (
                    rec["content_hash"], rec["nfs_server"], rec.get("nfs_export", ""),
                    rec["remote_path"], rec["canonical_path"], local_val,
                    rec["access_path"], rec["access_hostname"],
                    rec.get("mount_source", ""), rec["file_name"], rec["directory"],
                    rec.get("mtime"), rec.get("scan_id"),
                ))
            conn.commit()

    # ---------------------------------------------------------------
    # Host operations
    # ---------------------------------------------------------------

    def upsert_host(self, ip_address: str, hostname: str = None,
                    discovery_method: str = None, ssh_accessible: bool = None):
        """Insert or update a host record."""
        ph = "%s" if self.backend == "postgresql" else "?"
        ts = "NOW()" if self.backend == "postgresql" else "datetime('now')"
        bool_val = ssh_accessible if self.backend == "postgresql" else (1 if ssh_accessible else 0)

        sql = f"""
            INSERT INTO hosts (ip_address, hostname, discovery_method, ssh_accessible)
            VALUES ({ph}, {ph}, {ph}, {ph})
            ON CONFLICT (ip_address) DO UPDATE SET
                hostname = COALESCE(EXCLUDED.hostname, hosts.hostname),
                discovery_method = COALESCE(EXCLUDED.discovery_method, hosts.discovery_method),
                ssh_accessible = COALESCE(EXCLUDED.ssh_accessible, hosts.ssh_accessible),
                last_seen = {ts}
        """

        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, (ip_address, hostname, discovery_method, bool_val))
            conn.commit()

    # ---------------------------------------------------------------
    # Scan tracking
    # ---------------------------------------------------------------

    def start_scan(self, hostname: str, base_path: str) -> int:
        """Start a new scan and return scan ID."""
        ph = "%s" if self.backend == "postgresql" else "?"

        with self.get_connection() as conn:
            cur = conn.cursor()
            if self.backend == "postgresql":
                cur.execute(
                    f"INSERT INTO scans (hostname, base_path) VALUES ({ph}, {ph}) RETURNING id",
                    (hostname, base_path)
                )
                scan_id = cur.fetchone()[0]
            else:
                cur.execute(
                    f"INSERT INTO scans (hostname, base_path) VALUES ({ph}, {ph})",
                    (hostname, base_path)
                )
                scan_id = cur.lastrowid
            conn.commit()
            return scan_id

    def update_scan(self, scan_id: int, **kwargs):
        """Update scan record with progress/completion info."""
        if not kwargs:
            return
        ph = "%s" if self.backend == "postgresql" else "?"
        sets = []
        vals = []
        for key, val in kwargs.items():
            sets.append(f"{key} = {ph}")
            vals.append(val)
        vals.append(scan_id)
        sql = f"UPDATE scans SET {', '.join(sets)} WHERE id = {ph}"

        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, vals)
            conn.commit()

    def get_known_files_for_host(self, access_hostname: str) -> dict[str, tuple[str, str]]:
        """
        Get all known files accessible from a host as {access_path: (content_hash, mtime)}.
        Used for incremental scanning.
        """
        ph = "%s" if self.backend == "postgresql" else "?"
        sql = f"""
            SELECT access_path, content_hash, mtime
            FROM locations WHERE access_hostname = {ph}
        """
        result = {}
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, (access_hostname,))
            for row in cur.fetchall():
                result[row[0]] = (row[1], row[2])
        return result

    # ---------------------------------------------------------------
    # Search / query
    # ---------------------------------------------------------------

    def search_files(
        self,
        path_pattern: str = None,
        filename_pattern: str = None,
        nfs_server: str = None,
        mime_type: str = None,
        sonar_format: str = None,
        min_size: int = None,
        max_size: int = None,
        content_hash: str = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Search the catalog. Returns file + canonical location info."""
        ph = "%s" if self.backend == "postgresql" else "?"
        conditions = []
        params = []

        if content_hash:
            conditions.append(f"f.content_hash = {ph}")
            params.append(content_hash)

        if nfs_server:
            if self.backend == "postgresql":
                conditions.append(f"l.nfs_server ILIKE {ph}")
                params.append(f"%{nfs_server}%")
            else:
                conditions.append(f"l.nfs_server LIKE {ph}")
                params.append(f"%{nfs_server}%")

        if path_pattern:
            like = "ILIKE" if self.backend == "postgresql" else "LIKE"
            conditions.append(f"(l.canonical_path {like} {ph} OR l.access_path {like} {ph})")
            params.extend([f"%{path_pattern}%", f"%{path_pattern}%"])

        if filename_pattern:
            like = "ILIKE" if self.backend == "postgresql" else "LIKE"
            conditions.append(f"l.file_name {like} {ph}")
            params.append(f"%{filename_pattern}%")

        if mime_type:
            like = "ILIKE" if self.backend == "postgresql" else "LIKE"
            conditions.append(f"f.mime_type {like} {ph}")
            params.append(f"%{mime_type}%")

        if sonar_format:
            conditions.append(f"f.sonar_format = {ph}")
            params.append(sonar_format)

        if min_size is not None:
            conditions.append(f"f.file_size >= {ph}")
            params.append(min_size)
        if max_size is not None:
            conditions.append(f"f.file_size <= {ph}")
            params.append(max_size)

        where = "WHERE " + " AND ".join(conditions) if conditions else ""

        sql = f"""
            SELECT f.content_hash, f.file_size, f.mime_type, f.file_type,
                   f.sonar_format, f.hash_algorithm,
                   l.nfs_server, l.nfs_export, l.remote_path, l.canonical_path,
                   l.is_local, l.access_path, l.access_hostname, l.mount_source,
                   l.file_name, l.directory, l.mtime, l.discovered_at
            FROM files f
            JOIN locations l ON f.content_hash = l.content_hash
            {where}
            ORDER BY l.discovered_at DESC
            LIMIT {ph} OFFSET {ph}
        """
        params.extend([limit, offset])

        results = []
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            for row in cur.fetchall():
                results.append({
                    "content_hash": row[0],
                    "file_size": row[1],
                    "mime_type": row[2],
                    "file_type": row[3],
                    "sonar_format": row[4],
                    "hash_algorithm": row[5],
                    "nfs_server": row[6],
                    "nfs_export": row[7],
                    "remote_path": row[8],
                    "canonical_path": row[9],
                    "is_local": row[10],
                    "access_path": row[11],
                    "access_hostname": row[12],
                    "mount_source": row[13],
                    "file_name": row[14],
                    "directory": row[15],
                    "mtime": row[16],
                    "discovered_at": row[17],
                })
        return results

    def find_duplicates(self, min_count: int = 2, limit: int = 100) -> list[dict]:
        """Find files that exist on multiple NFS servers."""
        ph = "%s" if self.backend == "postgresql" else "?"

        sql = f"""
            SELECT f.content_hash, f.file_size, f.mime_type, f.sonar_format,
                   COUNT(DISTINCT l.nfs_server) as server_count,
                   COUNT(l.id) as location_count
            FROM files f
            JOIN locations l ON f.content_hash = l.content_hash
            GROUP BY f.content_hash, f.file_size, f.mime_type, f.sonar_format
            HAVING COUNT(DISTINCT l.nfs_server) >= {ph}
            ORDER BY f.file_size DESC
            LIMIT {ph}
        """

        results = []
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, (min_count, limit))
            for row in cur.fetchall():
                results.append({
                    "content_hash": row[0],
                    "file_size": row[1],
                    "mime_type": row[2],
                    "sonar_format": row[3],
                    "server_count": row[4],
                    "location_count": row[5],
                })
        return results

    def get_stats(self) -> dict:
        """Get catalog statistics."""
        stats = {}
        with self.get_connection() as conn:
            cur = conn.cursor()

            cur.execute("SELECT COUNT(*) FROM files")
            stats["unique_files"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM locations")
            stats["total_locations"] = cur.fetchone()[0]

            cur.execute("SELECT COALESCE(SUM(file_size), 0) FROM files")
            stats["unique_bytes"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT nfs_server) FROM locations")
            stats["nfs_servers_with_data"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM hosts")
            stats["total_hosts"] = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM hosts WHERE ssh_accessible = "
                + ("TRUE" if self.backend == "postgresql" else "1")
            )
            stats["accessible_hosts"] = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT sonar_format) FROM files WHERE sonar_format IS NOT NULL")
            stats["sonar_formats"] = cur.fetchone()[0]

            # Count local vs NFS
            local_col = "is_local" if self.backend == "postgresql" else "is_local"
            true_val = "TRUE" if self.backend == "postgresql" else "1"
            false_val = "FALSE" if self.backend == "postgresql" else "0"
            cur.execute(f"SELECT COUNT(*) FROM locations WHERE {local_col} = {false_val}")
            stats["nfs_locations"] = cur.fetchone()[0]
            cur.execute(f"SELECT COUNT(*) FROM locations WHERE {local_col} = {true_val}")
            stats["local_locations"] = cur.fetchone()[0]

        return stats

    def get_locations_for_hash(self, content_hash: str) -> list[dict]:
        """Get all locations where a specific file exists."""
        ph = "%s" if self.backend == "postgresql" else "?"
        sql = f"""
            SELECT nfs_server, nfs_export, remote_path, canonical_path,
                   is_local, access_path, access_hostname, mount_source,
                   file_name, directory, mtime
            FROM locations WHERE content_hash = {ph}
            ORDER BY nfs_server, remote_path
        """
        results = []
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, (content_hash,))
            for row in cur.fetchall():
                results.append({
                    "nfs_server": row[0],
                    "nfs_export": row[1],
                    "remote_path": row[2],
                    "canonical_path": row[3],
                    "is_local": row[4],
                    "access_path": row[5],
                    "access_hostname": row[6],
                    "mount_source": row[7],
                    "file_name": row[8],
                    "directory": row[9],
                    "mtime": row[10],
                })
        return results

    def close(self):
        """Close database connections."""
        if self._pg_pool:
            self._pg_pool.closeall()
        if self._sqlite_conn:
            self._sqlite_conn.close()
