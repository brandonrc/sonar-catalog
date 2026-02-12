"""
Search interface for the Sonar Catalog.

Provides both programmatic and CLI-friendly search functionality
with formatted output.
"""

import json
import logging
from typing import Optional

from .database import CatalogDB

logger = logging.getLogger(__name__)


def format_size(size_bytes: int) -> str:
    """Format byte count as human-readable string."""
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.1f} {units[i]}"


class CatalogSearch:
    """Search interface for the catalog database."""

    def __init__(self, db: CatalogDB):
        self.db = db

    def search(
        self,
        query: str = None,
        nfs_server: str = None,
        mime_type: str = None,
        sonar_format: str = None,
        min_size: int = None,
        max_size: int = None,
        content_hash: str = None,
        limit: int = 100,
        offset: int = 0,
        output_format: str = "table",  # "table", "json", "paths"
    ) -> str:
        """
        Search the catalog and return formatted results.

        The 'query' parameter does fuzzy matching against both
        file paths and filenames.
        """
        # Parse query into path/name patterns
        path_pattern = None
        filename_pattern = None

        if query:
            # If query contains '/', treat as path pattern
            if "/" in query:
                path_pattern = query
            else:
                # Search both path and filename
                path_pattern = query
                filename_pattern = query

        results = self.db.search_files(
            path_pattern=path_pattern,
            filename_pattern=filename_pattern if not path_pattern else None,
            nfs_server=nfs_server,
            mime_type=mime_type,
            sonar_format=sonar_format,
            min_size=min_size,
            max_size=max_size,
            content_hash=content_hash,
            limit=limit,
            offset=offset,
        )

        # If path search returned nothing, try filename search
        if not results and query and "/" not in query:
            results = self.db.search_files(
                filename_pattern=query,
                nfs_server=nfs_server,
                mime_type=mime_type,
                sonar_format=sonar_format,
                min_size=min_size,
                max_size=max_size,
                limit=limit,
                offset=offset,
            )

        if output_format == "json":
            return json.dumps(results, indent=2, default=str)
        elif output_format == "paths":
            return "\n".join(
                f"{r['canonical_path']}" for r in results
            )
        else:
            return self._format_table(results)

    def duplicates(
        self,
        min_count: int = 2,
        limit: int = 50,
        output_format: str = "table",
    ) -> str:
        """Find and display duplicate files across systems."""
        dupes = self.db.find_duplicates(min_count=min_count, limit=limit)

        if output_format == "json":
            return json.dumps(dupes, indent=2, default=str)

        if not dupes:
            return "No duplicates found."

        lines = []
        lines.append(f"{'Hash':<16} {'Size':>10} {'Servers':>8} {'Locations':>10} {'Format':<12}")
        lines.append("-" * 70)

        for d in dupes:
            lines.append(
                f"{d['content_hash'][:16]:<16} "
                f"{format_size(d['file_size']):>10} "
                f"{d['server_count']:>8} "
                f"{d['location_count']:>10} "
                f"{d.get('sonar_format') or '-':<12}"
            )

        return "\n".join(lines)

    def where_is(self, content_hash: str) -> str:
        """Show all locations for a given content hash."""
        locations = self.db.get_locations_for_hash(content_hash)

        if not locations:
            # Try partial hash match
            results = self.db.search_files(content_hash=content_hash, limit=1)
            if not results:
                return f"No file found with hash: {content_hash}"

        lines = []
        lines.append(f"Locations for {content_hash[:16]}...:")
        lines.append("")

        for loc in locations:
            lines.append(
                f"  {loc['canonical_path']:<40} (access: {loc['access_path']})"
            )
            if loc.get("mtime"):
                lines.append(f"  {'':40} mtime: {loc['mtime']}")

        return "\n".join(lines)

    def stats(self, output_format: str = "table") -> str:
        """Display catalog statistics."""
        s = self.db.get_stats()

        if output_format == "json":
            return json.dumps(s, indent=2, default=str)

        lines = [
            "=== Sonar Catalog Statistics ===",
            "",
            f"  Unique files:      {s['unique_files']:,}",
            f"  Total locations:   {s['total_locations']:,}",
            f"  Unique data size:  {format_size(s['unique_bytes'])}",
            f"  Dedup ratio:       {s['total_locations'] / max(s['unique_files'], 1):.1f}x",
            "",
            f"  NFS servers with data: {s['nfs_servers_with_data']}",
            f"  NFS locations:        {s['nfs_locations']}",
            f"  Local locations:      {s['local_locations']}",
            "",
            f"  Sonar formats:     {s['sonar_formats']}",
        ]
        return "\n".join(lines)

    def hosts(self, output_format: str = "table") -> str:
        """List all discovered hosts."""
        ph = "%s" if self.db.backend == "postgresql" else "?"
        results = []

        with self.db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT h.ip_address, h.hostname, h.discovery_method,
                       h.ssh_accessible, h.last_scan_at, h.scan_status,
                       COUNT(DISTINCT l.canonical_path) as file_count
                FROM hosts h
                LEFT JOIN locations l ON h.hostname = l.nfs_server
                GROUP BY h.ip_address, h.hostname, h.discovery_method,
                         h.ssh_accessible, h.last_scan_at, h.scan_status
                ORDER BY h.hostname
            """)
            for row in cur.fetchall():
                results.append({
                    "ip": row[0],
                    "hostname": row[1] or "-",
                    "method": row[2] or "-",
                    "ssh": row[3],
                    "last_scan": row[4] or "-",
                    "status": row[5] or "pending",
                    "files": row[6],
                })

        if output_format == "json":
            return json.dumps(results, indent=2, default=str)

        if not results:
            return "No hosts discovered yet."

        lines = []
        lines.append(
            f"{'IP':<16} {'Hostname':<20} {'Method':<12} {'SSH':>4} "
            f"{'Status':<10} {'Files':>8}"
        )
        lines.append("-" * 80)

        for h in results:
            ssh_str = "OK" if h["ssh"] else "NO"
            lines.append(
                f"{h['ip']:<16} {h['hostname']:<20} {h['method']:<12} "
                f"{ssh_str:>4} {h['status']:<10} {h['files']:>8}"
            )

        return "\n".join(lines)

    @staticmethod
    def _format_table(results: list[dict]) -> str:
        """Format search results as a table."""
        if not results:
            return "No results found."

        lines = []
        lines.append(
            f"{'NFS Server':<16} {'Size':>10} {'Format':<10} {'Canonical Path'}"
        )
        lines.append("-" * 100)

        for r in results:
            fmt = r.get("sonar_format") or r.get("mime_type") or "-"
            if len(fmt) > 10:
                fmt = fmt[:9] + "…"

            path = r["canonical_path"]
            if len(path) > 70:
                path = "…" + path[-69:]

            lines.append(
                f"{r['nfs_server']:<16} "
                f"{format_size(r['file_size']):>10} "
                f"{fmt:<10} "
                f"{path}"
            )

        lines.append(f"\n{len(results)} results")
        return "\n".join(lines)
