#!/usr/bin/env python3
"""
Sonar Catalog CLI - Main entry point.

Usage:
    sonar-catalog init                         Initialize database
    sonar-catalog discover                     Run host/mount discovery
    sonar-catalog crawl [PATH] [--host HOST]   Crawl and catalog files
    sonar-catalog crawl-all                    Crawl all accessible hosts
    sonar-catalog search QUERY [OPTIONS]       Search the catalog
    sonar-catalog dupes                        Find duplicate files
    sonar-catalog where HASH                   Show all locations for a file
    sonar-catalog stats                        Show catalog statistics
    sonar-catalog hosts                        List discovered hosts
    sonar-catalog config                       Show/edit configuration
"""

import argparse
import json
import logging
import os
import socket
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .config import Config, DEFAULT_CONFIG_PATH
from .database import CatalogDB
from .discovery import DiscoveryEngine
from .crawler import FileCrawler
from .mount_resolver import MountResolver
from .search import CatalogSearch, format_size


def setup_logging(level: str = "INFO", log_file: str = None):
    """Configure logging."""
    fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=fmt,
        handlers=handlers,
    )


def get_local_hostname() -> str:
    """Get the local machine's hostname."""
    return socket.gethostname()


def get_local_ip() -> str:
    """Get the local machine's primary IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------

def cmd_init(args, config: Config):
    """Initialize the database."""
    with CatalogDB(config.database) as db:
        print("Database initialized successfully.")

        # Save default config if it doesn't exist
        if not Path(DEFAULT_CONFIG_PATH).exists():
            config.save()
            print(f"Default config saved to {DEFAULT_CONFIG_PATH}")


def cmd_discover(args, config: Config):
    """Run host and mount discovery."""
    with CatalogDB(config.database) as db:
        engine = DiscoveryEngine(config.discovery)
        hosts, mounts = engine.run_full_discovery()

        # Store discovered hosts in DB
        for ip, host in hosts.items():
            db.upsert_host(
                ip_address=ip,
                hostname=host.hostname,
                discovery_method=host.discovery_method,
                ssh_accessible=host.ssh_accessible,
            )

        # Display results
        print(f"\n=== Discovery Results ===")
        print(f"Hosts found: {len(hosts)}")
        print(f"SSH accessible: {sum(1 for h in hosts.values() if h.ssh_accessible)}")
        print(f"Mount points: {len(mounts)}")

        if hosts:
            print(f"\n{'IP':<16} {'Hostname':<25} {'Method':<12} {'SSH':>4}")
            print("-" * 60)
            for ip, host in sorted(hosts.items(), key=lambda x: x[1].hostname or x[0]):
                ssh = "OK" if host.ssh_accessible else "NO"
                name = host.hostname or "-"
                print(f"{ip:<16} {name:<25} {host.discovery_method:<12} {ssh:>4}")

        if mounts:
            print(f"\n{'Local Path':<30} {'Remote':<40} {'Source':<10}")
            print("-" * 80)
            for mp in mounts:
                remote = f"{mp.remote_host}:{mp.remote_path}" if mp.remote_host else "-"
                print(f"{mp.local_path:<30} {remote:<40} {mp.source:<10}")

        # If accessible hosts found, also discover their mounts
        if args.deep:
            print("\n--- Deep discovery: checking remote autofs/fstab ---")
            for ip, host in hosts.items():
                if host.ssh_accessible:
                    remote_mounts = engine.ssh_discover_remote_mounts(host)
                    if remote_mounts:
                        print(f"\n  {host.hostname or ip}:")
                        for mp in remote_mounts:
                            remote = f"{mp.remote_host}:{mp.remote_path}" if mp.remote_host else "-"
                            print(f"    {mp.local_path:<30} {remote}")


def cmd_crawl(args, config: Config):
    """Crawl a filesystem path."""
    hostname = args.host or get_local_hostname()
    ip = args.ip or get_local_ip()
    path = os.path.abspath(args.path or ".")

    if not os.path.isdir(path):
        print(f"Error: {path} is not a directory", file=sys.stderr)
        sys.exit(1)

    with CatalogDB(config.database) as db:
        resolver = MountResolver()
        resolver.load()
        crawler = FileCrawler(db, config.crawler, config.metadata, resolver)

        print(f"Crawling {hostname}:{path} ...")
        print(f"  NFS mounts loaded: {len(resolver.get_nfs_mounts())}")
        start = datetime.now()

        def progress(stats):
            elapsed = (datetime.now() - start).total_seconds()
            rate = stats["files_found"] / max(elapsed, 1)
            print(
                f"\r  {stats['files_found']:,} found, "
                f"{stats['files_new']:,} new, "
                f"{stats['files_skipped']:,} skipped, "
                f"{format_size(stats['bytes_hashed'])} hashed "
                f"({rate:.0f} files/sec)",
                end="", flush=True
            )

        stats = crawler.crawl_local(
            base_path=path,
            hostname=hostname,
            ip_address=ip,
            access_hostname=hostname,
            progress_callback=progress,
        )

        elapsed = (datetime.now() - start).total_seconds()
        print(f"\n\nCrawl complete in {elapsed:.1f}s:")
        print(f"  Files found:    {stats.get('files_found', 0):,}")
        print(f"  New files:      {stats.get('files_new', 0):,}")
        print(f"  Skipped:        {stats.get('files_skipped', 0):,}")
        print(f"  Errors:         {stats.get('files_error', 0):,}")
        print(f"  Data hashed:    {format_size(stats.get('bytes_hashed', 0))}")


def cmd_crawl_all(args, config: Config):
    """Crawl all accessible hosts."""
    with CatalogDB(config.database) as db:
        # First discover
        engine = DiscoveryEngine(config.discovery)
        hosts, mounts = engine.run_full_discovery()

        # Store hosts
        for ip, host in hosts.items():
            db.upsert_host(
                ip_address=ip,
                hostname=host.hostname,
                discovery_method=host.discovery_method,
                ssh_accessible=host.ssh_accessible,
            )

        resolver = MountResolver()
        resolver.load()
        crawler = FileCrawler(db, config.crawler, config.metadata, resolver)
        local_hostname = get_local_hostname()
        local_ip = get_local_ip()

        # Crawl all local paths: discovered mounts + configured search paths
        local_paths = [mp.local_path for mp in mounts] + list(config.discovery.search_paths)
        for path in local_paths:
            if os.path.isdir(path):
                print(f"\n--- Crawling local: {path} ---")
                stats = crawler.crawl_local(
                    base_path=path,
                    hostname=local_hostname,
                    ip_address=local_ip,
                    access_hostname=local_hostname,
                )
                print(f"  Found {stats.get('files_found', 0):,} files, "
                      f"{stats.get('files_new', 0):,} new")

        # Crawl accessible remote hosts
        for ip, host in hosts.items():
            if host.ssh_accessible and host.ip != local_ip:
                for search_path in config.discovery.search_paths:
                    print(f"\n--- Crawling remote: {host.hostname or ip}:{search_path} ---")
                    stats = crawler.crawl_remote(
                        host_ip=ip,
                        hostname=host.hostname or ip,
                        remote_path=search_path,
                        ssh_user=config.discovery.ssh_user,
                        ssh_key=config.discovery.ssh_key_path,
                    )
                    found = stats.get("files_found", 0)
                    if found:
                        print(f"  Found {found:,} files")


def cmd_search(args, config: Config):
    """Search the catalog."""
    with CatalogDB(config.database) as db:
        searcher = CatalogSearch(db)

        # Parse size filters
        min_size = _parse_size(args.min_size) if args.min_size else None
        max_size = _parse_size(args.max_size) if args.max_size else None

        print(searcher.search(
            query=args.query,
            nfs_server=args.server,
            mime_type=args.mime,
            sonar_format=args.format,
            min_size=min_size,
            max_size=max_size,
            content_hash=args.hash,
            limit=args.limit,
            offset=args.offset,
            output_format=args.output,
        ))


def cmd_dupes(args, config: Config):
    """Find duplicate files."""
    with CatalogDB(config.database) as db:
        print(CatalogSearch(db).duplicates(
            min_count=args.min_count,
            limit=args.limit,
            output_format=args.output,
        ))


def cmd_where(args, config: Config):
    """Show all locations for a file hash."""
    with CatalogDB(config.database) as db:
        print(CatalogSearch(db).where_is(args.hash))


def cmd_stats(args, config: Config):
    """Show catalog statistics."""
    with CatalogDB(config.database) as db:
        print(CatalogSearch(db).stats(output_format=args.output))


def cmd_hosts(args, config: Config):
    """List discovered hosts."""
    with CatalogDB(config.database) as db:
        print(CatalogSearch(db).hosts(output_format=args.output))


def cmd_config(args, config: Config):
    """Show or create configuration."""
    if args.create:
        config.save(args.path)
        print(f"Config written to {args.path or DEFAULT_CONFIG_PATH}")
    else:
        from dataclasses import asdict
        print(json.dumps(asdict(config), indent=2))


def cmd_add_magic_byte(args, config: Config):
    """
    Learn a new file format's magic bytes from a sample file.

    Reads the header of the given file, extracts the first N bytes
    (default 4) at the given offset (default 0), and registers them
    as a custom signature in the config. Optionally also registers
    the file's extension as a format mapping.
    """
    sample_path = os.path.abspath(args.file)
    if not os.path.isfile(sample_path):
        print(f"Error: {sample_path} is not a file", file=sys.stderr)
        sys.exit(1)

    byte_length = args.length
    offset = args.offset
    format_name = args.format_name

    # If no format name given, derive from filename
    if not format_name:
        base = os.path.basename(sample_path)
        name, ext = os.path.splitext(base)
        # Use the extension without dot, or the filename
        format_name = ext.lstrip(".") if ext else name
        print(f"No --name given, using format name: '{format_name}'")

    # Read the magic bytes from the sample file
    try:
        with open(sample_path, "rb") as f:
            f.seek(offset)
            magic_bytes = f.read(byte_length)
    except Exception as e:
        print(f"Error reading {sample_path}: {e}", file=sys.stderr)
        sys.exit(1)

    if len(magic_bytes) < byte_length:
        print(
            f"Warning: file only has {len(magic_bytes)} bytes at offset {offset} "
            f"(requested {byte_length})",
            file=sys.stderr
        )

    hex_str = magic_bytes.hex()
    printable = "".join(
        chr(b) if 32 <= b < 127 else "." for b in magic_bytes
    )

    # Show what we found
    print(f"\nSample file:  {sample_path}")
    print(f"Format name:  {format_name}")
    print(f"Offset:       {offset}")
    print(f"Byte length:  {len(magic_bytes)}")
    print(f"Hex:          {hex_str}")
    print(f"Printable:    {printable}")

    # Build the entry
    entry = {
        "format": format_name,
        "hex_bytes": hex_str,
        "byte_length": len(magic_bytes),
        "offset": offset,
        "sample_file": sample_path,
        "description": args.description or f"Learned from {os.path.basename(sample_path)}",
    }

    # Also register the extension if present
    _, ext = os.path.splitext(sample_path)
    if ext and not args.no_extension:
        entry["extension"] = ext.lower()
        config.metadata.custom_extension_map[ext.lower()] = format_name
        print(f"Extension:    {ext.lower()} -> {format_name}")

    # Check for duplicates
    existing = [
        e for e in config.metadata.custom_magic_bytes
        if e.get("format") == format_name
    ]
    if existing:
        if args.force:
            config.metadata.custom_magic_bytes = [
                e for e in config.metadata.custom_magic_bytes
                if e.get("format") != format_name
            ]
            print(f"\nReplacing existing entry for '{format_name}'")
        else:
            print(
                f"\nWarning: format '{format_name}' already registered. "
                f"Use --force to replace.",
                file=sys.stderr
            )
            sys.exit(1)

    config.metadata.custom_magic_bytes.append(entry)
    config.save(args.config_path)

    print(f"\nSaved to {args.config_path or DEFAULT_CONFIG_PATH}")
    print(f"Total custom signatures: {len(config.metadata.custom_magic_bytes)}")


def cmd_rebuild_index(args, config: Config):
    """Rebuild the full-text search index."""
    if config.database.backend == "postgresql":
        print("FTS5 index is only used with the SQLite backend.", file=sys.stderr)
        sys.exit(1)
    with CatalogDB(config.database) as db:
        print("Rebuilding FTS5 search index...")
        db.rebuild_fts_index()
        print("Index rebuilt successfully.")


def cmd_extract_nav(args, config: Config):
    """Extract navigation data from already-cataloged files."""
    from .extractors import extract_nav
    from .crawler import detect_sonar_format, FileCrawler

    with CatalogDB(config.database) as db:
        # Determine which files to process
        if args.hash:
            files = db.search_files(content_hash=args.hash, limit=1)
        elif args.format:
            files = db.search_files(sonar_format=args.format, limit=args.limit)
        else:
            files = _get_files_without_nav(db, limit=args.limit, force=args.force)

        total = len(files)
        extracted = 0
        failed = 0

        print(f"Extracting navigation from {total} files...")

        for i, f in enumerate(files):
            access_path = f.get("access_path", "")
            if not access_path or not os.path.exists(access_path):
                locs = db.get_locations_for_hash(f["content_hash"])
                access_path = next(
                    (loc["access_path"] for loc in locs
                     if loc.get("access_path") and os.path.exists(loc["access_path"])),
                    None
                )
                if not access_path:
                    failed += 1
                    continue

            try:
                result = extract_nav(
                    access_path,
                    sonar_format=f.get("sonar_format"),
                    sidecar_config=config.metadata.nav_extraction.sidecar_patterns,
                )
                if result and result.track:
                    track = result.track
                    max_pts = config.metadata.nav_extraction.max_track_points
                    if len(track) > max_pts:
                        track = FileCrawler._downsample_track(track, max_pts)

                    lats = [p[0] for p in track]
                    lons = [p[1] for p in track]
                    db.insert_nav_data(f["content_hash"], {
                        "lat_min": min(lats), "lat_max": max(lats),
                        "lon_min": min(lons), "lon_max": max(lons),
                        "lat_center": (min(lats) + max(lats)) / 2,
                        "lon_center": (min(lons) + max(lons)) / 2,
                        "metadata": {
                            "track": track,
                            "source": result.source,
                            "point_count_original": result.point_count_original,
                            "point_count_stored": len(track),
                        },
                    })
                    extracted += 1
            except Exception as e:
                if args.verbose:
                    print(f"  Error: {access_path}: {e}")
                failed += 1

            if (i + 1) % 100 == 0:
                print(f"  {i+1}/{total} processed, {extracted} extracted", flush=True)

        print(f"\nDone: {extracted} files with nav data, {failed} failed, "
              f"{total - extracted - failed} no nav data found")


def _get_files_without_nav(db: CatalogDB, limit: int, force: bool = False) -> list[dict]:
    """Get cataloged files that don't yet have navigation data."""
    ph = db._ph
    true_val = "TRUE" if db.backend == "postgresql" else "1"

    if force:
        sql = f"""
            SELECT f.content_hash, f.sonar_format, l.access_path
            FROM files f
            JOIN locations l ON f.content_hash = l.content_hash
            WHERE f.sonar_format IS NOT NULL
            GROUP BY f.content_hash
            LIMIT {ph}
        """
    else:
        sql = f"""
            SELECT f.content_hash, f.sonar_format, l.access_path
            FROM files f
            JOIN locations l ON f.content_hash = l.content_hash
            LEFT JOIN file_metadata fm ON f.content_hash = fm.content_hash
                AND fm.has_nav = {true_val}
            WHERE fm.content_hash IS NULL
              AND f.sonar_format IS NOT NULL
            GROUP BY f.content_hash
            LIMIT {ph}
        """

    results = []
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute(sql, (limit,))
        for row in cur.fetchall():
            results.append({
                "content_hash": row[0],
                "sonar_format": row[1],
                "access_path": row[2],
            })
    return results


def cmd_demo(args, config: Config):
    """Load demo/simulation data for exploring the UI without real sonar data."""
    from .demo import load_demo_data

    with CatalogDB(config.database) as db:
        num_files = args.num_files
        seed = args.seed

        print(f"Generating demo data ({num_files} files, seed={seed})...")
        summary = load_demo_data(db, num_files=num_files, seed=seed)

        print(f"\nDemo data loaded:")
        print(f"  Files:      {summary['files']}")
        print(f"  Locations:  {summary['locations']}")
        print(f"  Nav tracks: {summary['nav_tracks']}")
        print(f"  Hosts:      {summary['hosts']}")
        print(f"\nYou can now explore with:")
        print(f"  sonar-catalog search line")
        print(f"  sonar-catalog stats")
        print(f"  sonar-catalog web")


def cmd_export(args, config: Config):
    """Export catalog data to a file."""
    from .plugins import plugin_manager, initialize_plugins

    initialize_plugins(disabled_plugins=set(config.plugins.disabled_plugins))

    format_name = args.export_format

    # List available formats
    if args.list_formats:
        all_formats = plugin_manager.call_hook("get_export_formats")
        print("Available export formats:")
        for fmt_list in all_formats:
            for fmt in fmt_list:
                print(f"  {fmt['name']:<12} {fmt['description']:<30} {fmt.get('extension', '')}")
        return

    if not format_name:
        print("Error: --format is required (use --list-formats to see options)", file=sys.stderr)
        sys.exit(1)

    with CatalogDB(config.database) as db:
        # Get data to export
        if args.geo:
            data = db.get_geo_points(limit=args.limit)
        else:
            data = db.search_files(
                sonar_format=args.sonar_format,
                nfs_server=args.server,
                limit=args.limit,
            )

        if not data:
            print("No data to export.")
            return

        result = plugin_manager.call_hook(
            "export_data",
            data=data,
            format_name=format_name,
            output_path=args.output,
        )

        if result is None:
            print(f"Error: no exporter found for format '{format_name}'", file=sys.stderr)
            sys.exit(1)

        if args.output:
            print(f"Exported {len(data)} records to {args.output}")
        else:
            print(result)


def cmd_web(args, config: Config):
    """Start the web interface."""
    try:
        from .web import create_app
    except ImportError:
        print("Flask is not installed. Install with: pip install sonar-catalog[web]",
              file=sys.stderr)
        sys.exit(1)

    app = create_app(config)
    print(f"Starting Sonar Catalog at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


def cmd_plugins(args, config: Config):
    """List, enable, or disable plugins."""
    from .plugins import plugin_manager, initialize_plugins

    initialize_plugins(disabled_plugins=set(config.plugins.disabled_plugins))

    if args.plugins_action == "list":
        plugins = plugin_manager.list_plugins()
        disabled = set(config.plugins.disabled_plugins)

        if not plugins and not disabled:
            print("No plugins registered.")
            return

        print(f"{'Plugin':<25} {'Version':<10} {'Status':<10} {'Hooks'}")
        print("-" * 70)
        for name, info in sorted(plugins.items()):
            status = "enabled" if info.enabled else "disabled"
            hooks = ", ".join(info.hooks) if info.hooks else "-"
            print(f"{name:<25} {info.version:<10} {status:<10} {hooks}")

        # Show disabled plugins not in the loaded list
        for name in sorted(disabled):
            if name not in plugins:
                print(f"{name:<25} {'?':<10} {'disabled':<10} -")

    elif args.plugins_action == "enable":
        name = args.plugin_name
        if name in config.plugins.disabled_plugins:
            config.plugins.disabled_plugins.remove(name)
            config.save()
            print(f"Enabled plugin: {name}")
            print("Restart to apply changes.")
        else:
            print(f"Plugin '{name}' is not in the disabled list.")

    elif args.plugins_action == "disable":
        name = args.plugin_name
        if name == "builtin":
            print("Warning: disabling the built-in plugin will remove all "
                  "default format detection and nav extraction.", file=sys.stderr)
        if name not in config.plugins.disabled_plugins:
            config.plugins.disabled_plugins.append(name)
            config.save()
            print(f"Disabled plugin: {name}")
            print("Restart to apply changes.")
        else:
            print(f"Plugin '{name}' is already disabled.")

    elif args.plugins_action == "info":
        name = args.plugin_name
        info = plugin_manager.get_plugin(name)
        if not info:
            print(f"Plugin '{name}' not found.", file=sys.stderr)
            sys.exit(1)
        print(f"Name:        {info.name}")
        print(f"Version:     {info.version}")
        print(f"Description: {info.description}")
        print(f"Enabled:     {info.enabled}")
        print(f"Hooks:       {', '.join(info.hooks) if info.hooks else 'none'}")


def cmd_list_magic_bytes(args, config: Config):
    """List all registered magic byte signatures (built-in + custom)."""
    from .plugins.builtin.formats import SONAR_SIGNATURES, EXTENSION_TO_FORMAT

    print("=== Built-in Magic Byte Signatures ===")
    for sig, fmt in SONAR_SIGNATURES.items():
        hex_str = sig.hex()
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in sig)
        print(f"  {fmt:<16} hex={hex_str:<12} ascii={printable}")

    print(f"\n=== Built-in Extension Map ({len(EXTENSION_TO_FORMAT)} entries) ===")
    for ext, fmt in sorted(EXTENSION_TO_FORMAT.items()):
        print(f"  {ext:<10} -> {fmt}")

    custom = config.metadata.custom_magic_bytes
    if custom:
        print(f"\n=== Custom Magic Byte Signatures ({len(custom)}) ===")
        for entry in custom:
            hex_bytes = entry.get("hex_bytes", "")
            raw = bytes.fromhex(hex_bytes)
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            print(
                f"  {entry.get('format', '?'):<16} "
                f"hex={hex_bytes:<12} "
                f"offset={entry.get('offset', 0)} "
                f"len={entry.get('byte_length', 0)} "
                f"ascii={printable}"
            )
            if entry.get("extension"):
                print(f"  {'':16} extension={entry['extension']}")
            if entry.get("description"):
                print(f"  {'':16} {entry['description']}")
    else:
        print("\n=== Custom Magic Byte Signatures ===")
        print("  (none registered — use 'sonar-catalog config add-magic-byte' to add)")

    custom_ext = config.metadata.custom_extension_map
    if custom_ext:
        print(f"\n=== Custom Extension Map ({len(custom_ext)}) ===")
        for ext, fmt in sorted(custom_ext.items()):
            print(f"  {ext:<10} -> {fmt}")


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

def _parse_size(size_str: str) -> int:
    """Parse human-readable size string (e.g., '10MB', '1.5GB') to bytes."""
    size_str = size_str.strip().upper()
    multipliers = {
        "B": 1, "K": 1024, "KB": 1024,
        "M": 1024**2, "MB": 1024**2,
        "G": 1024**3, "GB": 1024**3,
        "T": 1024**4, "TB": 1024**4,
        "P": 1024**5, "PB": 1024**5,
    }

    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(suffix):
            num = size_str[:-len(suffix)].strip()
            return int(float(num) * mult)

    return int(size_str)


# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="sonar-catalog",
        description="Petabyte-scale sonar file catalog with deduplication",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", "-c", default=None, help="Config file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    subparsers.add_parser("init", help="Initialize database and config")

    # discover
    p_discover = subparsers.add_parser("discover", help="Discover hosts and mounts")
    p_discover.add_argument("--deep", action="store_true",
                           help="Also discover remote host mounts via SSH")

    # crawl
    p_crawl = subparsers.add_parser("crawl", help="Crawl and catalog a path")
    p_crawl.add_argument("path", nargs="?", default=".",
                         help="Path to crawl (default: current directory)")
    p_crawl.add_argument("--host", help="Hostname for this path")
    p_crawl.add_argument("--ip", help="IP address for this host")

    # crawl-all
    subparsers.add_parser("crawl-all", help="Discover and crawl all accessible hosts")

    # search
    p_search = subparsers.add_parser("search", help="Search the catalog")
    p_search.add_argument("query", nargs="?", help="Search query (path or filename pattern)")
    p_search.add_argument("--server", "-s", help="Filter by NFS server name")
    p_search.add_argument("--mime", help="Filter by MIME type")
    p_search.add_argument("--format", "-f", help="Filter by sonar format")
    p_search.add_argument("--min-size", help="Minimum file size (e.g., 10MB)")
    p_search.add_argument("--max-size", help="Maximum file size (e.g., 1GB)")
    p_search.add_argument("--hash", help="Search by content hash")
    p_search.add_argument("--limit", type=int, default=100, help="Max results")
    p_search.add_argument("--offset", type=int, default=0, help="Result offset")
    p_search.add_argument("--output", "-o", choices=["table", "json", "paths"],
                         default="table", help="Output format")

    # dupes
    p_dupes = subparsers.add_parser("dupes", help="Find duplicate files")
    p_dupes.add_argument("--min-count", type=int, default=2,
                         help="Minimum host count to be a duplicate")
    p_dupes.add_argument("--limit", type=int, default=50, help="Max results")
    p_dupes.add_argument("--output", "-o", choices=["table", "json"],
                         default="table", help="Output format")

    # where
    p_where = subparsers.add_parser("where", help="Show all locations for a file")
    p_where.add_argument("hash", help="Content hash (full or prefix)")

    # stats
    p_stats = subparsers.add_parser("stats", help="Catalog statistics")
    p_stats.add_argument("--output", "-o", choices=["table", "json"],
                         default="table", help="Output format")

    # hosts
    p_hosts = subparsers.add_parser("hosts", help="List discovered hosts")
    p_hosts.add_argument("--output", "-o", choices=["table", "json"],
                         default="table", help="Output format")

    # config
    p_config = subparsers.add_parser("config", help="Show/create config")
    p_config.add_argument("--create", action="store_true",
                         help="Create default config file")
    p_config.add_argument("--path", help="Config file path")

    # add-magic-byte — learn a new format from a sample file
    p_magic = subparsers.add_parser(
        "add-magic-byte",
        help="Learn a file format's magic bytes from a sample file"
    )
    p_magic.add_argument("file", help="Path to a sample file of this format")
    p_magic.add_argument("--name", dest="format_name",
                         help="Format name (default: derived from file extension)")
    p_magic.add_argument("--length", "-l", type=int, default=4,
                         help="Number of magic bytes to capture (default: 4)")
    p_magic.add_argument("--offset", type=int, default=0,
                         help="Byte offset in file where signature starts (default: 0)")
    p_magic.add_argument("--description", "-d",
                         help="Human-readable description of this format")
    p_magic.add_argument("--no-extension", action="store_true",
                         help="Don't register the file extension as a format mapping")
    p_magic.add_argument("--force", action="store_true",
                         help="Replace existing entry for this format name")
    p_magic.add_argument("--config-path", default=None,
                         help="Config file to save to (default: standard location)")

    # list-magic-bytes — show all registered signatures
    subparsers.add_parser(
        "list-magic-bytes",
        help="List all registered magic byte signatures (built-in + custom)"
    )

    # extract-nav
    p_extract = subparsers.add_parser("extract-nav",
        help="Extract navigation/position data from cataloged sonar files")
    p_extract.add_argument("--hash", help="Extract for a single file by content hash")
    p_extract.add_argument("--format", "-f", help="Extract for all files of a sonar format")
    p_extract.add_argument("--limit", type=int, default=10000,
        help="Max files to process (default: 10000)")
    p_extract.add_argument("--force", action="store_true",
        help="Re-extract even if nav data already exists")

    # plugins
    p_plugins = subparsers.add_parser("plugins", help="Manage plugins")
    p_plugins_sub = p_plugins.add_subparsers(dest="plugins_action")
    p_plugins_sub.add_parser("list", help="List all registered plugins")
    p_plugins_enable = p_plugins_sub.add_parser("enable", help="Enable a plugin")
    p_plugins_enable.add_argument("plugin_name", help="Plugin name to enable")
    p_plugins_disable = p_plugins_sub.add_parser("disable", help="Disable a plugin")
    p_plugins_disable.add_argument("plugin_name", help="Plugin name to disable")
    p_plugins_info = p_plugins_sub.add_parser("info", help="Show plugin details")
    p_plugins_info.add_argument("plugin_name", help="Plugin name")

    # demo
    p_demo = subparsers.add_parser("demo", help="Load synthetic demo data for exploring the UI")
    p_demo.add_argument("--num-files", type=int, default=500,
                        help="Number of synthetic files to generate (default: 500)")
    p_demo.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility (default: 42)")

    # export
    p_export = subparsers.add_parser("export", help="Export catalog data to a file")
    p_export.add_argument("--format", dest="export_format",
                          help="Export format (csv, geojson, json)")
    p_export.add_argument("--output", "-o", help="Output file path (omit for stdout)")
    p_export.add_argument("--limit", type=int, default=10000, help="Max records to export")
    p_export.add_argument("--geo", action="store_true",
                          help="Export geographic points instead of file records")
    p_export.add_argument("--server", help="Filter by NFS server")
    p_export.add_argument("--sonar-format", help="Filter by sonar format")
    p_export.add_argument("--list-formats", action="store_true",
                          help="List available export formats")

    # rebuild-index
    subparsers.add_parser("rebuild-index", help="Rebuild FTS5 search index from existing data")

    # web
    p_web = subparsers.add_parser("web", help="Start the web interface")
    p_web.add_argument("--port", "-p", type=int, default=8080, help="Port (default: 8080)")
    p_web.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p_web.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Set up logging
    log_level = "DEBUG" if args.verbose else ("WARNING" if args.quiet else "INFO")

    # Load config
    config_path = args.config
    config = Config.load(config_path)
    setup_logging(log_level, config.log_file)

    # Initialize plugin system
    from .plugins import initialize_plugins
    initialize_plugins(disabled_plugins=set(config.plugins.disabled_plugins))

    # Dispatch
    commands = {
        "init": cmd_init,
        "discover": cmd_discover,
        "crawl": cmd_crawl,
        "crawl-all": cmd_crawl_all,
        "search": cmd_search,
        "dupes": cmd_dupes,
        "where": cmd_where,
        "stats": cmd_stats,
        "hosts": cmd_hosts,
        "config": cmd_config,
        "add-magic-byte": cmd_add_magic_byte,
        "list-magic-bytes": cmd_list_magic_bytes,
        "plugins": cmd_plugins,
        "extract-nav": cmd_extract_nav,
        "rebuild-index": cmd_rebuild_index,
        "demo": cmd_demo,
        "export": cmd_export,
        "web": cmd_web,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        try:
            cmd_func(args, config)
        except KeyboardInterrupt:
            print("\nInterrupted.", file=sys.stderr)
            sys.exit(130)
        except Exception as e:
            if args.verbose:
                import traceback
                traceback.print_exc()
            else:
                print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
