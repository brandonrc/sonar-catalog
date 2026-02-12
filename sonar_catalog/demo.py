"""
Demo/simulation data generator for sonar-catalog.

Generates realistic synthetic sonar catalog data — files, locations,
nav tracks, and hosts — so developers can explore the web UI and
API without real sonar data.
"""

import hashlib
import math
import random
from datetime import datetime, timedelta

# Simulated survey regions around the world
SURVEY_REGIONS = [
    {"name": "North Sea Survey", "lat": 56.0, "lon": 3.0, "radius": 2.0},
    {"name": "Gulf of Mexico", "lat": 28.0, "lon": -90.0, "radius": 3.0},
    {"name": "Mediterranean", "lat": 36.0, "lon": 15.0, "radius": 2.5},
    {"name": "Norwegian Fjords", "lat": 62.0, "lon": 6.0, "radius": 1.5},
    {"name": "Great Barrier Reef", "lat": -18.0, "lon": 147.0, "radius": 2.0},
    {"name": "Chesapeake Bay", "lat": 37.5, "lon": -76.0, "radius": 1.0},
    {"name": "Puget Sound", "lat": 47.5, "lon": -122.5, "radius": 0.8},
    {"name": "Tokyo Bay", "lat": 35.4, "lon": 139.8, "radius": 0.5},
]

FORMATS = ["xtf", "jsf", "s7k", "all", "kmall", "segy", "bag", "csv"]

SERVERS = [
    "sonar-nas-01", "sonar-nas-02", "survey-store-01",
    "archive-server", "field-ws-01", "field-ws-02",
]

EXTENSIONS = {
    "xtf": ".xtf", "jsf": ".jsf", "s7k": ".s7k", "all": ".all",
    "kmall": ".kmall", "segy": ".sgy", "bag": ".bag", "csv": ".csv",
}

LINE_PREFIXES = [
    "line", "track", "survey", "profile", "swath", "run",
    "transect", "leg", "pass", "sweep",
]

PROJECT_NAMES = [
    "pipeline_inspection_2024", "harbor_survey_Q3", "reef_mapping",
    "channel_dredge_monitor", "wreck_search_zone_A", "geohazard_study",
    "cable_route_survey", "bathymetry_update", "sar_calibration",
    "seafloor_habitat_map", "oil_lease_block_42", "coastal_erosion",
]


def _make_hash(seed: str) -> str:
    """Generate a deterministic content hash from a seed string."""
    return hashlib.blake2b(seed.encode(), digest_size=32).hexdigest()


def _generate_track(center_lat, center_lon, radius, num_points=50):
    """Generate a realistic-looking survey track (zigzag pattern)."""
    track = []
    # Simulate a zigzag survey pattern
    num_lines = random.randint(3, 8)
    pts_per_line = max(2, num_points // num_lines)

    lat_start = center_lat - radius * 0.3
    lat_end = center_lat + radius * 0.3
    lon_start = center_lon - radius * 0.3
    lon_end = center_lon + radius * 0.3

    for i in range(num_lines):
        frac = i / max(1, num_lines - 1)
        lon = lon_start + frac * (lon_end - lon_start)

        for j in range(pts_per_line):
            jfrac = j / max(1, pts_per_line - 1)
            if i % 2 == 0:
                lat = lat_start + jfrac * (lat_end - lat_start)
            else:
                lat = lat_end - jfrac * (lat_end - lat_start)

            # Add small jitter for realism
            lat += random.gauss(0, 0.001)
            lon += random.gauss(0, 0.001)
            track.append([round(lat, 6), round(lon, 6)])

    return track


def generate_demo_data(
    num_files: int = 500,
    num_hosts: int = 4,
    seed: int = 42,
) -> dict:
    """
    Generate synthetic catalog data.

    Returns dict with keys: files, locations, nav_data, hosts
    ready for batch insertion into the database.
    """
    random.seed(seed)

    files = []
    locations = []
    nav_data = []
    hosts = []

    # Generate hosts
    used_servers = SERVERS[:num_hosts]
    for i, server in enumerate(used_servers):
        hosts.append({
            "ip_address": f"192.168.1.{10 + i}",
            "hostname": server,
            "discovery_method": "autofs",
            "ssh_accessible": True,
        })

    # Generate files across survey regions
    for idx in range(num_files):
        region = random.choice(SURVEY_REGIONS)
        fmt = random.choice(FORMATS)
        ext = EXTENSIONS.get(fmt, f".{fmt}")
        project = random.choice(PROJECT_NAMES)
        prefix = random.choice(LINE_PREFIXES)
        line_num = random.randint(1, 999)
        file_name = f"{prefix}_{line_num:03d}{ext}"

        content_hash = _make_hash(f"file_{idx}_{file_name}")
        file_size = random.randint(50_000, 2_000_000_000)  # 50KB to 2GB
        partial_hash = _make_hash(f"partial_{idx}")

        files.append({
            "content_hash": content_hash,
            "file_size": file_size,
            "partial_hash": partial_hash,
            "hash_algorithm": "blake2b",
            "sonar_format": fmt,
        })

        # Generate 1-3 locations per file (simulating copies across servers)
        num_copies = random.choices([1, 2, 3], weights=[60, 30, 10])[0]
        servers_for_file = random.sample(used_servers, min(num_copies, len(used_servers)))

        for server in servers_for_file:
            export_path = random.choice(["/data", "/survey", "/export/sonar"])
            remote_path = f"{export_path}/{project}/{file_name}"
            canonical = f"{server}:{remote_path}"

            days_ago = random.randint(1, 730)
            mtime = (datetime.now() - timedelta(days=days_ago)).isoformat()

            locations.append({
                "content_hash": content_hash,
                "nfs_server": server,
                "nfs_export": export_path,
                "remote_path": remote_path,
                "canonical_path": canonical,
                "is_local": False,
                "access_path": f"/mnt/{server}{remote_path}",
                "access_hostname": "localhost",
                "file_name": file_name,
                "directory": f"{export_path}/{project}",
                "mtime": mtime,
                "sonar_format": fmt,
            })

        # Generate nav data for ~70% of files (sonar files with position data)
        if fmt in ("xtf", "jsf", "s7k", "all", "kmall") and random.random() < 0.7:
            track = _generate_track(
                region["lat"], region["lon"], region["radius"],
                num_points=random.randint(20, 200),
            )
            lats = [p[0] for p in track]
            lons = [p[1] for p in track]

            sources = {"xtf": "xtf_pingheader", "jsf": "jsf_nav", "s7k": "s7k_position",
                        "all": "all_position", "kmall": "kmall_spo"}

            nav_data.append({
                "content_hash": content_hash,
                "lat_min": min(lats),
                "lat_max": max(lats),
                "lon_min": min(lons),
                "lon_max": max(lons),
                "lat_center": (min(lats) + max(lats)) / 2,
                "lon_center": (min(lons) + max(lons)) / 2,
                "metadata": {
                    "track": track,
                    "source": sources.get(fmt, "unknown"),
                    "point_count_original": len(track) * random.randint(5, 50),
                    "point_count_stored": len(track),
                },
            })

    return {
        "files": files,
        "locations": locations,
        "nav_data": nav_data,
        "hosts": hosts,
    }


def load_demo_data(db, num_files: int = 500, seed: int = 42):
    """Generate and load demo data into a database."""
    data = generate_demo_data(num_files=num_files, seed=seed)

    db.insert_files_batch(data["files"])
    db.insert_locations_batch(data["locations"])

    for host in data["hosts"]:
        db.upsert_host(**host)

    if data["nav_data"]:
        db.insert_nav_data_batch(data["nav_data"])

    return {
        "files": len(data["files"]),
        "locations": len(data["locations"]),
        "nav_tracks": len(data["nav_data"]),
        "hosts": len(data["hosts"]),
    }
