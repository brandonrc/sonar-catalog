"""REST API blueprint for the Sonar Catalog."""

from flask import Blueprint, current_app, jsonify, request

from ..search import CatalogSearch

api_bp = Blueprint("api", __name__)


def _get_db():
    return current_app.config["GET_DB"]()


@api_bp.route("/search")
def search():
    """Search the catalog."""
    q = request.args.get("q", "")
    server = request.args.get("server") or None
    fmt = request.args.get("format") or None
    min_size = request.args.get("min_size", type=int)
    max_size = request.args.get("max_size", type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)

    with _get_db() as db:
        searcher = CatalogSearch(db)
        if q and not request.args.get("hash") and db.backend != "postgresql":
            results = db.search_files_fts(
                query=q,
                nfs_server=server,
                sonar_format=fmt,
                min_size=min_size,
                max_size=max_size,
                limit=limit,
                offset=offset,
            )
        else:
            results = db.search_files(
                path_pattern=q or None,
                nfs_server=server,
                sonar_format=fmt,
                min_size=min_size,
                max_size=max_size,
                content_hash=request.args.get("hash"),
                limit=limit,
                offset=offset,
            )
    return jsonify(results)


@api_bp.route("/files/<content_hash>")
def file_detail(content_hash):
    """Get file info and all locations for a content hash."""
    with _get_db() as db:
        locations = db.get_locations_for_hash(content_hash)
        file_info = db.search_files(content_hash=content_hash, limit=1)
    if not file_info:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"file": file_info[0], "locations": locations})


@api_bp.route("/duplicates")
def duplicates():
    """Find duplicate files."""
    min_count = request.args.get("min_count", 2, type=int)
    limit = request.args.get("limit", 50, type=int)
    with _get_db() as db:
        dupes = db.find_duplicates(min_count=min_count, limit=limit)
    return jsonify(dupes)


@api_bp.route("/stats")
def stats():
    """Get catalog statistics."""
    with _get_db() as db:
        s = db.get_stats()
    return jsonify(s)


@api_bp.route("/hosts")
def hosts():
    """List discovered hosts."""
    with _get_db() as db:
        with db.get_connection() as conn:
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
            results = []
            for row in cur.fetchall():
                results.append({
                    "ip": row[0],
                    "hostname": row[1] or "-",
                    "method": row[2] or "-",
                    "ssh": bool(row[3]),
                    "last_scan": row[4] or "-",
                    "status": row[5] or "pending",
                    "files": row[6],
                })
    return jsonify(results)


@api_bp.route("/servers")
def servers():
    """Get distinct server names for filter dropdown."""
    with _get_db() as db:
        with db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT nfs_server FROM locations ORDER BY nfs_server")
            return jsonify([row[0] for row in cur.fetchall()])


@api_bp.route("/formats")
def formats():
    """Get distinct sonar formats for filter dropdown."""
    with _get_db() as db:
        with db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT DISTINCT sonar_format FROM files "
                "WHERE sonar_format IS NOT NULL ORDER BY sonar_format"
            )
            return jsonify([row[0] for row in cur.fetchall()])


# --- Geographic / Navigation endpoints ---

@api_bp.route("/geo/points")
def geo_points():
    """Get file locations as map points for the globe view."""
    lat_min = request.args.get("lat_min", type=float)
    lat_max = request.args.get("lat_max", type=float)
    lon_min = request.args.get("lon_min", type=float)
    lon_max = request.args.get("lon_max", type=float)
    fmt = request.args.get("format") or None
    limit = request.args.get("limit", 10000, type=int)

    with _get_db() as db:
        points = db.get_geo_points(
            lat_min=lat_min, lat_max=lat_max,
            lon_min=lon_min, lon_max=lon_max,
            sonar_format=fmt, limit=limit,
        )
    return jsonify(points)


@api_bp.route("/geo/track/<content_hash>")
def geo_track(content_hash):
    """Get the navigation track for a specific file."""
    with _get_db() as db:
        track_data = db.get_track(content_hash)
    if not track_data:
        return jsonify({"error": "No navigation data for this file"}), 404
    return jsonify(track_data)


@api_bp.route("/geo/bounds")
def geo_bounds():
    """Get the overall geographic bounds of all files with nav data."""
    with _get_db() as db:
        bounds = db.get_geo_bounds()
    if not bounds:
        return jsonify({"error": "No navigation data available"}), 404
    return jsonify(bounds)
