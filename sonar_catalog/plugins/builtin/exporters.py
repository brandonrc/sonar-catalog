"""
Built-in data export hooks.

Provides CSV, GeoJSON, and JSON export capabilities through the plugin
hook system so third-party plugins can add their own export formats.
"""

import csv
import json
import logging
import io
from typing import Optional

logger = logging.getLogger(__name__)


def _get_export_formats():
    """Hook impl: return built-in export format descriptors."""
    return [
        {"name": "csv", "description": "Comma-separated values", "extension": ".csv"},
        {"name": "geojson", "description": "GeoJSON FeatureCollection", "extension": ".geojson"},
        {"name": "json", "description": "JSON array", "extension": ".json"},
    ]


def _export_data(data=None, format_name=None, output_path=None, **kwargs):
    """
    Hook impl: export catalog data to a file.

    Args:
        data: list of dicts to export
        format_name: "csv", "geojson", or "json"
        output_path: file path to write to (or None for stdout string)
    """
    if not data or format_name not in ("csv", "geojson", "json"):
        return None

    if format_name == "csv":
        return _export_csv(data, output_path)
    elif format_name == "geojson":
        return _export_geojson(data, output_path)
    elif format_name == "json":
        return _export_json(data, output_path)

    return None


def _export_csv(data: list[dict], output_path: Optional[str] = None) -> str:
    """Export data as CSV."""
    if not data:
        return ""

    fieldnames = list(data[0].keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in data:
        writer.writerow(row)

    content = buf.getvalue()
    if output_path:
        with open(output_path, "w", newline="") as f:
            f.write(content)
    return content


def _export_geojson(data: list[dict], output_path: Optional[str] = None) -> str:
    """Export data as GeoJSON FeatureCollection."""
    features = []
    for item in data:
        lat = item.get("lat") or item.get("lat_center")
        lon = item.get("lon") or item.get("lon_center")
        if lat is None or lon is None:
            continue

        properties = {k: v for k, v in item.items()
                      if k not in ("lat", "lon", "lat_center", "lon_center")}

        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": properties,
        })

    collection = {"type": "FeatureCollection", "features": features}
    content = json.dumps(collection, indent=2, default=str)

    if output_path:
        with open(output_path, "w") as f:
            f.write(content)
    return content


def _export_json(data: list[dict], output_path: Optional[str] = None) -> str:
    """Export data as JSON array."""
    content = json.dumps(data, indent=2, default=str)
    if output_path:
        with open(output_path, "w") as f:
            f.write(content)
    return content


def register_export_hooks(manager):
    """Register export hooks with the plugin manager."""
    from . import PLUGIN_NAME

    manager.register_hook_impl(
        "get_export_formats", PLUGIN_NAME, _get_export_formats,
    )
    manager.register_hook_impl(
        "export_data", PLUGIN_NAME, _export_data,
        priority=100,
    )
