"""Sidecar/companion file extractor for navigation data."""

import csv
import json
import logging
from pathlib import Path
from typing import Optional

from .base import NavExtractor, NavResult

logger = logging.getLogger(__name__)


class SidecarExtractor(NavExtractor):
    """
    Extract navigation from companion files next to sonar data.

    Supports configurable patterns like:
        {"pattern": "{stem}.nav", "format": "csv",
         "lat_field": "lat", "lon_field": "lon", "delimiter": ","}
    """

    supported_formats = []  # handles all formats (sidecar is format-agnostic)

    def __init__(self, sidecar_patterns: list[dict] = None):
        self._patterns = sidecar_patterns or []

    def can_handle(self, file_path: str, sonar_format: Optional[str] = None) -> bool:
        return bool(self._patterns)

    def extract(self, file_path: str, sonar_format: Optional[str] = None) -> Optional[NavResult]:
        p = Path(file_path)
        stem = p.stem
        name = p.name
        parent = p.parent

        for cfg in self._patterns:
            pattern = cfg.get("pattern", "")
            resolved = pattern.format(stem=stem, name=name, dir=str(parent))
            sidecar_path = parent / resolved

            if sidecar_path.exists():
                try:
                    result = self._parse_sidecar(str(sidecar_path), cfg)
                    if result and result.track:
                        return result
                except Exception as e:
                    logger.debug(f"Sidecar parse error {sidecar_path}: {e}")
                    continue

        return None

    def _parse_sidecar(self, path: str, cfg: dict) -> Optional[NavResult]:
        fmt = cfg.get("format", "csv")
        if fmt == "csv":
            return self._parse_csv(path, cfg)
        elif fmt == "json":
            return self._parse_json(path, cfg)
        return None

    def _parse_csv(self, path: str, cfg: dict) -> Optional[NavResult]:
        """Parse CSV/delimited nav file."""
        lat_field = cfg.get("lat_field", "lat")
        lon_field = cfg.get("lon_field", "lon")
        delimiter = cfg.get("delimiter", ",")

        track = []
        with open(path, "r") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                try:
                    lat = float(row[lat_field])
                    lon = float(row[lon_field])
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        track.append([lat, lon])
                except (KeyError, ValueError):
                    continue

        if track:
            return NavResult(
                track=track,
                source=f"sidecar:{Path(path).name}",
                point_count_original=len(track),
            )
        return None

    def _parse_json(self, path: str, cfg: dict) -> Optional[NavResult]:
        """Parse JSON sidecar file with nav data."""
        lat_field = cfg.get("lat_field", "lat")
        lon_field = cfg.get("lon_field", "lon")
        track_field = cfg.get("track_field", "track")

        with open(path, "r") as f:
            data = json.load(f)

        track = []

        # Try array of points in a track field
        if track_field in data and isinstance(data[track_field], list):
            for pt in data[track_field]:
                if isinstance(pt, dict):
                    try:
                        lat = float(pt[lat_field])
                        lon = float(pt[lon_field])
                        if -90 <= lat <= 90 and -180 <= lon <= 180:
                            track.append([lat, lon])
                    except (KeyError, ValueError):
                        continue
                elif isinstance(pt, (list, tuple)) and len(pt) >= 2:
                    try:
                        lat, lon = float(pt[0]), float(pt[1])
                        if -90 <= lat <= 90 and -180 <= lon <= 180:
                            track.append([lat, lon])
                    except (ValueError, IndexError):
                        continue

        # Fall back to single point
        if not track and lat_field in data and lon_field in data:
            try:
                lat = float(data[lat_field])
                lon = float(data[lon_field])
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    track.append([lat, lon])
            except (ValueError, TypeError):
                pass

        if track:
            return NavResult(
                track=track,
                source=f"sidecar:{Path(path).name}",
                point_count_original=len(track),
            )
        return None
