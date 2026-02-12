"""Tests for the export plugin hooks."""

import csv
import json
import io
import os
import pytest

from sonar_catalog.plugins.builtin.exporters import (
    _export_csv, _export_geojson, _export_json,
    _export_data, _get_export_formats,
)


SAMPLE_DATA = [
    {"content_hash": "abc123", "file_size": 1024, "sonar_format": "xtf",
     "file_name": "line_001.xtf"},
    {"content_hash": "def456", "file_size": 2048, "sonar_format": "jsf",
     "file_name": "track_002.jsf"},
]

SAMPLE_GEO_DATA = [
    {"content_hash": "abc123", "lat": 56.0, "lon": 3.0,
     "sonar_format": "xtf", "file_name": "line_001.xtf"},
    {"content_hash": "def456", "lat": 28.0, "lon": -90.0,
     "sonar_format": "jsf", "file_name": "track_002.jsf"},
]


class TestGetExportFormats:
    def test_returns_formats(self):
        formats = _get_export_formats()
        assert isinstance(formats, list)
        names = [f["name"] for f in formats]
        assert "csv" in names
        assert "geojson" in names
        assert "json" in names

    def test_format_has_required_fields(self):
        for fmt in _get_export_formats():
            assert "name" in fmt
            assert "description" in fmt
            assert "extension" in fmt


class TestExportCSV:
    def test_csv_output(self):
        result = _export_csv(SAMPLE_DATA)
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["content_hash"] == "abc123"
        assert rows[1]["sonar_format"] == "jsf"

    def test_csv_to_file(self, tmp_path):
        out = str(tmp_path / "test.csv")
        _export_csv(SAMPLE_DATA, out)
        assert os.path.exists(out)
        with open(out) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2

    def test_csv_empty(self):
        assert _export_csv([]) == ""


class TestExportGeoJSON:
    def test_geojson_structure(self):
        result = _export_geojson(SAMPLE_GEO_DATA)
        data = json.loads(result)
        assert data["type"] == "FeatureCollection"
        assert len(data["features"]) == 2
        for feature in data["features"]:
            assert feature["type"] == "Feature"
            assert feature["geometry"]["type"] == "Point"
            assert len(feature["geometry"]["coordinates"]) == 2

    def test_geojson_coordinates(self):
        result = _export_geojson(SAMPLE_GEO_DATA)
        data = json.loads(result)
        # GeoJSON coordinates are [lon, lat]
        assert data["features"][0]["geometry"]["coordinates"] == [3.0, 56.0]

    def test_geojson_properties(self):
        result = _export_geojson(SAMPLE_GEO_DATA)
        data = json.loads(result)
        props = data["features"][0]["properties"]
        assert props["content_hash"] == "abc123"
        assert "lat" not in props  # lat/lon should be in geometry, not properties

    def test_geojson_to_file(self, tmp_path):
        out = str(tmp_path / "test.geojson")
        _export_geojson(SAMPLE_GEO_DATA, out)
        assert os.path.exists(out)

    def test_geojson_skips_no_coords(self):
        data = [{"content_hash": "abc", "file_name": "test.xtf"}]
        result = _export_geojson(data)
        fc = json.loads(result)
        assert len(fc["features"]) == 0

    def test_geojson_uses_lat_center(self):
        data = [{"content_hash": "x", "lat_center": 10.0, "lon_center": 20.0}]
        result = _export_geojson(data)
        fc = json.loads(result)
        assert len(fc["features"]) == 1
        assert fc["features"][0]["geometry"]["coordinates"] == [20.0, 10.0]


class TestExportJSON:
    def test_json_output(self):
        result = _export_json(SAMPLE_DATA)
        data = json.loads(result)
        assert len(data) == 2
        assert data[0]["content_hash"] == "abc123"

    def test_json_to_file(self, tmp_path):
        out = str(tmp_path / "test.json")
        _export_json(SAMPLE_DATA, out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert len(data) == 2


class TestExportData:
    def test_csv_dispatch(self):
        result = _export_data(data=SAMPLE_DATA, format_name="csv")
        assert "content_hash" in result

    def test_json_dispatch(self):
        result = _export_data(data=SAMPLE_DATA, format_name="json")
        assert isinstance(json.loads(result), list)

    def test_geojson_dispatch(self):
        result = _export_data(data=SAMPLE_GEO_DATA, format_name="geojson")
        fc = json.loads(result)
        assert fc["type"] == "FeatureCollection"

    def test_unknown_format_returns_none(self):
        result = _export_data(data=SAMPLE_DATA, format_name="xlsx")
        assert result is None

    def test_no_data_returns_none(self):
        result = _export_data(data=None, format_name="csv")
        assert result is None

    def test_empty_data_returns_none(self):
        result = _export_data(data=[], format_name="csv")
        assert result is None


class TestExportViaPluginManager:
    """Test export through the full plugin hook system."""

    def test_export_through_hooks(self):
        import sonar_catalog.plugins as plugins_mod
        plugins_mod.reset_plugins()
        plugins_mod.initialize_plugins()
        try:
            pm = plugins_mod.plugin_manager
            formats = pm.call_hook("get_export_formats")
            assert len(formats) > 0

            result = pm.call_hook(
                "export_data",
                data=SAMPLE_DATA,
                format_name="csv",
            )
            assert "content_hash" in result
        finally:
            plugins_mod.reset_plugins()
