"""Tests for navigation data extractors."""

import json
import os
import struct
import tempfile

import pytest

from sonar_catalog.extractors import extract_nav
from sonar_catalog.extractors.base import NavResult
from sonar_catalog.extractors.nmea import (
    parse_nmea_coord,
    parse_nmea_sentence,
    parse_gga,
)
from sonar_catalog.extractors.sidecar import SidecarExtractor
from sonar_catalog.extractors.jsf import JSFExtractor
from sonar_catalog.extractors.xtf import XTFExtractor


class TestNMEAParser:
    def test_parse_coord_north(self):
        assert abs(parse_nmea_coord("4807.038", "N") - 48.1173) < 0.001

    def test_parse_coord_south(self):
        result = parse_nmea_coord("3401.200", "S")
        assert result < 0
        assert abs(result - (-34.02)) < 0.001

    def test_parse_coord_east(self):
        assert abs(parse_nmea_coord("01131.000", "E") - 11.5167) < 0.001

    def test_parse_coord_west(self):
        result = parse_nmea_coord("07030.000", "W")
        assert result < 0

    def test_parse_coord_empty(self):
        assert parse_nmea_coord("", "N") is None
        assert parse_nmea_coord("4807.038", "") is None

    def test_parse_gga(self):
        sentence = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,47.0,M,,*47"
        result = parse_gga(sentence)
        assert result is not None
        lat, lon = result
        assert abs(lat - 48.1173) < 0.001
        assert abs(lon - 11.5167) < 0.001

    def test_parse_nmea_sentence_rmc(self):
        sentence = "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A"
        result = parse_nmea_sentence(sentence)
        assert result is not None
        assert abs(result[0] - 48.1173) < 0.001

    def test_parse_nmea_sentence_unknown(self):
        assert parse_nmea_sentence("$GPVTG,054.7,T,034.4,M,005.5,N,010.2,K*48") is None

    def test_parse_nmea_sentence_invalid(self):
        assert parse_nmea_sentence("not an nmea sentence") is None


class TestSidecarExtractor:
    def test_csv_sidecar(self, tmp_path):
        # Create a sonar file
        sonar_file = tmp_path / "line001.xtf"
        sonar_file.write_bytes(b"\x01\x00" + b"\x00" * 100)

        # Create a CSV sidecar
        nav_file = tmp_path / "line001.nav"
        nav_file.write_text("lat,lon\n48.117,11.517\n48.120,11.520\n48.125,11.525\n")

        patterns = [{"pattern": "{stem}.nav", "format": "csv",
                     "lat_field": "lat", "lon_field": "lon", "delimiter": ","}]
        ext = SidecarExtractor(patterns)
        assert ext.can_handle(str(sonar_file))

        result = ext.extract(str(sonar_file))
        assert result is not None
        assert len(result.track) == 3
        assert abs(result.track[0][0] - 48.117) < 0.001
        assert "sidecar:" in result.source

    def test_json_sidecar_track(self, tmp_path):
        sonar_file = tmp_path / "survey.jsf"
        sonar_file.write_bytes(b"\x16\x16" + b"\x00" * 100)

        meta_file = tmp_path / "survey.meta.json"
        meta_file.write_text(json.dumps({
            "track": [
                {"lat": 34.05, "lon": -118.25},
                {"lat": 34.06, "lon": -118.26},
            ]
        }))

        patterns = [{"pattern": "{stem}.meta.json", "format": "json",
                     "lat_field": "lat", "lon_field": "lon"}]
        ext = SidecarExtractor(patterns)
        result = ext.extract(str(sonar_file))
        assert result is not None
        assert len(result.track) == 2

    def test_json_sidecar_single_point(self, tmp_path):
        sonar_file = tmp_path / "data.xtf"
        sonar_file.write_bytes(b"\x00" * 100)

        meta_file = tmp_path / "data.meta.json"
        meta_file.write_text(json.dumps({"lat": 55.0, "lon": -3.0}))

        patterns = [{"pattern": "{stem}.meta.json", "format": "json",
                     "lat_field": "lat", "lon_field": "lon"}]
        ext = SidecarExtractor(patterns)
        result = ext.extract(str(sonar_file))
        assert result is not None
        assert len(result.track) == 1

    def test_no_sidecar_file(self, tmp_path):
        sonar_file = tmp_path / "solo.xtf"
        sonar_file.write_bytes(b"\x00" * 100)

        patterns = [{"pattern": "{stem}.nav", "format": "csv",
                     "lat_field": "lat", "lon_field": "lon"}]
        ext = SidecarExtractor(patterns)
        result = ext.extract(str(sonar_file))
        assert result is None

    def test_invalid_coordinates_filtered(self, tmp_path):
        sonar_file = tmp_path / "bad.xtf"
        sonar_file.write_bytes(b"\x00" * 100)

        nav_file = tmp_path / "bad.nav"
        nav_file.write_text("lat,lon\n999.0,999.0\n48.0,11.0\n")

        patterns = [{"pattern": "{stem}.nav", "format": "csv",
                     "lat_field": "lat", "lon_field": "lon"}]
        ext = SidecarExtractor(patterns)
        result = ext.extract(str(sonar_file))
        assert result is not None
        assert len(result.track) == 1  # only the valid point


class TestJSFExtractor:
    def _build_jsf_message(self, msg_type, data):
        """Build a JSF message with proper 20-byte header."""
        header = b"\x16\x16"          # 2: marker
        header += struct.pack("<H", 1)  # 2: version
        header += struct.pack("<H", 0)  # 2: session
        header += struct.pack("<H", msg_type)  # 2: msg_type
        header += b"\x00" * 8          # 8: command, subsystem, channel, seq, reserved
        header += struct.pack("<I", len(data))  # 4: data size
        return header + data  # total header = 20 bytes

    def test_jsf_sonar_data_nav(self, tmp_path):
        """Test extracting nav from JSF sonar data message (type 80)."""
        # Build a sonar data payload with position at offset 80
        data = bytearray(240)
        # Lat/lon in 1/10000 arc-seconds
        lat_arcsec = int(48.1173 * 3600 * 10000)
        lon_arcsec = int(11.5167 * 3600 * 10000)
        struct.pack_into("<i", data, 80, lat_arcsec)
        struct.pack_into("<i", data, 84, lon_arcsec)

        jsf_file = tmp_path / "test.jsf"
        msg1 = self._build_jsf_message(80, bytes(data))
        msg2 = self._build_jsf_message(80, bytes(data))
        jsf_file.write_bytes(msg1 + msg2)

        ext = JSFExtractor()
        assert ext.can_handle(str(jsf_file), "jsf")

        result = ext.extract(str(jsf_file))
        assert result is not None
        assert len(result.track) == 2
        assert abs(result.track[0][0] - 48.1173) < 0.01
        assert result.source == "jsf_nav"

    def test_jsf_nmea_message(self, tmp_path):
        """Test extracting nav from JSF NMEA message (type 2002)."""
        nmea = b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,47.0,M,,*47"
        jsf_file = tmp_path / "nmea.jsf"
        jsf_file.write_bytes(self._build_jsf_message(2002, nmea))

        ext = JSFExtractor()
        result = ext.extract(str(jsf_file), "jsf")
        assert result is not None
        assert len(result.track) == 1
        assert abs(result.track[0][0] - 48.1173) < 0.01

    def test_jsf_empty_file(self, tmp_path):
        jsf_file = tmp_path / "empty.jsf"
        jsf_file.write_bytes(b"")
        ext = JSFExtractor()
        result = ext.extract(str(jsf_file), "jsf")
        assert result is None

    def test_jsf_no_nav(self, tmp_path):
        """Non-nav message type should be skipped."""
        data = b"\x00" * 100
        jsf_file = tmp_path / "nonav.jsf"
        jsf_file.write_bytes(self._build_jsf_message(999, data))

        ext = JSFExtractor()
        result = ext.extract(str(jsf_file), "jsf")
        assert result is None


class TestXTFExtractor:
    def _build_xtf_packet(self, pkt_type, lat, lon, header_size=242):
        """Build an XTF packet with ping header containing lat/lon."""
        # 14-byte packet header
        hdr = struct.pack("<H", 0xFACE)  # magic
        hdr += struct.pack("B", header_size)  # header size (must fit in uint8)
        hdr += struct.pack("B", pkt_type)
        hdr += b"\x00" * 4  # reserved
        hdr += struct.pack("<I", header_size)  # total bytes = header_size
        hdr += b"\x00" * 2  # reserved

        # Ping data (after the 14-byte packet header)
        ping_data = bytearray(header_size - 14)
        if len(ping_data) >= 102:
            struct.pack_into("<d", ping_data, 86, lon)
            struct.pack_into("<d", ping_data, 94, lat)

        return hdr + bytes(ping_data)

    def test_xtf_ping_nav(self, tmp_path):
        """Test extracting nav from XTF PingHeader."""
        # File header (1024 bytes, first byte = 0x01)
        file_hdr = bytearray(1024)
        file_hdr[0] = 0x01

        pkt1 = self._build_xtf_packet(0, 48.1173, 11.5167, header_size=242)
        pkt2 = self._build_xtf_packet(0, 48.1200, 11.5200, header_size=242)

        xtf_file = tmp_path / "test.xtf"
        xtf_file.write_bytes(bytes(file_hdr) + pkt1 + pkt2)

        ext = XTFExtractor()
        assert ext.can_handle(str(xtf_file), "xtf")

        result = ext.extract(str(xtf_file))
        assert result is not None
        assert len(result.track) == 2
        assert abs(result.track[0][0] - 48.1173) < 0.001
        assert abs(result.track[0][1] - 11.5167) < 0.001
        assert result.source == "xtf_pingheader"

    def test_xtf_zero_coords_filtered(self, tmp_path):
        """Packets with (0,0) should be filtered out."""
        file_hdr = bytearray(1024)
        file_hdr[0] = 0x01
        pkt = self._build_xtf_packet(0, 0.0, 0.0, header_size=242)

        xtf_file = tmp_path / "zeros.xtf"
        xtf_file.write_bytes(bytes(file_hdr) + pkt)

        ext = XTFExtractor()
        result = ext.extract(str(xtf_file), "xtf")
        assert result is None

    def test_xtf_bad_magic(self, tmp_path):
        """File without XTF magic should return None."""
        xtf_file = tmp_path / "notxtf.xtf"
        xtf_file.write_bytes(b"\x00" * 2048)

        ext = XTFExtractor()
        result = ext.extract(str(xtf_file), "xtf")
        assert result is None


class TestExtractNavDispatcher:
    def test_sidecar_priority(self, tmp_path):
        """Sidecar should be tried before binary parsing."""
        sonar_file = tmp_path / "line.jsf"
        sonar_file.write_bytes(b"\x16\x16" + b"\x00" * 100)

        nav_file = tmp_path / "line.nav"
        nav_file.write_text("lat,lon\n55.0,-3.0\n")

        sidecar_config = [{"pattern": "{stem}.nav", "format": "csv",
                           "lat_field": "lat", "lon_field": "lon"}]

        result = extract_nav(str(sonar_file), "jsf", sidecar_config=sidecar_config)
        assert result is not None
        assert "sidecar:" in result.source

    def test_fallback_to_binary(self, tmp_path):
        """When no sidecar, should try binary extractor."""
        # Build valid JSF with nav
        data = bytearray(240)
        lat_arcsec = int(48.0 * 3600 * 10000)
        lon_arcsec = int(11.0 * 3600 * 10000)
        struct.pack_into("<i", data, 80, lat_arcsec)
        struct.pack_into("<i", data, 84, lon_arcsec)

        header = b"\x16\x16"
        header += struct.pack("<H", 1)
        header += struct.pack("<H", 0)
        header += struct.pack("<H", 80)
        header += b"\x00" * 8
        header += struct.pack("<I", len(data))

        jsf_file = tmp_path / "test.jsf"
        jsf_file.write_bytes(header + bytes(data))

        result = extract_nav(str(jsf_file), "jsf")
        assert result is not None
        assert result.source == "jsf_nav"

    def test_no_match(self, tmp_path):
        """Unknown format with no sidecar should return None."""
        f = tmp_path / "data.xyz"
        f.write_bytes(b"some data")
        result = extract_nav(str(f), "unknown_format")
        assert result is None


class TestNavDataDB:
    """Test database geo methods."""

    def test_insert_and_query_nav(self, tmp_db):
        """Insert nav data and query it back."""
        # First insert a file record
        tmp_db.insert_files_batch([
            {"content_hash": "geo1", "file_size": 1000, "partial_hash": "p1",
             "sonar_format": "xtf"},
        ])

        # Insert nav data
        tmp_db.insert_nav_data("geo1", {
            "lat_min": 48.0, "lat_max": 48.5,
            "lon_min": 11.0, "lon_max": 11.5,
            "lat_center": 48.25, "lon_center": 11.25,
            "metadata": {
                "track": [[48.0, 11.0], [48.25, 11.25], [48.5, 11.5]],
                "source": "test",
                "point_count_original": 3,
                "point_count_stored": 3,
            },
        })

        # Query geo points
        points = tmp_db.get_geo_points()
        assert len(points) == 1
        assert abs(points[0]["lat"] - 48.25) < 0.001
        assert points[0]["sonar_format"] == "xtf"

    def test_get_track(self, tmp_db):
        """Get track for a specific file."""
        tmp_db.insert_files_batch([
            {"content_hash": "geo2", "file_size": 2000, "partial_hash": "p2",
             "sonar_format": "jsf"},
        ])
        tmp_db.insert_nav_data("geo2", {
            "lat_min": 34.0, "lat_max": 34.1,
            "lon_min": -118.3, "lon_max": -118.2,
            "lat_center": 34.05, "lon_center": -118.25,
            "metadata": {
                "track": [[34.0, -118.3], [34.1, -118.2]],
                "source": "jsf_nav",
                "point_count_original": 100,
                "point_count_stored": 2,
            },
        })

        track = tmp_db.get_track("geo2")
        assert track is not None
        assert len(track["track"]) == 2
        assert track["source"] == "jsf_nav"
        assert track["bbox"]["lat_min"] == 34.0

    def test_get_track_not_found(self, tmp_db):
        assert tmp_db.get_track("nonexistent") is None

    def test_get_geo_bounds(self, tmp_db):
        """Get overall bounds of all nav data."""
        tmp_db.insert_files_batch([
            {"content_hash": "g1", "file_size": 100, "partial_hash": "p1",
             "sonar_format": "xtf"},
            {"content_hash": "g2", "file_size": 200, "partial_hash": "p2",
             "sonar_format": "jsf"},
        ])
        tmp_db.insert_nav_data_batch([
            {
                "content_hash": "g1",
                "lat_min": 48.0, "lat_max": 49.0,
                "lon_min": 11.0, "lon_max": 12.0,
                "lat_center": 48.5, "lon_center": 11.5,
                "metadata": {"track": [], "source": "test"},
            },
            {
                "content_hash": "g2",
                "lat_min": 34.0, "lat_max": 35.0,
                "lon_min": -119.0, "lon_max": -118.0,
                "lat_center": 34.5, "lon_center": -118.5,
                "metadata": {"track": [], "source": "test"},
            },
        ])

        bounds = tmp_db.get_geo_bounds()
        assert bounds is not None
        assert bounds["lat_min"] == 34.0
        assert bounds["lat_max"] == 49.0
        assert bounds["file_count"] == 2

    def test_get_geo_bounds_empty(self, tmp_db):
        assert tmp_db.get_geo_bounds() is None

    def test_geo_points_bbox_filter(self, tmp_db):
        """Bounding box filter should narrow results."""
        tmp_db.insert_files_batch([
            {"content_hash": "f1", "file_size": 100, "partial_hash": "p1",
             "sonar_format": "xtf"},
            {"content_hash": "f2", "file_size": 200, "partial_hash": "p2",
             "sonar_format": "jsf"},
        ])
        tmp_db.insert_nav_data_batch([
            {
                "content_hash": "f1",
                "lat_min": 48.0, "lat_max": 49.0,
                "lon_min": 11.0, "lon_max": 12.0,
                "lat_center": 48.5, "lon_center": 11.5,
                "metadata": {"track": [], "source": "test"},
            },
            {
                "content_hash": "f2",
                "lat_min": 34.0, "lat_max": 35.0,
                "lon_min": -119.0, "lon_max": -118.0,
                "lat_center": 34.5, "lon_center": -118.5,
                "metadata": {"track": [], "source": "test"},
            },
        ])

        # Filter to only European point
        points = tmp_db.get_geo_points(lat_min=40.0, lat_max=50.0)
        assert len(points) == 1
        assert points[0]["content_hash"] == "f1"
