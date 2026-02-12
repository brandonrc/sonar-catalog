"""Tests for crawler module — sonar format detection."""

import os
import tempfile

from sonar_catalog.crawler import detect_sonar_format
from sonar_catalog.plugins.builtin.formats import SONAR_SIGNATURES, EXTENSION_TO_FORMAT


class TestSonarFormatDetection:
    """Test magic byte and extension-based format detection."""

    def test_xtf_magic_bytes(self):
        with tempfile.NamedTemporaryFile(suffix=".xtf", delete=False) as f:
            f.write(b"\x01\x00" + b"\x00" * 100)
            path = f.name
        try:
            assert detect_sonar_format(path, ".xtf") == "xtf"
        finally:
            os.unlink(path)

    def test_jsf_magic_bytes(self):
        with tempfile.NamedTemporaryFile(suffix=".jsf", delete=False) as f:
            f.write(b"\x16\x16" + b"\x00" * 100)
            path = f.name
        try:
            assert detect_sonar_format(path, ".jsf") == "jsf"
        finally:
            os.unlink(path)

    def test_extension_fallback(self):
        with tempfile.NamedTemporaryFile(suffix=".bag", delete=False) as f:
            f.write(b"\x00\x00\x00\x00" * 10)  # no matching magic bytes
            path = f.name
        try:
            # .bag has no magic match but extension maps to "bag"
            fmt = detect_sonar_format(path, ".bag")
            assert fmt == "bag"
        finally:
            os.unlink(path)

    def test_custom_magic_bytes(self):
        custom = [
            {"format": "custom-fmt", "hex_bytes": "cafebabe", "byte_length": 4, "offset": 0}
        ]
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            f.write(bytes.fromhex("cafebabe") + b"\x00" * 50)
            path = f.name
        try:
            assert detect_sonar_format(path, ".dat", custom_magic=custom) == "custom-fmt"
        finally:
            os.unlink(path)

    def test_custom_magic_with_offset(self):
        custom = [
            {"format": "offset-fmt", "hex_bytes": "dead", "byte_length": 2, "offset": 4}
        ]
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            f.write(b"\x00\x00\x00\x00" + bytes.fromhex("dead") + b"\x00" * 50)
            path = f.name
        try:
            assert detect_sonar_format(path, ".dat", custom_magic=custom) == "offset-fmt"
        finally:
            os.unlink(path)

    def test_custom_extension_map(self):
        custom_ext = {".sonarx": "my-sonar"}
        with tempfile.NamedTemporaryFile(suffix=".sonarx", delete=False) as f:
            f.write(b"\x00" * 50)
            path = f.name
        try:
            fmt = detect_sonar_format(path, ".sonarx", custom_ext_map=custom_ext)
            assert fmt == "my-sonar"
        finally:
            os.unlink(path)

    def test_unknown_format_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix=".xyz_unknown", delete=False) as f:
            f.write(b"\x99\x88\x77\x66" * 10)
            path = f.name
        try:
            assert detect_sonar_format(path, ".xyz_unknown") is None
        finally:
            os.unlink(path)

    def test_permission_error_graceful(self):
        # Non-existent path should not crash, just return extension fallback
        fmt = detect_sonar_format("/nonexistent/path.xtf", ".xtf")
        assert fmt == "xtf"  # falls through to extension
