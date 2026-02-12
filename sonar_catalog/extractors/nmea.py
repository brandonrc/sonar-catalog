"""Shared NMEA 0183 sentence parser for extracting lat/lon."""

import re
from typing import Optional


def parse_nmea_coord(value: str, direction: str) -> Optional[float]:
    """
    Parse NMEA coordinate (DDMM.MMMM or DDDMM.MMMM) to decimal degrees.

    Examples:
        "4807.038", "N" → 48.1173
        "01131.000", "E" → 11.5167
    """
    if not value or not direction:
        return None
    try:
        # Find the decimal point to determine degree width
        dot = value.index(".")
        deg_width = dot - 2  # degrees are everything before the last 2 digits before dot
        degrees = float(value[:deg_width])
        minutes = float(value[deg_width:])
        result = degrees + minutes / 60.0
        if direction in ("S", "W"):
            result = -result
        return result
    except (ValueError, IndexError):
        return None


def parse_gga(sentence: str) -> Optional[tuple[float, float]]:
    """Parse $GPGGA sentence → (lat, lon) or None."""
    parts = sentence.split(",")
    if len(parts) < 6:
        return None
    lat = parse_nmea_coord(parts[2], parts[3])
    lon = parse_nmea_coord(parts[4], parts[5])
    if lat is not None and lon is not None:
        return (lat, lon)
    return None


def parse_rmc(sentence: str) -> Optional[tuple[float, float]]:
    """Parse $GPRMC sentence → (lat, lon) or None."""
    parts = sentence.split(",")
    if len(parts) < 7:
        return None
    lat = parse_nmea_coord(parts[3], parts[4])
    lon = parse_nmea_coord(parts[5], parts[6])
    if lat is not None and lon is not None:
        return (lat, lon)
    return None


def parse_gll(sentence: str) -> Optional[tuple[float, float]]:
    """Parse $GPGLL sentence → (lat, lon) or None."""
    parts = sentence.split(",")
    if len(parts) < 5:
        return None
    lat = parse_nmea_coord(parts[1], parts[2])
    lon = parse_nmea_coord(parts[3], parts[4])
    if lat is not None and lon is not None:
        return (lat, lon)
    return None


# Map sentence type to parser
_PARSERS = {
    "GGA": parse_gga,
    "RMC": parse_rmc,
    "GLL": parse_gll,
}


def parse_nmea_sentence(sentence: str) -> Optional[tuple[float, float]]:
    """
    Parse any supported NMEA sentence → (lat, lon) or None.

    Handles $GPGGA, $GPRMC, $GPGLL and $GNGGA, $GNRMC, $GNGLL variants.
    """
    sentence = sentence.strip()
    if not sentence.startswith("$"):
        return None

    # Extract sentence type (e.g., "GGA" from "$GPGGA" or "$GNGGA")
    tag = sentence.split(",")[0]
    if len(tag) < 4:
        return None
    sentence_type = tag[-3:]  # last 3 chars: "GGA", "RMC", "GLL"

    parser = _PARSERS.get(sentence_type)
    if parser:
        return parser(sentence)
    return None


def extract_positions_from_text(text: str) -> list[tuple[float, float]]:
    """Extract all lat/lon positions from text containing NMEA sentences."""
    positions = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("$"):
            pos = parse_nmea_sentence(line)
            if pos:
                positions.append(pos)
    return positions
