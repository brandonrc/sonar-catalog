"""JSF (EdgeTech JSTAR) navigation data extractor."""

import logging
import struct
from typing import Optional

from .base import NavExtractor, NavResult
from .nmea import parse_nmea_sentence

logger = logging.getLogger(__name__)

# JSF message start marker
JSF_MARKER = b"\x16\x16"

# Message types containing navigation data
MSG_TYPE_SONAR_DATA = 80  # Sonar data message with embedded position
MSG_TYPE_NMEA = 2002  # NMEA text string


class JSFExtractor(NavExtractor):
    """Extract navigation data from JSF (EdgeTech JSTAR) files."""

    supported_formats = ["jsf"]

    def extract(self, file_path: str, sonar_format: Optional[str] = None) -> Optional[NavResult]:
        track = []
        try:
            with open(file_path, "rb") as f:
                while True:
                    # Read 4-byte preamble: 2-byte marker + 2-byte version
                    preamble = f.read(4)
                    if len(preamble) < 4:
                        break

                    if preamble[0:2] != JSF_MARKER:
                        # Lost sync — scan forward one byte
                        f.seek(-3, 1)
                        continue

                    # Read rest of 16-byte message header
                    # Bytes 4-5: session ID
                    # Bytes 6-7: message type (uint16 LE)
                    # Bytes 8: command type
                    # Bytes 9: subsystem number
                    # Bytes 10: channel number
                    # Bytes 11: sequence number
                    # Bytes 12-15: reserved
                    hdr_rest = f.read(12)
                    if len(hdr_rest) < 12:
                        break

                    msg_type = struct.unpack_from("<H", hdr_rest, 2)[0]

                    # Read 4-byte data size
                    size_bytes = f.read(4)
                    if len(size_bytes) < 4:
                        break
                    data_size = struct.unpack("<I", size_bytes)[0]

                    # Sanity check data size (max 10MB per message)
                    if data_size > 10 * 1024 * 1024:
                        f.seek(-3, 1)
                        continue

                    if msg_type == MSG_TYPE_SONAR_DATA and data_size >= 240:
                        # Sonar data header contains position
                        # Read enough for the position fields
                        data = f.read(min(data_size, 240))
                        if len(data) >= 240:
                            # Coordinates stored as int32: units of arc-seconds * 10000
                            # Offset 80: Y (latitude), Offset 84: X (longitude)
                            try:
                                y_raw = struct.unpack_from("<i", data, 80)[0]
                                x_raw = struct.unpack_from("<i", data, 84)[0]
                                # Convert from 1/10000 arc-seconds to decimal degrees
                                lat = y_raw / (3600.0 * 10000.0)
                                lon = x_raw / (3600.0 * 10000.0)
                                if -90 <= lat <= 90 and -180 <= lon <= 180 and (lat != 0 or lon != 0):
                                    track.append([lat, lon])
                            except struct.error:
                                pass
                        # Skip remaining data
                        remaining = data_size - len(data)
                        if remaining > 0:
                            f.seek(remaining, 1)

                    elif msg_type == MSG_TYPE_NMEA and data_size > 0:
                        # NMEA text message
                        data = f.read(data_size)
                        try:
                            text = data.decode("ascii", errors="ignore")
                            pos = parse_nmea_sentence(text.strip())
                            if pos:
                                track.append(list(pos))
                        except Exception:
                            pass
                    else:
                        # Skip non-nav messages
                        if data_size > 0:
                            f.seek(data_size, 1)

        except (OSError, PermissionError) as e:
            logger.debug(f"JSF read error {file_path}: {e}")
            return None

        if track:
            return NavResult(
                track=track,
                source="jsf_nav",
                point_count_original=len(track),
            )
        return None
