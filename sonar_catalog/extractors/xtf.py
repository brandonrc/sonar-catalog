"""XTF (eXtended Triton Format) navigation data extractor."""

import logging
import struct
from typing import Optional

from .base import NavExtractor, NavResult

logger = logging.getLogger(__name__)

XTF_HEADER_SIZE = 1024  # File header is always 1024 bytes
XTF_PACKET_MAGIC = 0xFACE
PING_HEADER_TYPE = 0  # Sonar ping data


class XTFExtractor(NavExtractor):
    """Extract navigation data from XTF files via PingHeader lat/lon."""

    supported_formats = ["xtf"]

    def extract(self, file_path: str, sonar_format: Optional[str] = None) -> Optional[NavResult]:
        track = []
        try:
            with open(file_path, "rb") as f:
                # Read file header to get number of channels (determines header size)
                file_hdr = f.read(XTF_HEADER_SIZE)
                if len(file_hdr) < XTF_HEADER_SIZE:
                    return None

                # Verify XTF magic: first byte should be 0x01 (file header type)
                if file_hdr[0] != 0x01:
                    return None

                while True:
                    # Read packet header (14 bytes minimum)
                    pkt_hdr = f.read(14)
                    if len(pkt_hdr) < 14:
                        break

                    # Packet header structure:
                    # Bytes 0-1: magic (0xFACE, uint16 LE)
                    # Byte 2: header size (in bytes)
                    # Byte 3: packet type
                    # Bytes 4-7: reserved
                    # Bytes 8-11: num_bytes_this_record (uint32 LE)
                    # Bytes 12-13: reserved
                    magic = struct.unpack_from("<H", pkt_hdr, 0)[0]

                    if magic != XTF_PACKET_MAGIC:
                        # Lost sync — scan forward
                        f.seek(-13, 1)
                        continue

                    pkt_type = pkt_hdr[3]
                    header_size = pkt_hdr[2]
                    num_bytes = struct.unpack_from("<I", pkt_hdr, 8)[0]

                    if num_bytes < 14 or num_bytes > 100 * 1024 * 1024:
                        # Invalid size, try to resync
                        f.seek(-13, 1)
                        continue

                    if pkt_type == PING_HEADER_TYPE:
                        # Read the rest of the packet header (PingHeader)
                        # We already read 14 bytes, need the rest of header_size
                        remaining_header = header_size - 14
                        if remaining_header < 0:
                            remaining_header = 242 - 14  # standard PingHeader size

                        ping_data = f.read(remaining_header)
                        if len(ping_data) < remaining_header:
                            break

                        # PingHeader lat/lon fields (after the 14-byte packet header):
                        # SensorXcoordinate (double, longitude) at offset 86 from ping_data start
                        # SensorYcoordinate (double, latitude) at offset 94 from ping_data start
                        if len(ping_data) >= 102:
                            try:
                                lon = struct.unpack_from("<d", ping_data, 86)[0]
                                lat = struct.unpack_from("<d", ping_data, 94)[0]

                                if -90 <= lat <= 90 and -180 <= lon <= 180 and (lat != 0 or lon != 0):
                                    track.append([lat, lon])
                            except struct.error:
                                pass

                        # Skip remaining data bytes after header
                        data_remaining = num_bytes - 14 - remaining_header
                        if data_remaining > 0:
                            f.seek(data_remaining, 1)
                    else:
                        # Skip non-ping packets
                        skip = num_bytes - 14
                        if skip > 0:
                            f.seek(skip, 1)

        except (OSError, PermissionError) as e:
            logger.debug(f"XTF read error {file_path}: {e}")
            return None

        if track:
            return NavResult(
                track=track,
                source="xtf_pingheader",
                point_count_original=len(track),
            )
        return None
