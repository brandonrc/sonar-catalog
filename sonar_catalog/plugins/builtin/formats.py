"""
Built-in format detection hooks.

Provides magic byte signatures and extension-to-format mappings
that were previously hardcoded in crawler.py.
"""

# Magic bytes / signatures for common sonar formats
SONAR_SIGNATURES = {
    b"\x01\x00": "xtf",     # XTF (eXtended Triton Format)
    b"\x16\x16": "jsf",     # JSF (EdgeTech JSTAR)
    b"\xff\xff": "s7k",     # s7k (Reson/Teledyne)
    b"\x02\x00": "all",     # Kongsberg .all
    b"C 1 ": "segy",        # SEG-Y textual header variant 1
    b"C  1": "segy",        # SEG-Y textual header variant 2
}

# Extension-based format detection (fallback)
EXTENSION_TO_FORMAT = {
    ".xtf": "xtf",
    ".jsf": "jsf",
    ".s7k": "s7k",
    ".all": "all",
    ".wcd": "wcd",
    ".kmall": "kmall",
    ".db": "humminbird",
    ".sl2": "lowrance",
    ".sl3": "lowrance",
    ".son": "garmin",
    ".sgy": "segy",
    ".segy": "segy",
    ".bag": "bag",
    ".raw": "raw_sonar",
    ".csv": "csv",
    ".xyz": "xyz_points",
    ".tif": "geotiff",
    ".tiff": "geotiff",
}


def _get_format_signatures():
    """Hook impl: return built-in magic byte signatures."""
    return dict(SONAR_SIGNATURES)


def _get_extension_map():
    """Hook impl: return built-in extension-to-format map."""
    return dict(EXTENSION_TO_FORMAT)


def _detect_format(file_path=None, header=None, extension=None,
                   custom_magic=None, custom_ext_map=None):
    """
    Hook impl: detect sonar format from magic bytes or extension.

    Checks custom user-defined magic bytes first (from config),
    then built-in signatures, then custom extension map, then built-in extensions.
    """
    if header:
        # Check custom magic bytes first (user-defined take priority)
        if custom_magic:
            for entry in custom_magic:
                offset = entry.get("offset", 0)
                hex_bytes = entry.get("hex_bytes", "")
                fmt = entry.get("format", "unknown")
                try:
                    sig = bytes.fromhex(hex_bytes)
                    if len(header) >= offset + len(sig):
                        if header[offset:offset + len(sig)] == sig:
                            return fmt
                except (ValueError, TypeError):
                    continue

        # Check built-in magic signatures
        if len(header) >= 4:
            for sig, fmt in SONAR_SIGNATURES.items():
                if header.startswith(sig):
                    return fmt

    # Fall back to extension (custom map first, then built-in)
    if extension:
        ext = extension.lower()
        if custom_ext_map and ext in custom_ext_map:
            return custom_ext_map[ext]
        return EXTENSION_TO_FORMAT.get(ext)

    return None


def register_format_hooks(manager):
    """Register format detection hooks with the plugin manager."""
    from . import PLUGIN_NAME

    manager.register_hook_impl(
        "get_format_signatures", PLUGIN_NAME, _get_format_signatures,
    )
    manager.register_hook_impl(
        "get_extension_map", PLUGIN_NAME, _get_extension_map,
    )
    manager.register_hook_impl(
        "detect_format", PLUGIN_NAME, _detect_format,
        priority=100,  # built-in = lowest priority, custom plugins override
    )
