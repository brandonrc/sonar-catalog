"""
Navigation data extraction framework.

Provides a pluggable extractor system for pulling lat/lon track data
from sonar files or their companion metadata files.

When the plugin system is initialized, extraction dispatches through
the plugin hook system. Otherwise falls back to direct extraction.
"""

import logging
from typing import Optional

from .base import NavExtractor, NavResult
from .sidecar import SidecarExtractor
from .jsf import JSFExtractor
from .xtf import XTFExtractor

logger = logging.getLogger(__name__)

# Direct extractors — used as fallback when plugin system isn't active
_FORMAT_EXTRACTORS: list[type[NavExtractor]] = [
    JSFExtractor,
    XTFExtractor,
]


def extract_nav(
    file_path: str,
    sonar_format: Optional[str] = None,
    sidecar_config: list[dict] = None,
) -> Optional[NavResult]:
    """
    Try to extract navigation data from a file.

    Dispatches through the plugin hook system if initialized,
    otherwise falls back to direct extraction.
    """
    # Try plugin system first
    try:
        from sonar_catalog.plugins import plugin_manager, _initialized

        if _initialized and plugin_manager.plugin_names:
            result = plugin_manager.call_hook(
                "extract_nav",
                file_path=file_path,
                sonar_format=sonar_format,
                sidecar_config=sidecar_config,
            )
            if result is not None:
                return result
            # Plugin system active but no result — don't fall through to
            # direct extractors (they'd be duplicates of the builtin plugin)
            return None
    except ImportError:
        pass

    # Fallback: direct extraction (no plugin system)
    return _extract_nav_direct(file_path, sonar_format, sidecar_config)


def _extract_nav_direct(
    file_path: str,
    sonar_format: Optional[str] = None,
    sidecar_config: list[dict] = None,
) -> Optional[NavResult]:
    """Direct extraction without plugin system."""
    # Try sidecar extractor first (user-defined companion files)
    if sidecar_config:
        sidecar = SidecarExtractor(sidecar_config)
        if sidecar.can_handle(file_path, sonar_format):
            try:
                result = sidecar.extract(file_path, sonar_format)
                if result and result.track:
                    return result
            except Exception as e:
                logger.debug(f"Sidecar extraction failed for {file_path}: {e}")

    # Try format-specific extractors
    for ext_cls in _FORMAT_EXTRACTORS:
        ext = ext_cls()
        if ext.can_handle(file_path, sonar_format):
            try:
                result = ext.extract(file_path, sonar_format)
                if result and result.track:
                    return result
            except Exception as e:
                logger.debug(f"{ext_cls.__name__} failed for {file_path}: {e}")

    return None


__all__ = [
    "NavExtractor",
    "NavResult",
    "SidecarExtractor",
    "JSFExtractor",
    "XTFExtractor",
    "extract_nav",
]
