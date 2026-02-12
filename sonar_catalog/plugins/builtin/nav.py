"""
Built-in navigation extraction hooks.

Wraps the existing JSF and XTF extractors as plugin hook implementations.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _extract_nav(file_path=None, sonar_format=None, sidecar_config=None):
    """
    Hook impl: extract navigation data from a sonar file.

    Tries sidecar patterns first, then JSF/XTF binary extractors.
    """
    from sonar_catalog.extractors.sidecar import SidecarExtractor
    from sonar_catalog.extractors.jsf import JSFExtractor
    from sonar_catalog.extractors.xtf import XTFExtractor

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
    for ext_cls in [JSFExtractor, XTFExtractor]:
        ext = ext_cls()
        if ext.can_handle(file_path, sonar_format):
            try:
                result = ext.extract(file_path, sonar_format)
                if result and result.track:
                    return result
            except Exception as e:
                logger.debug(f"{ext_cls.__name__} failed for {file_path}: {e}")

    return None


def register_nav_hooks(manager):
    """Register navigation extraction hooks with the plugin manager."""
    from . import PLUGIN_NAME

    manager.register_hook_impl(
        "extract_nav", PLUGIN_NAME, _extract_nav,
        priority=100,  # built-in = lowest priority
    )
