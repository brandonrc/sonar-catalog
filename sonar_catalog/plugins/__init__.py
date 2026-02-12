"""
Plugin system for sonar-catalog.

Provides a pluggable extension architecture using Python entry_points
for third-party plugin discovery and a hook specification system for
defining extension points.

Usage:
    from sonar_catalog.plugins import plugin_manager, initialize_plugins

    # Initialize once at startup (discovers entry_point plugins)
    initialize_plugins()

    # Call hooks
    fmt = plugin_manager.call_hook("detect_format", file_path=path, header=header)
"""

import logging
from typing import Optional

from .hooks import HookSpec, create_default_hooks
from .manager import PluginManager, PluginInfo

logger = logging.getLogger(__name__)

# Global singleton — the central plugin registry
plugin_manager = PluginManager()

_initialized = False


def initialize_plugins(disabled_plugins: Optional[set[str]] = None):
    """
    Initialize the plugin system.

    Call once at application startup. Discovers plugins from:
    1. Python entry_points (group: sonar_catalog.plugins)
    2. Built-in plugins are registered by the caller after this.

    Args:
        disabled_plugins: Set of plugin names to skip during discovery.
    """
    global _initialized

    if _initialized:
        return

    # Register built-in plugin first (lowest priority)
    from .builtin import register as register_builtin

    register_builtin(plugin_manager)

    # Discover third-party plugins from entry_points
    plugin_manager.discover(disabled_plugins=disabled_plugins)

    _initialized = True
    logger.debug(
        f"Plugin system initialized: {len(plugin_manager.plugin_names)} plugins loaded"
    )


def reset_plugins():
    """Reset the plugin system. Primarily for testing."""
    global plugin_manager, _initialized
    plugin_manager = PluginManager()
    _initialized = False


__all__ = [
    "plugin_manager",
    "initialize_plugins",
    "reset_plugins",
    "PluginManager",
    "PluginInfo",
    "HookSpec",
]
