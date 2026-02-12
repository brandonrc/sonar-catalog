"""
Built-in plugin for sonar-catalog.

Registers the default format detection signatures, extension mappings,
and navigation extractors (JSF, XTF) through the same hook system
that third-party plugins use.
"""

from .formats import register_format_hooks
from .nav import register_nav_hooks
from .exporters import register_export_hooks

PLUGIN_NAME = "builtin"
PLUGIN_VERSION = "1.0.0"


def register(manager):
    """Register all built-in hooks with the plugin manager."""
    manager.register_plugin(
        name=PLUGIN_NAME,
        version=PLUGIN_VERSION,
        description="Built-in sonar format detection, navigation extraction, and data export",
    )
    register_format_hooks(manager)
    register_nav_hooks(manager)
    register_export_hooks(manager)
