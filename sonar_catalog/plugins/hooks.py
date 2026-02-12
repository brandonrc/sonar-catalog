"""
Hook specification system for sonar-catalog plugins.

Defines extension points that plugins can implement. Two hook modes:

- firstresult: Returns the first non-None result (e.g. format detection)
- historic: Collects all results from all plugins (e.g. signature registration)
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class HookImpl:
    """A single hook implementation from a plugin."""

    plugin_name: str
    func: Callable
    priority: int = 100  # lower = called first


class HookSpec:
    """
    A hook specification defining an extension point.

    Plugins register implementations against a spec. When the hook is called:
    - firstresult=True: returns the first non-None result, short-circuits
    - firstresult=False (historic): calls all implementations, returns list
    """

    def __init__(self, name: str, firstresult: bool = False):
        self.name = name
        self.firstresult = firstresult
        self._impls: list[HookImpl] = []

    def register(self, plugin_name: str, func: Callable, priority: int = 100):
        """Register an implementation for this hook."""
        self._impls.append(HookImpl(plugin_name, func, priority))
        self._impls.sort(key=lambda x: x.priority)

    def unregister(self, plugin_name: str):
        """Remove all implementations for a plugin."""
        self._impls = [impl for impl in self._impls if impl.plugin_name != plugin_name]

    def call(self, **kwargs) -> Any:
        """
        Call all implementations.

        firstresult: return first non-None result.
        historic: return list of all non-None results.
        """
        if self.firstresult:
            for impl in self._impls:
                try:
                    result = impl.func(**kwargs)
                    if result is not None:
                        return result
                except Exception as e:
                    logger.debug(f"Hook {self.name}: {impl.plugin_name} failed: {e}")
            return None
        else:
            results = []
            for impl in self._impls:
                try:
                    result = impl.func(**kwargs)
                    if result is not None:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Hook {self.name}: {impl.plugin_name} failed: {e}")
            return results

    @property
    def implementations(self) -> list[HookImpl]:
        return list(self._impls)


# ---------------------------------------------------------------
# Hook spec definitions — the extension points of sonar-catalog
# ---------------------------------------------------------------

def create_default_hooks() -> dict[str, HookSpec]:
    """Create the standard set of hook specifications."""
    return {
        # Format detection: given a file path and header bytes, return format name.
        # firstresult — first plugin to recognize the format wins.
        "detect_format": HookSpec("detect_format", firstresult=True),

        # Navigation extraction: given a file path and format, return NavResult.
        # firstresult — first successful extractor wins.
        "extract_nav": HookSpec("extract_nav", firstresult=True),

        # Magic byte signatures: return dict of {bytes: format_name}.
        # historic — all plugins contribute their signatures.
        "get_format_signatures": HookSpec("get_format_signatures"),

        # Extension-to-format map: return dict of {".ext": "format_name"}.
        # historic — all plugins contribute their mappings.
        "get_extension_map": HookSpec("get_extension_map"),

        # Export data: given data, format name, output path, return bool.
        # firstresult — first matching exporter handles it.
        "export_data": HookSpec("export_data", firstresult=True),

        # List export formats: return list of dicts with format metadata.
        # historic — all plugins contribute their formats.
        "get_export_formats": HookSpec("get_export_formats"),

        # Web route registration: receive a Flask Blueprint to register routes on.
        # historic — all plugins can add routes.
        "register_web_routes": HookSpec("register_web_routes"),
    }
