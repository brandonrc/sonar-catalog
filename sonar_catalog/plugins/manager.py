"""
Plugin manager for sonar-catalog.

Discovers, registers, and manages plugins. Inspired by napari's
NapariPluginManager but kept minimal — no external dependencies.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .hooks import HookSpec, create_default_hooks

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """Metadata about a registered plugin."""

    name: str
    version: str = "0.0.0"
    description: str = ""
    module: Any = None
    enabled: bool = True
    hooks: list[str] = field(default_factory=list)


class PluginManager:
    """
    Central plugin registry.

    Manages plugin lifecycle: discovery, registration, enable/disable.
    Plugins implement hooks (extension points) to contribute functionality.
    """

    ENTRY_POINT_GROUP = "sonar_catalog.plugins"

    def __init__(self):
        self._plugins: dict[str, PluginInfo] = {}
        self._hooks: dict[str, HookSpec] = create_default_hooks()
        self._disabled: set[str] = set()
        self._callbacks: dict[str, list[Callable]] = {
            "register": [],
            "unregister": [],
            "enable": [],
            "disable": [],
        }

    # ---- Plugin registration ----

    def register_plugin(
        self,
        name: str,
        module: Any = None,
        version: str = "0.0.0",
        description: str = "",
    ) -> Optional[PluginInfo]:
        """Register a plugin. Returns None if the plugin is disabled."""
        if name in self._disabled:
            logger.debug(f"Skipping disabled plugin: {name}")
            return None

        info = PluginInfo(
            name=name,
            version=version,
            description=description,
            module=module,
        )
        self._plugins[name] = info

        for cb in self._callbacks["register"]:
            try:
                cb(name)
            except Exception as e:
                logger.debug(f"Register callback error for {name}: {e}")

        logger.debug(f"Registered plugin: {name} v{version}")
        return info

    def unregister_plugin(self, name: str):
        """Remove a plugin and all its hook implementations."""
        if name not in self._plugins:
            return

        for hook in self._hooks.values():
            hook.unregister(name)

        del self._plugins[name]

        for cb in self._callbacks["unregister"]:
            try:
                cb(name)
            except Exception as e:
                logger.debug(f"Unregister callback error for {name}: {e}")

        logger.debug(f"Unregistered plugin: {name}")

    # ---- Hook management ----

    def register_hook_impl(
        self,
        hook_name: str,
        plugin_name: str,
        func: Callable,
        priority: int = 100,
    ):
        """Register a hook implementation from a plugin."""
        if hook_name not in self._hooks:
            raise ValueError(f"Unknown hook: {hook_name}")

        if plugin_name in self._disabled:
            return

        self._hooks[hook_name].register(plugin_name, func, priority)

        if plugin_name in self._plugins:
            if hook_name not in self._plugins[plugin_name].hooks:
                self._plugins[plugin_name].hooks.append(hook_name)

    def call_hook(self, hook_name: str, **kwargs) -> Any:
        """Call a hook, dispatching to all registered implementations."""
        if hook_name not in self._hooks:
            raise ValueError(f"Unknown hook: {hook_name}")
        return self._hooks[hook_name].call(**kwargs)

    def add_hook_spec(self, name: str, spec: HookSpec):
        """Add a new hook specification (for plugins that define new hooks)."""
        self._hooks[name] = spec

    # ---- Enable / disable ----

    def enable_plugin(self, name: str):
        """Re-enable a disabled plugin."""
        self._disabled.discard(name)

        if name in self._plugins:
            self._plugins[name].enabled = True

        for cb in self._callbacks["enable"]:
            try:
                cb(name)
            except Exception as e:
                logger.debug(f"Enable callback error for {name}: {e}")

        logger.debug(f"Enabled plugin: {name}")

    def disable_plugin(self, name: str):
        """Disable a plugin, removing its hook implementations."""
        self._disabled.add(name)

        # Remove hook implementations but keep plugin info
        for hook in self._hooks.values():
            hook.unregister(name)

        if name in self._plugins:
            self._plugins[name].enabled = False
            self._plugins[name].hooks.clear()

        for cb in self._callbacks["disable"]:
            try:
                cb(name)
            except Exception as e:
                logger.debug(f"Disable callback error for {name}: {e}")

        logger.debug(f"Disabled plugin: {name}")

    def is_disabled(self, name: str) -> bool:
        return name in self._disabled

    # ---- Discovery ----

    def discover(self, disabled_plugins: set[str] = None):
        """
        Discover and load plugins via Python entry_points.

        Third-party plugins declare themselves in pyproject.toml:

            [project.entry-points."sonar_catalog.plugins"]
            my_plugin = "my_package.plugin_module"

        The target module must have a register(manager) function.
        """
        if disabled_plugins:
            self._disabled.update(disabled_plugins)

        try:
            from importlib.metadata import entry_points

            eps = entry_points(group=self.ENTRY_POINT_GROUP)
            for ep in eps:
                if ep.name in self._disabled:
                    logger.debug(f"Skipping disabled plugin: {ep.name}")
                    continue

                if ep.name in self._plugins:
                    logger.debug(f"Plugin already loaded: {ep.name}")
                    continue

                try:
                    module = ep.load()
                    self.register_plugin(
                        name=ep.name,
                        module=module,
                        version=getattr(module, "__version__", "0.0.0"),
                        description=getattr(module, "__doc__", "") or "",
                    )

                    # Call the plugin's register function
                    if hasattr(module, "register"):
                        module.register(self)
                    else:
                        # Try manifest-based registration
                        self._try_manifest_registration(ep.name, module)

                except Exception as e:
                    logger.warning(f"Failed to load plugin {ep.name}: {e}")

        except Exception as e:
            logger.debug(f"Plugin discovery error: {e}")

    def _try_manifest_registration(self, plugin_name: str, module):
        """Try to register a plugin from its sonar-plugin.yaml manifest."""
        try:
            from .manifest import find_manifest_in_package, load_manifest, register_from_manifest

            yaml_text = find_manifest_in_package(module)
            if yaml_text:
                manifest = load_manifest(yaml_text)
                register_from_manifest(self, manifest)
                logger.debug(f"Plugin {plugin_name} registered via manifest")
            else:
                logger.warning(
                    f"Plugin {plugin_name} has no register() function or manifest"
                )
        except ImportError:
            logger.warning(
                f"Plugin {plugin_name} has a manifest but PyYAML is not installed"
            )
        except Exception as e:
            logger.warning(f"Manifest registration failed for {plugin_name}: {e}")

    # ---- Event callbacks ----

    def on(self, event: str, callback: Callable):
        """Register a callback for plugin lifecycle events."""
        if event not in self._callbacks:
            raise ValueError(f"Unknown event: {event}")
        self._callbacks[event].append(callback)

    # ---- Introspection ----

    def get_plugin(self, name: str) -> Optional[PluginInfo]:
        return self._plugins.get(name)

    def list_plugins(self) -> dict[str, PluginInfo]:
        return dict(self._plugins)

    @property
    def hooks(self) -> dict[str, HookSpec]:
        return dict(self._hooks)

    @property
    def plugin_names(self) -> list[str]:
        return list(self._plugins.keys())
