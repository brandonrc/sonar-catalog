"""Tests for the plugin manager and hook specification system."""

import pytest

from sonar_catalog.plugins import reset_plugins
from sonar_catalog.plugins.hooks import HookSpec, create_default_hooks
from sonar_catalog.plugins.manager import PluginManager, PluginInfo


@pytest.fixture(autouse=True)
def clean_plugins():
    """Reset global plugin state between tests."""
    reset_plugins()
    yield
    reset_plugins()


class TestHookSpec:
    def test_firstresult_returns_first_non_none(self):
        hook = HookSpec("test", firstresult=True)
        hook.register("a", lambda: None)
        hook.register("b", lambda: "found_b")
        hook.register("c", lambda: "found_c")
        assert hook.call() == "found_b"

    def test_firstresult_returns_none_when_all_none(self):
        hook = HookSpec("test", firstresult=True)
        hook.register("a", lambda: None)
        assert hook.call() is None

    def test_firstresult_empty(self):
        hook = HookSpec("test", firstresult=True)
        assert hook.call() is None

    def test_historic_collects_all(self):
        hook = HookSpec("test", firstresult=False)
        hook.register("a", lambda: {"x": 1})
        hook.register("b", lambda: {"y": 2})
        results = hook.call()
        assert len(results) == 2
        assert {"x": 1} in results
        assert {"y": 2} in results

    def test_historic_skips_none(self):
        hook = HookSpec("test", firstresult=False)
        hook.register("a", lambda: None)
        hook.register("b", lambda: "ok")
        results = hook.call()
        assert results == ["ok"]

    def test_historic_empty(self):
        hook = HookSpec("test", firstresult=False)
        assert hook.call() == []

    def test_priority_ordering(self):
        hook = HookSpec("test", firstresult=True)
        # Higher priority (lower number) should be called first
        hook.register("low_pri", lambda: "low", priority=200)
        hook.register("high_pri", lambda: "high", priority=10)
        assert hook.call() == "high"

    def test_unregister(self):
        hook = HookSpec("test", firstresult=True)
        hook.register("a", lambda: "a_result")
        hook.register("b", lambda: "b_result")
        hook.unregister("a")
        assert hook.call() == "b_result"

    def test_unregister_nonexistent(self):
        hook = HookSpec("test", firstresult=True)
        hook.unregister("nope")  # should not raise

    def test_kwargs_passed_through(self):
        hook = HookSpec("test", firstresult=True)
        hook.register("a", lambda path=None, fmt=None: f"{path}:{fmt}")
        assert hook.call(path="/data/f.xtf", fmt="xtf") == "/data/f.xtf:xtf"

    def test_exception_in_impl_is_caught(self):
        hook = HookSpec("test", firstresult=True)

        def bad_func():
            raise RuntimeError("boom")

        hook.register("bad", bad_func)
        hook.register("good", lambda: "ok")
        # bad_func fails but good still runs
        assert hook.call() == "ok"

    def test_exception_in_historic_is_caught(self):
        hook = HookSpec("test", firstresult=False)

        def bad_func():
            raise RuntimeError("boom")

        hook.register("bad", bad_func)
        hook.register("good", lambda: "ok")
        results = hook.call()
        assert results == ["ok"]

    def test_implementations_property(self):
        hook = HookSpec("test", firstresult=True)
        hook.register("a", lambda: None, priority=50)
        hook.register("b", lambda: None, priority=10)
        impls = hook.implementations
        assert len(impls) == 2
        assert impls[0].plugin_name == "b"  # lower priority first
        assert impls[1].plugin_name == "a"


class TestPluginManager:
    def test_register_plugin(self):
        pm = PluginManager()
        info = pm.register_plugin("test-plugin", version="1.0", description="A test")
        assert info is not None
        assert info.name == "test-plugin"
        assert info.version == "1.0"
        assert pm.get_plugin("test-plugin") is info

    def test_register_disabled_plugin_returns_none(self):
        pm = PluginManager()
        pm.disable_plugin("blocked")
        info = pm.register_plugin("blocked")
        assert info is None
        assert pm.get_plugin("blocked") is None

    def test_unregister_plugin(self):
        pm = PluginManager()
        pm.register_plugin("tmp")
        pm.register_hook_impl("detect_format", "tmp", lambda **kw: "xtf")
        pm.unregister_plugin("tmp")
        assert pm.get_plugin("tmp") is None
        # Hook implementation should also be gone
        assert pm.call_hook("detect_format") is None

    def test_unregister_nonexistent(self):
        pm = PluginManager()
        pm.unregister_plugin("nope")  # should not raise

    def test_register_hook_impl(self):
        pm = PluginManager()
        pm.register_plugin("fmt-detector")
        pm.register_hook_impl(
            "detect_format", "fmt-detector",
            lambda file_path=None, header=None: "jsf" if header == b"\x16\x16" else None,
        )
        result = pm.call_hook("detect_format", file_path="test.jsf", header=b"\x16\x16")
        assert result == "jsf"

    def test_register_hook_unknown_raises(self):
        pm = PluginManager()
        with pytest.raises(ValueError, match="Unknown hook"):
            pm.register_hook_impl("nonexistent_hook", "p", lambda: None)

    def test_call_hook_unknown_raises(self):
        pm = PluginManager()
        with pytest.raises(ValueError, match="Unknown hook"):
            pm.call_hook("nonexistent_hook")

    def test_register_hook_for_disabled_plugin(self):
        pm = PluginManager()
        pm.disable_plugin("blocked")
        pm.register_hook_impl("detect_format", "blocked", lambda: "x")
        # Should not be registered
        assert pm.call_hook("detect_format") is None

    def test_enable_disable_lifecycle(self):
        pm = PluginManager()
        pm.register_plugin("toggleable")
        pm.register_hook_impl("detect_format", "toggleable", lambda **kw: "xtf")

        # Works initially
        assert pm.call_hook("detect_format") == "xtf"

        # Disable removes hooks
        pm.disable_plugin("toggleable")
        assert pm.call_hook("detect_format") is None
        assert pm.get_plugin("toggleable").enabled is False

        # Re-enable (doesn't re-register hooks — caller must do that)
        pm.enable_plugin("toggleable")
        assert pm.get_plugin("toggleable").enabled is True

    def test_is_disabled(self):
        pm = PluginManager()
        assert not pm.is_disabled("x")
        pm.disable_plugin("x")
        assert pm.is_disabled("x")
        pm.enable_plugin("x")
        assert not pm.is_disabled("x")

    def test_list_plugins(self):
        pm = PluginManager()
        pm.register_plugin("a")
        pm.register_plugin("b")
        plugins = pm.list_plugins()
        assert "a" in plugins
        assert "b" in plugins
        assert len(plugins) == 2

    def test_plugin_names(self):
        pm = PluginManager()
        pm.register_plugin("x")
        pm.register_plugin("y")
        assert sorted(pm.plugin_names) == ["x", "y"]

    def test_hooks_property(self):
        pm = PluginManager()
        hooks = pm.hooks
        assert "detect_format" in hooks
        assert "extract_nav" in hooks
        assert "get_format_signatures" in hooks

    def test_add_hook_spec(self):
        pm = PluginManager()
        pm.add_hook_spec("custom_hook", HookSpec("custom_hook", firstresult=True))
        pm.register_plugin("custom")
        pm.register_hook_impl("custom_hook", "custom", lambda: "works")
        assert pm.call_hook("custom_hook") == "works"

    def test_event_callbacks(self):
        pm = PluginManager()
        events = []
        pm.on("register", lambda name: events.append(("register", name)))
        pm.on("unregister", lambda name: events.append(("unregister", name)))
        pm.on("enable", lambda name: events.append(("enable", name)))
        pm.on("disable", lambda name: events.append(("disable", name)))

        pm.register_plugin("p1")
        pm.disable_plugin("p1")
        pm.enable_plugin("p1")
        pm.unregister_plugin("p1")

        assert events == [
            ("register", "p1"),
            ("disable", "p1"),
            ("enable", "p1"),
            ("unregister", "p1"),
        ]

    def test_on_unknown_event_raises(self):
        pm = PluginManager()
        with pytest.raises(ValueError, match="Unknown event"):
            pm.on("bad_event", lambda: None)

    def test_hook_impl_tracks_on_plugin_info(self):
        pm = PluginManager()
        pm.register_plugin("p")
        pm.register_hook_impl("detect_format", "p", lambda **kw: None)
        pm.register_hook_impl("extract_nav", "p", lambda **kw: None)
        info = pm.get_plugin("p")
        assert "detect_format" in info.hooks
        assert "extract_nav" in info.hooks

    def test_duplicate_hook_not_double_tracked(self):
        pm = PluginManager()
        pm.register_plugin("p")
        pm.register_hook_impl("detect_format", "p", lambda **kw: None)
        pm.register_hook_impl("detect_format", "p", lambda **kw: None)
        info = pm.get_plugin("p")
        assert info.hooks.count("detect_format") == 1


class TestHistoricHooks:
    """Test historic hooks that collect signatures/maps from all plugins."""

    def test_collect_format_signatures(self):
        pm = PluginManager()
        pm.register_plugin("builtin")
        pm.register_plugin("custom")

        pm.register_hook_impl(
            "get_format_signatures", "builtin",
            lambda: {b"\x01\x00": "xtf", b"\x16\x16": "jsf"},
        )
        pm.register_hook_impl(
            "get_format_signatures", "custom",
            lambda: {b"\xCA\xFE": "custom_sonar"},
        )

        all_sigs = pm.call_hook("get_format_signatures")
        assert len(all_sigs) == 2

        # Merge them
        merged = {}
        for d in all_sigs:
            merged.update(d)

        assert merged[b"\x01\x00"] == "xtf"
        assert merged[b"\x16\x16"] == "jsf"
        assert merged[b"\xCA\xFE"] == "custom_sonar"

    def test_collect_extension_maps(self):
        pm = PluginManager()
        pm.register_plugin("builtin")

        pm.register_hook_impl(
            "get_extension_map", "builtin",
            lambda: {".xtf": "xtf", ".jsf": "jsf"},
        )

        maps = pm.call_hook("get_extension_map")
        assert len(maps) == 1
        assert maps[0][".xtf"] == "xtf"


class TestDefaultHooks:
    """Verify the default hook specs are created correctly."""

    def test_all_default_hooks_present(self):
        hooks = create_default_hooks()
        expected = [
            "detect_format", "extract_nav",
            "get_format_signatures", "get_extension_map",
            "export_data", "get_export_formats",
            "register_web_routes",
        ]
        for name in expected:
            assert name in hooks, f"Missing default hook: {name}"

    def test_firstresult_hooks(self):
        hooks = create_default_hooks()
        assert hooks["detect_format"].firstresult is True
        assert hooks["extract_nav"].firstresult is True
        assert hooks["export_data"].firstresult is True

    def test_historic_hooks(self):
        hooks = create_default_hooks()
        assert hooks["get_format_signatures"].firstresult is False
        assert hooks["get_extension_map"].firstresult is False
        assert hooks["get_export_formats"].firstresult is False
        assert hooks["register_web_routes"].firstresult is False


class TestPluginDiscovery:
    """Test entry_point based discovery (mocked)."""

    def test_discover_with_disabled(self):
        pm = PluginManager()
        pm.discover(disabled_plugins={"blocked-plugin"})
        assert pm.is_disabled("blocked-plugin")

    def test_discover_no_entry_points(self):
        """Discovery with no plugins installed should not error."""
        pm = PluginManager()
        pm.discover()
        # Only manually registered plugins should exist
        assert len(pm.plugin_names) == 0

    def test_discover_skips_already_loaded(self):
        """If a plugin is already registered, discovery should skip it."""
        pm = PluginManager()
        pm.register_plugin("pre-loaded")
        pm.discover()
        # Should still have exactly 1
        assert len(pm.plugin_names) == 1


class TestPluginIntegration:
    """End-to-end plugin workflow tests."""

    def test_format_detection_workflow(self):
        """Simulate a complete format detection workflow through plugins."""
        pm = PluginManager()

        # Register a "builtin" plugin
        pm.register_plugin("builtin", version="1.0")

        # Provide magic byte signatures
        pm.register_hook_impl(
            "get_format_signatures", "builtin",
            lambda: {b"\x01\x00": "xtf", b"\x16\x16": "jsf"},
        )

        # Provide extension map
        pm.register_hook_impl(
            "get_extension_map", "builtin",
            lambda: {".xtf": "xtf", ".jsf": "jsf"},
        )

        # Provide format detector
        def detect(file_path=None, header=None, extension=None):
            # Try magic bytes
            sigs = pm.call_hook("get_format_signatures")
            merged_sigs = {}
            for d in sigs:
                merged_sigs.update(d)
            if header:
                for sig, fmt in merged_sigs.items():
                    if header.startswith(sig):
                        return fmt
            # Try extension
            maps = pm.call_hook("get_extension_map")
            merged_map = {}
            for d in maps:
                merged_map.update(d)
            if extension:
                return merged_map.get(extension)
            return None

        pm.register_hook_impl("detect_format", "builtin", detect)

        # Test detection
        assert pm.call_hook("detect_format", header=b"\x16\x16\x00", extension=".jsf") == "jsf"
        assert pm.call_hook("detect_format", header=b"\x01\x00\x00", extension=".xtf") == "xtf"
        assert pm.call_hook("detect_format", header=b"\x00\x00\x00", extension=".xtf") == "xtf"
        assert pm.call_hook("detect_format", header=b"\x00\x00\x00", extension=".unknown") is None

    def test_multiple_plugins_priority(self):
        """Custom plugin takes priority over builtin."""
        pm = PluginManager()
        pm.register_plugin("builtin")
        pm.register_plugin("custom")

        pm.register_hook_impl(
            "detect_format", "builtin",
            lambda file_path=None, header=None: "generic",
            priority=100,  # lower priority
        )
        pm.register_hook_impl(
            "detect_format", "custom",
            lambda file_path=None, header=None: "custom_format"
            if header == b"\xCA\xFE" else None,
            priority=50,  # higher priority (called first)
        )

        # Custom header: custom plugin handles it
        assert pm.call_hook("detect_format", header=b"\xCA\xFE") == "custom_format"
        # Unknown header: custom returns None, builtin catches it
        assert pm.call_hook("detect_format", header=b"\x00\x00") == "generic"


class TestManifest:
    """Test plugin manifest parsing and registration."""

    def test_parse_manifest(self):
        pytest.importorskip("yaml")
        from sonar_catalog.plugins.manifest import load_manifest

        yaml_text = """
name: test-plugin
version: 2.0.0
description: A test plugin

contributions:
  formats:
    - name: foobar
      extensions: [".fb", ".fbar"]
      magic_bytes: "464f4f42"
      magic_offset: 0
  nav_extractors:
    - format: foobar
      python_name: sonar_catalog.extractors.jsf:JSFExtractor
"""
        manifest = load_manifest(yaml_text)
        assert manifest.name == "test-plugin"
        assert manifest.version == "2.0.0"
        assert len(manifest.formats) == 1
        assert manifest.formats[0].name == "foobar"
        assert manifest.formats[0].extensions == [".fb", ".fbar"]
        assert manifest.formats[0].magic_bytes == "464f4f42"
        assert len(manifest.nav_extractors) == 1
        assert manifest.nav_extractors[0].format == "foobar"

    def test_manifest_missing_name(self):
        pytest.importorskip("yaml")
        from sonar_catalog.plugins.manifest import load_manifest

        with pytest.raises(ValueError, match="must have a 'name'"):
            load_manifest("version: 1.0\n")

    def test_manifest_invalid_yaml(self):
        pytest.importorskip("yaml")
        from sonar_catalog.plugins.manifest import load_manifest

        with pytest.raises(ValueError, match="YAML mapping"):
            load_manifest("just a string")

    def test_register_from_manifest_formats(self):
        pytest.importorskip("yaml")
        from sonar_catalog.plugins.manifest import load_manifest, register_from_manifest

        pm = PluginManager()
        manifest = load_manifest("""
name: fmt-plugin
version: 1.0.0
contributions:
  formats:
    - name: foobar
      extensions: [".fb"]
      magic_bytes: "464f4f42"
""")
        pm.register_plugin("fmt-plugin")
        register_from_manifest(pm, manifest)

        # Check signatures registered
        sigs = pm.call_hook("get_format_signatures")
        assert len(sigs) == 1
        assert sigs[0][bytes.fromhex("464f4f42")] == "foobar"

        # Check extension map registered
        maps = pm.call_hook("get_extension_map")
        assert len(maps) == 1
        assert maps[0][".fb"] == "foobar"

    def test_register_from_manifest_nav_extractor(self):
        pytest.importorskip("yaml")
        from sonar_catalog.plugins.manifest import load_manifest, register_from_manifest

        pm = PluginManager()
        manifest = load_manifest("""
name: nav-plugin
version: 1.0.0
contributions:
  nav_extractors:
    - format: jsf
      python_name: sonar_catalog.extractors.jsf:JSFExtractor
""")
        pm.register_plugin("nav-plugin")
        register_from_manifest(pm, manifest)

        # Hook should be registered (though we can't easily test with real files here)
        hook = pm.hooks["extract_nav"]
        assert len(hook.implementations) == 1
        assert hook.implementations[0].plugin_name == "nav-plugin"

    def test_import_object(self):
        from sonar_catalog.plugins.manifest import _import_object

        cls = _import_object("sonar_catalog.extractors.jsf:JSFExtractor")
        from sonar_catalog.extractors.jsf import JSFExtractor
        assert cls is JSFExtractor

    def test_import_object_invalid_format(self):
        from sonar_catalog.plugins.manifest import _import_object

        with pytest.raises(ValueError, match="must be 'module:name'"):
            _import_object("no_colon_here")


class TestBuiltinPlugin:
    """Test the built-in plugin registration."""

    def test_builtin_registers_all_hooks(self):
        from sonar_catalog.plugins.builtin import register

        pm = PluginManager()
        register(pm)

        assert pm.get_plugin("builtin") is not None
        info = pm.get_plugin("builtin")
        assert "get_format_signatures" in info.hooks
        assert "get_extension_map" in info.hooks
        assert "detect_format" in info.hooks
        assert "extract_nav" in info.hooks

    def test_builtin_format_signatures(self):
        from sonar_catalog.plugins.builtin import register

        pm = PluginManager()
        register(pm)

        sigs = pm.call_hook("get_format_signatures")
        merged = {}
        for d in sigs:
            merged.update(d)

        assert merged[b"\x01\x00"] == "xtf"
        assert merged[b"\x16\x16"] == "jsf"
        assert merged[b"\xff\xff"] == "s7k"

    def test_builtin_extension_map(self):
        from sonar_catalog.plugins.builtin import register

        pm = PluginManager()
        register(pm)

        maps = pm.call_hook("get_extension_map")
        merged = {}
        for d in maps:
            merged.update(d)

        assert merged[".xtf"] == "xtf"
        assert merged[".jsf"] == "jsf"
        assert merged[".bag"] == "bag"

    def test_builtin_detect_format(self):
        from sonar_catalog.plugins.builtin import register

        pm = PluginManager()
        register(pm)

        # Magic byte detection
        fmt = pm.call_hook("detect_format", header=b"\x16\x16\x00\x00", extension=".jsf")
        assert fmt == "jsf"

        # Extension fallback
        fmt = pm.call_hook("detect_format", header=b"\x00\x00\x00\x00", extension=".bag")
        assert fmt == "bag"

        # Unknown
        fmt = pm.call_hook("detect_format", header=b"\x00\x00\x00\x00", extension=".nope")
        assert fmt is None
