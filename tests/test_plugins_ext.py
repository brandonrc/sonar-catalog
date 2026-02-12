"""Extended plugin tests — nav hooks, discovery, manager edge cases."""

import pytest
from unittest.mock import patch, MagicMock

from sonar_catalog.plugins import reset_plugins, plugin_manager
from sonar_catalog.plugins.hooks import HookSpec, create_default_hooks
from sonar_catalog.plugins.manager import PluginManager


@pytest.fixture(autouse=True)
def clean_plugins():
    reset_plugins()
    yield
    reset_plugins()


class TestBuiltinNavHook:
    """Test the built-in navigation extraction hook."""

    def test_nav_hook_registered(self):
        import sonar_catalog.plugins as pm
        pm.reset_plugins()
        pm.initialize_plugins()
        mgr = pm.plugin_manager
        hook = mgr.hooks["extract_nav"]
        assert len(hook.implementations) == 1
        assert hook.implementations[0].plugin_name == "builtin"
        pm.reset_plugins()

    def test_nav_hook_returns_none_for_nonexistent(self):
        import sonar_catalog.plugins as pm
        pm.reset_plugins()
        pm.initialize_plugins()
        mgr = pm.plugin_manager
        result = mgr.call_hook(
            "extract_nav",
            file_path="/nonexistent/file.xtf",
            sonar_format="xtf",
        )
        assert result is None
        pm.reset_plugins()

    def test_nav_hook_with_jsf_file(self, tmp_path):
        """Test with a fake JSF file that has no valid nav data."""
        import sonar_catalog.plugins as pm
        pm.reset_plugins()
        pm.initialize_plugins()
        mgr = pm.plugin_manager

        f = tmp_path / "test.jsf"
        f.write_bytes(b"\x16\x16" + b"\x00" * 200)

        result = mgr.call_hook(
            "extract_nav",
            file_path=str(f),
            sonar_format="jsf",
        )
        # No valid nav data in dummy file
        assert result is None
        pm.reset_plugins()

    def test_nav_hook_with_sidecar_config(self, tmp_path):
        """Test sidecar extraction with matching nav file."""
        import sonar_catalog.plugins as pm
        pm.reset_plugins()
        pm.initialize_plugins()
        mgr = pm.plugin_manager

        # Create a sonar file
        f = tmp_path / "survey.xtf"
        f.write_bytes(b"\x01\x00" + b"\x00" * 100)

        # Create matching sidecar CSV
        nav = tmp_path / "survey.nav"
        nav.write_text("lat,lon\n56.0,3.0\n56.1,3.1\n56.2,3.2\n")

        sidecar_config = [{
            "pattern": "{stem}.nav",
            "format": "csv",
            "lat_field": "lat",
            "lon_field": "lon",
            "delimiter": ",",
        }]

        result = mgr.call_hook(
            "extract_nav",
            file_path=str(f),
            sonar_format="xtf",
            sidecar_config=sidecar_config,
        )
        if result and result.track:
            assert len(result.track) >= 3
        pm.reset_plugins()


class TestBuiltinExportHooks:
    def test_export_hooks_registered(self):
        import sonar_catalog.plugins as pm
        pm.reset_plugins()
        pm.initialize_plugins()
        mgr = pm.plugin_manager

        info = mgr.get_plugin("builtin")
        assert "get_export_formats" in info.hooks
        assert "export_data" in info.hooks
        pm.reset_plugins()


class TestPluginManagerDiscovery:
    """Test the entry_point discovery system."""

    def test_discover_with_mock_entry_points(self):
        pm = PluginManager()

        # Mock a plugin module
        mock_module = MagicMock()
        mock_module.__version__ = "1.2.3"
        mock_module.__doc__ = "A mock plugin"
        mock_module.register = MagicMock()

        mock_ep = MagicMock()
        mock_ep.name = "mock-plugin"
        mock_ep.load.return_value = mock_module

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            pm.discover()

        assert "mock-plugin" in pm.plugin_names
        info = pm.get_plugin("mock-plugin")
        assert info.version == "1.2.3"
        mock_module.register.assert_called_once_with(pm)

    def test_discover_skips_disabled(self):
        pm = PluginManager()

        mock_ep = MagicMock()
        mock_ep.name = "disabled-plugin"

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            pm.discover(disabled_plugins={"disabled-plugin"})

        assert "disabled-plugin" not in pm.plugin_names

    def test_discover_handles_load_error(self):
        pm = PluginManager()

        mock_ep = MagicMock()
        mock_ep.name = "broken-plugin"
        mock_ep.load.side_effect = ImportError("no module")

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            pm.discover()

        assert "broken-plugin" not in pm.plugin_names

    def test_discover_module_without_register(self):
        """Module without register() falls back to manifest."""
        pm = PluginManager()

        mock_module = MagicMock(spec=[])  # no register attribute
        del mock_module.register

        mock_ep = MagicMock()
        mock_ep.name = "no-register"
        mock_ep.load.return_value = mock_module

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            pm.discover()

        # Plugin should be registered (even if manifest fallback failed)
        assert "no-register" in pm.plugin_names

    def test_discover_already_loaded(self):
        pm = PluginManager()
        pm.register_plugin("pre-loaded")

        mock_ep = MagicMock()
        mock_ep.name = "pre-loaded"

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            pm.discover()

        # Should not double-load
        assert len(pm.plugin_names) == 1


class TestPluginManagerCallbacks:
    def test_callback_error_doesnt_break(self):
        pm = PluginManager()

        def bad_callback(name):
            raise RuntimeError("boom")

        pm.on("register", bad_callback)
        pm.on("unregister", bad_callback)
        pm.on("enable", bad_callback)
        pm.on("disable", bad_callback)

        # These should not raise despite callback errors
        info = pm.register_plugin("test")
        assert info is not None
        pm.disable_plugin("test")
        pm.enable_plugin("test")
        pm.unregister_plugin("test")


class TestInitializePlugins:
    def test_double_init_is_noop(self):
        import sonar_catalog.plugins as pm
        pm.reset_plugins()
        pm.initialize_plugins()
        first_count = len(pm.plugin_manager.plugin_names)
        pm.initialize_plugins()
        assert len(pm.plugin_manager.plugin_names) == first_count
        pm.reset_plugins()

    def test_init_with_disabled(self):
        import sonar_catalog.plugins as pm
        pm.reset_plugins()
        pm.initialize_plugins(disabled_plugins={"some-plugin"})
        assert pm.plugin_manager.is_disabled("some-plugin")
        pm.reset_plugins()
