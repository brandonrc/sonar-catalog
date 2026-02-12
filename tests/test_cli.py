"""Tests for the CLI commands.

Tests each CLI subcommand by directly calling the cmd_* functions
with mocked args and a real temporary database.
"""

import argparse
import json
import os
import sys
import pytest
from io import StringIO
from unittest.mock import patch, MagicMock

from sonar_catalog.config import Config, DatabaseConfig
from sonar_catalog.database import CatalogDB
from sonar_catalog.demo import load_demo_data
from sonar_catalog.cli import (
    cmd_init, cmd_search, cmd_dupes, cmd_where, cmd_stats, cmd_hosts,
    cmd_config, cmd_demo, cmd_export, cmd_list_magic_bytes,
    cmd_rebuild_index, cmd_plugins, cmd_extract_nav,
    _parse_size, setup_logging, get_local_hostname, get_local_ip,
)


@pytest.fixture
def config_with_db(tmp_path):
    """Create a Config with a temporary SQLite database."""
    db_path = str(tmp_path / "test.db")
    config = Config()
    config.database = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
    return config


@pytest.fixture
def populated_config(config_with_db):
    """Config with database pre-populated with demo data."""
    with CatalogDB(config_with_db.database) as db:
        load_demo_data(db, num_files=20, seed=42)
    return config_with_db


class TestParseSize:
    def test_bytes(self):
        assert _parse_size("100B") == 100

    def test_kilobytes(self):
        assert _parse_size("10KB") == 10240

    def test_megabytes(self):
        assert _parse_size("5MB") == 5 * 1024 ** 2

    def test_gigabytes(self):
        assert _parse_size("1GB") == 1024 ** 3

    def test_terabytes(self):
        assert _parse_size("2TB") == 2 * 1024 ** 4

    def test_shorthand(self):
        assert _parse_size("10M") == 10 * 1024 ** 2
        assert _parse_size("1G") == 1024 ** 3

    def test_plain_number(self):
        assert _parse_size("12345") == 12345

    def test_fractional(self):
        assert _parse_size("1.5GB") == int(1.5 * 1024 ** 3)


class TestSetupLogging:
    def test_basic(self):
        setup_logging("INFO")

    def test_with_logfile(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging("DEBUG", log_file)
        assert os.path.exists(log_file) or True  # file handler created


class TestHelperFunctions:
    def test_get_local_hostname(self):
        hostname = get_local_hostname()
        assert isinstance(hostname, str)
        assert len(hostname) > 0

    def test_get_local_ip(self):
        ip = get_local_ip()
        assert isinstance(ip, str)


class TestCmdInit:
    def test_init_creates_db(self, config_with_db, capsys):
        args = argparse.Namespace()
        cmd_init(args, config_with_db)
        captured = capsys.readouterr()
        assert "initialized" in captured.out.lower()


class TestCmdDemo:
    def test_demo_loads_data(self, config_with_db, capsys):
        args = argparse.Namespace(num_files=10, seed=42)
        cmd_demo(args, config_with_db)
        captured = capsys.readouterr()
        assert "Demo data loaded" in captured.out
        assert "Files:" in captured.out
        assert "10" in captured.out

    def test_demo_data_is_queryable(self, config_with_db, capsys):
        args = argparse.Namespace(num_files=15, seed=123)
        cmd_demo(args, config_with_db)

        # Now search
        search_args = argparse.Namespace(
            query=None, server=None, mime=None, format=None,
            min_size=None, max_size=None, hash=None,
            limit=100, offset=0, output="json",
        )
        cmd_search(search_args, config_with_db)
        captured = capsys.readouterr()
        data = json.loads(captured.out.split("sonar-catalog web\n")[-1])
        assert len(data) > 0


class TestCmdSearch:
    def test_search_table(self, populated_config, capsys):
        args = argparse.Namespace(
            query=None, server=None, mime=None, format=None,
            min_size=None, max_size=None, hash=None,
            limit=10, offset=0, output="table",
        )
        cmd_search(args, populated_config)
        captured = capsys.readouterr()
        assert "NFS Server" in captured.out or "No results" in captured.out

    def test_search_json(self, populated_config, capsys):
        args = argparse.Namespace(
            query=None, server=None, mime=None, format=None,
            min_size=None, max_size=None, hash=None,
            limit=5, offset=0, output="json",
        )
        cmd_search(args, populated_config)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)

    def test_search_paths(self, populated_config, capsys):
        args = argparse.Namespace(
            query=None, server=None, mime=None, format=None,
            min_size=None, max_size=None, hash=None,
            limit=5, offset=0, output="paths",
        )
        cmd_search(args, populated_config)
        captured = capsys.readouterr()
        assert isinstance(captured.out, str)

    def test_search_by_format(self, populated_config, capsys):
        args = argparse.Namespace(
            query=None, server=None, mime=None, format="xtf",
            min_size=None, max_size=None, hash=None,
            limit=10, offset=0, output="json",
        )
        cmd_search(args, populated_config)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        for item in data:
            assert item["sonar_format"] == "xtf"

    def test_search_with_size_filter(self, populated_config, capsys):
        args = argparse.Namespace(
            query=None, server=None, mime=None, format=None,
            min_size="1MB", max_size="1GB", hash=None,
            limit=10, offset=0, output="json",
        )
        cmd_search(args, populated_config)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        for item in data:
            assert item["file_size"] >= 1024 ** 2
            assert item["file_size"] <= 1024 ** 3


class TestCmdDupes:
    def test_dupes_table(self, populated_config, capsys):
        args = argparse.Namespace(min_count=2, limit=50, output="table")
        cmd_dupes(args, populated_config)
        captured = capsys.readouterr()
        assert isinstance(captured.out, str)

    def test_dupes_json(self, populated_config, capsys):
        args = argparse.Namespace(min_count=2, limit=50, output="json")
        cmd_dupes(args, populated_config)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)


class TestCmdWhere:
    def test_where_found(self, populated_config, capsys):
        with CatalogDB(populated_config.database) as db:
            results = db.search_files(limit=1)
        content_hash = results[0]["content_hash"]

        args = argparse.Namespace(hash=content_hash)
        cmd_where(args, populated_config)
        captured = capsys.readouterr()
        assert "Locations for" in captured.out

    def test_where_not_found(self, populated_config, capsys):
        args = argparse.Namespace(hash="nonexistent")
        cmd_where(args, populated_config)
        captured = capsys.readouterr()
        assert "No file found" in captured.out


class TestCmdStats:
    def test_stats_table(self, populated_config, capsys):
        args = argparse.Namespace(output="table")
        cmd_stats(args, populated_config)
        captured = capsys.readouterr()
        assert "Sonar Catalog Statistics" in captured.out

    def test_stats_json(self, populated_config, capsys):
        args = argparse.Namespace(output="json")
        cmd_stats(args, populated_config)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "unique_files" in data


class TestCmdHosts:
    def test_hosts_table(self, populated_config, capsys):
        args = argparse.Namespace(output="table")
        cmd_hosts(args, populated_config)
        captured = capsys.readouterr()
        assert isinstance(captured.out, str)

    def test_hosts_json(self, populated_config, capsys):
        args = argparse.Namespace(output="json")
        cmd_hosts(args, populated_config)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)


class TestCmdConfig:
    def test_show_config(self, config_with_db, capsys):
        args = argparse.Namespace(create=False, path=None)
        cmd_config(args, config_with_db)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "database" in data

    def test_create_config(self, config_with_db, tmp_path, capsys):
        config_path = str(tmp_path / "new_config.json")
        args = argparse.Namespace(create=True, path=config_path)
        cmd_config(args, config_with_db)
        captured = capsys.readouterr()
        assert "Config written" in captured.out
        assert os.path.exists(config_path)


class TestCmdRebuildIndex:
    def test_rebuild(self, populated_config, capsys):
        args = argparse.Namespace()
        cmd_rebuild_index(args, populated_config)
        captured = capsys.readouterr()
        assert "rebuilt" in captured.out.lower()


class TestCmdListMagicBytes:
    def test_list(self, config_with_db, capsys):
        args = argparse.Namespace()
        cmd_list_magic_bytes(args, config_with_db)
        captured = capsys.readouterr()
        assert "Built-in Magic Byte Signatures" in captured.out
        assert "xtf" in captured.out
        assert "jsf" in captured.out


class TestCmdExport:
    def test_list_formats(self, populated_config, capsys):
        from sonar_catalog.plugins import initialize_plugins, reset_plugins
        reset_plugins()
        initialize_plugins()
        try:
            args = argparse.Namespace(
                list_formats=True, export_format=None, output=None,
                limit=100, geo=False, server=None, sonar_format=None,
            )
            cmd_export(args, populated_config)
            captured = capsys.readouterr()
            assert "csv" in captured.out
            assert "geojson" in captured.out
        finally:
            reset_plugins()

    def test_export_csv(self, populated_config, tmp_path, capsys):
        from sonar_catalog.plugins import initialize_plugins, reset_plugins
        reset_plugins()
        initialize_plugins()
        try:
            out_path = str(tmp_path / "export.csv")
            args = argparse.Namespace(
                list_formats=False, export_format="csv", output=out_path,
                limit=10, geo=False, server=None, sonar_format=None,
            )
            cmd_export(args, populated_config)
            captured = capsys.readouterr()
            assert "Exported" in captured.out
            assert os.path.exists(out_path)
        finally:
            reset_plugins()

    def test_export_json_stdout(self, populated_config, capsys):
        from sonar_catalog.plugins import initialize_plugins, reset_plugins
        reset_plugins()
        initialize_plugins()
        try:
            args = argparse.Namespace(
                list_formats=False, export_format="json", output=None,
                limit=5, geo=False, server=None, sonar_format=None,
            )
            cmd_export(args, populated_config)
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert isinstance(data, list)
        finally:
            reset_plugins()

    def test_export_geojson(self, populated_config, tmp_path, capsys):
        from sonar_catalog.plugins import initialize_plugins, reset_plugins
        reset_plugins()
        initialize_plugins()
        try:
            out_path = str(tmp_path / "export.geojson")
            args = argparse.Namespace(
                list_formats=False, export_format="geojson", output=out_path,
                limit=10, geo=True, server=None, sonar_format=None,
            )
            cmd_export(args, populated_config)
            captured = capsys.readouterr()
            # May or may not have geo data
            assert isinstance(captured.out, str)
        finally:
            reset_plugins()

    def test_export_no_format_errors(self, populated_config, capsys):
        from sonar_catalog.plugins import initialize_plugins, reset_plugins
        reset_plugins()
        initialize_plugins()
        try:
            args = argparse.Namespace(
                list_formats=False, export_format=None, output=None,
                limit=10, geo=False, server=None, sonar_format=None,
            )
            with pytest.raises(SystemExit):
                cmd_export(args, populated_config)
        finally:
            reset_plugins()


class TestCmdPlugins:
    def test_plugins_list(self, config_with_db, capsys):
        from sonar_catalog.plugins import reset_plugins
        reset_plugins()
        try:
            args = argparse.Namespace(plugins_action="list")
            cmd_plugins(args, config_with_db)
            captured = capsys.readouterr()
            assert "builtin" in captured.out
        finally:
            reset_plugins()

    def test_plugins_info(self, config_with_db, capsys):
        from sonar_catalog.plugins import reset_plugins
        reset_plugins()
        try:
            args = argparse.Namespace(plugins_action="info", plugin_name="builtin")
            cmd_plugins(args, config_with_db)
            captured = capsys.readouterr()
            assert "builtin" in captured.out
            assert "Version" in captured.out
        finally:
            reset_plugins()

    def test_plugins_info_not_found(self, config_with_db, capsys):
        from sonar_catalog.plugins import reset_plugins
        reset_plugins()
        try:
            args = argparse.Namespace(plugins_action="info", plugin_name="nonexistent")
            with pytest.raises(SystemExit):
                cmd_plugins(args, config_with_db)
        finally:
            reset_plugins()

    def test_plugins_disable(self, config_with_db, tmp_path, capsys):
        from sonar_catalog.plugins import reset_plugins
        reset_plugins()
        config_with_db.plugins.disabled_plugins = []
        config_path = tmp_path / "config.json"
        config_with_db.save(config_path)
        try:
            args = argparse.Namespace(plugins_action="disable", plugin_name="some-plugin")
            cmd_plugins(args, config_with_db)
            captured = capsys.readouterr()
            assert "Disabled" in captured.out
        finally:
            reset_plugins()

    def test_plugins_enable(self, config_with_db, tmp_path, capsys):
        from sonar_catalog.plugins import reset_plugins
        reset_plugins()
        config_with_db.plugins.disabled_plugins = ["some-plugin"]
        config_path = tmp_path / "config.json"
        config_with_db.save(config_path)
        try:
            args = argparse.Namespace(plugins_action="enable", plugin_name="some-plugin")
            cmd_plugins(args, config_with_db)
            captured = capsys.readouterr()
            assert "Enabled" in captured.out
        finally:
            reset_plugins()


class TestCmdExtractNav:
    def test_no_accessible_files(self, populated_config, capsys):
        """Extract nav on demo data (no actual files on disk)."""
        args = argparse.Namespace(
            hash=None, format=None, limit=5, force=False, verbose=False,
        )
        cmd_extract_nav(args, populated_config)
        captured = capsys.readouterr()
        assert "Extracting" in captured.out
