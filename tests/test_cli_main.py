"""Tests for CLI main() function and argparse integration."""

import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

from sonar_catalog.config import Config, DatabaseConfig
from sonar_catalog.cli import main, _parse_size, cmd_add_magic_byte


class TestMainArgparse:
    """Test the main() function's argparse dispatch."""

    @pytest.fixture(autouse=True)
    def reset_plugins(self):
        from sonar_catalog.plugins import reset_plugins
        reset_plugins()
        yield
        reset_plugins()

    def _run_main(self, args, tmp_db_path):
        """Run main() with given args and a temp database."""
        full_args = ["sonar-catalog", "--config", "/dev/null"] + args
        with patch("sys.argv", full_args), \
             patch("sonar_catalog.cli.Config.load") as mock_load:
            config = Config()
            config.database = DatabaseConfig(backend="sqlite", sqlite_path=tmp_db_path)
            mock_load.return_value = config
            main()

    def test_no_command_shows_help(self, capsys):
        with patch("sys.argv", ["sonar-catalog"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_version(self, capsys):
        with patch("sys.argv", ["sonar-catalog", "--version"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0

    def test_init_command(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        captured = capsys.readouterr()
        assert "initialized" in captured.out.lower()

    def test_stats_command(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        self._run_main(["stats"], db_path)
        captured = capsys.readouterr()
        assert "Statistics" in captured.out or "Unique" in captured.out

    def test_search_command(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        self._run_main(["search", "--output", "json"], db_path)
        captured = capsys.readouterr()
        # Should output valid JSON
        assert "[]" in captured.out or "[" in captured.out

    def test_dupes_command(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        self._run_main(["dupes", "--output", "json"], db_path)
        captured = capsys.readouterr()
        assert "[]" in captured.out

    def test_hosts_command(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        self._run_main(["hosts", "--output", "json"], db_path)
        captured = capsys.readouterr()
        assert "[]" in captured.out

    def test_config_show(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["config"], db_path)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "database" in data

    def test_demo_command(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        self._run_main(["demo", "--num-files", "10"], db_path)
        captured = capsys.readouterr()
        assert "Demo data loaded" in captured.out

    def test_list_magic_bytes(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["list-magic-bytes"], db_path)
        captured = capsys.readouterr()
        assert "Built-in Magic Byte" in captured.out

    def test_rebuild_index(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        self._run_main(["rebuild-index"], db_path)
        captured = capsys.readouterr()
        assert "rebuilt" in captured.out.lower()

    def test_plugins_list(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["plugins", "list"], db_path)
        captured = capsys.readouterr()
        assert "builtin" in captured.out

    def test_export_list_formats(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["export", "--list-formats"], db_path)
        captured = capsys.readouterr()
        assert "csv" in captured.out

    def test_verbose_flag(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["-v", "init"], db_path)
        captured = capsys.readouterr()
        assert "initialized" in captured.out.lower()

    def test_quiet_flag(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["-q", "init"], db_path)
        captured = capsys.readouterr()
        assert "initialized" in captured.out.lower()

    def test_where_command(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        self._run_main(["init"], db_path)
        self._run_main(["where", "nonexistent_hash"], db_path)
        captured = capsys.readouterr()
        assert "No file found" in captured.out


class TestCmdAddMagicByte:
    def test_add_magic_byte(self, tmp_path, capsys):
        """Test adding a custom magic byte signature."""
        sample = tmp_path / "sample.sonarformat"
        sample.write_bytes(b"\xDE\xAD\xBE\xEF" + b"\x00" * 100)

        config_path = str(tmp_path / "config.json")
        config = Config()

        args = MagicMock()
        args.file = str(sample)
        args.format_name = "dead_beef"
        args.length = 4
        args.offset = 0
        args.description = "Test format"
        args.no_extension = False
        args.force = False
        args.config_path = config_path

        cmd_add_magic_byte(args, config)
        captured = capsys.readouterr()
        assert "dead_beef" in captured.out
        assert "deadbeef" in captured.out
        assert os.path.exists(config_path)

    def test_add_magic_byte_no_format_name(self, tmp_path, capsys):
        """Derive format name from extension."""
        sample = tmp_path / "sample.foobar"
        sample.write_bytes(b"\xAA\xBB" * 10)

        config_path = str(tmp_path / "config.json")
        config = Config()

        args = MagicMock()
        args.file = str(sample)
        args.format_name = None
        args.length = 2
        args.offset = 0
        args.description = None
        args.no_extension = False
        args.force = False
        args.config_path = config_path

        cmd_add_magic_byte(args, config)
        captured = capsys.readouterr()
        assert "foobar" in captured.out

    def test_add_magic_byte_duplicate_no_force(self, tmp_path, capsys):
        sample = tmp_path / "sample.dup"
        sample.write_bytes(b"\x11\x22" * 10)

        config_path = str(tmp_path / "config.json")
        config = Config()
        config.metadata.custom_magic_bytes = [{"format": "dup", "hex_bytes": "1122"}]

        args = MagicMock()
        args.file = str(sample)
        args.format_name = "dup"
        args.length = 2
        args.offset = 0
        args.description = None
        args.no_extension = True
        args.force = False
        args.config_path = config_path

        with pytest.raises(SystemExit):
            cmd_add_magic_byte(args, config)

    def test_add_magic_byte_force_replace(self, tmp_path, capsys):
        sample = tmp_path / "sample.dup"
        sample.write_bytes(b"\x33\x44" * 10)

        config_path = str(tmp_path / "config.json")
        config = Config()
        config.metadata.custom_magic_bytes = [{"format": "dup", "hex_bytes": "1122"}]

        args = MagicMock()
        args.file = str(sample)
        args.format_name = "dup"
        args.length = 2
        args.offset = 0
        args.description = None
        args.no_extension = True
        args.force = True
        args.config_path = config_path

        cmd_add_magic_byte(args, config)
        captured = capsys.readouterr()
        assert "Replacing" in captured.out

    def test_add_magic_byte_nonexistent_file(self, capsys):
        config = Config()
        args = MagicMock()
        args.file = "/nonexistent/sample.xtf"
        args.format_name = "test"
        args.length = 4
        args.offset = 0
        args.description = None
        args.no_extension = False
        args.force = False
        args.config_path = None

        with pytest.raises(SystemExit):
            cmd_add_magic_byte(args, config)

    def test_add_magic_byte_with_offset(self, tmp_path, capsys):
        sample = tmp_path / "sample.off"
        sample.write_bytes(b"\x00\x00\xFF\xEE\xDD" + b"\x00" * 50)

        config_path = str(tmp_path / "config.json")
        config = Config()

        args = MagicMock()
        args.file = str(sample)
        args.format_name = "offset_fmt"
        args.length = 3
        args.offset = 2
        args.description = "Format with offset"
        args.no_extension = True
        args.force = False
        args.config_path = config_path

        cmd_add_magic_byte(args, config)
        captured = capsys.readouterr()
        assert "ffeedd" in captured.out
        assert "offset_fmt" in captured.out
