"""Tests for CLI commands that require mocked infrastructure (discover, crawl)."""

import argparse
import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from sonar_catalog.config import Config, DatabaseConfig, DiscoveryConfig, CrawlerConfig
from sonar_catalog.database import CatalogDB
from sonar_catalog.cli import cmd_discover, cmd_crawl, cmd_crawl_all, cmd_web


@pytest.fixture
def config_with_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    config = Config()
    config.database = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
    # Initialize DB
    with CatalogDB(config.database) as db:
        pass
    return config


class TestCmdDiscover:
    @patch("sonar_catalog.cli.DiscoveryEngine")
    def test_discover_basic(self, mock_engine_cls, config_with_db, capsys):
        mock_engine = MagicMock()
        mock_engine.run_full_discovery.return_value = ({}, [])
        mock_engine_cls.return_value = mock_engine

        args = argparse.Namespace(deep=False)
        cmd_discover(args, config_with_db)
        captured = capsys.readouterr()
        assert "Discovery Results" in captured.out
        assert "Hosts found: 0" in captured.out

    @patch("sonar_catalog.cli.DiscoveryEngine")
    def test_discover_with_hosts(self, mock_engine_cls, config_with_db, capsys):
        from sonar_catalog.discovery import DiscoveredHost, MountPoint

        hosts = {
            "192.168.1.10": DiscoveredHost(
                ip="192.168.1.10", hostname="sonar-01",
                discovery_method="autofs", ssh_accessible=True,
            ),
            "192.168.1.11": DiscoveredHost(
                ip="192.168.1.11", hostname="sonar-02",
                discovery_method="ip_neigh", ssh_accessible=False,
            ),
        }
        mounts = [
            MountPoint(
                local_path="/auto/nfs/sonar01",
                remote_host="sonar-01",
                remote_path="/export/data",
                source="autofs", fstype="nfs",
            )
        ]

        mock_engine = MagicMock()
        mock_engine.run_full_discovery.return_value = (hosts, mounts)
        mock_engine_cls.return_value = mock_engine

        args = argparse.Namespace(deep=False)
        cmd_discover(args, config_with_db)
        captured = capsys.readouterr()
        assert "Hosts found: 2" in captured.out
        assert "SSH accessible: 1" in captured.out
        assert "sonar-01" in captured.out
        assert "sonar-02" in captured.out

    @patch("sonar_catalog.cli.DiscoveryEngine")
    def test_discover_deep(self, mock_engine_cls, config_with_db, capsys):
        from sonar_catalog.discovery import DiscoveredHost

        hosts = {
            "192.168.1.10": DiscoveredHost(
                ip="192.168.1.10", hostname="sonar-01",
                discovery_method="autofs", ssh_accessible=True,
            ),
        }
        mock_engine = MagicMock()
        mock_engine.run_full_discovery.return_value = (hosts, [])
        mock_engine.ssh_discover_remote_mounts.return_value = []
        mock_engine_cls.return_value = mock_engine

        args = argparse.Namespace(deep=True)
        cmd_discover(args, config_with_db)
        captured = capsys.readouterr()
        assert "Deep discovery" in captured.out


class TestCmdCrawl:
    @patch("sonar_catalog.cli.FileCrawler")
    @patch("sonar_catalog.cli.MountResolver")
    def test_crawl_basic(self, mock_resolver_cls, mock_crawler_cls, config_with_db, tmp_path, capsys):
        crawl_dir = tmp_path / "data"
        crawl_dir.mkdir()

        mock_resolver = MagicMock()
        mock_resolver.get_nfs_mounts.return_value = []
        mock_resolver_cls.return_value = mock_resolver

        mock_crawler = MagicMock()
        mock_crawler.crawl_local.return_value = {
            "files_found": 10,
            "files_new": 8,
            "files_skipped": 2,
            "files_error": 0,
            "bytes_hashed": 1024000,
        }
        mock_crawler_cls.return_value = mock_crawler

        args = argparse.Namespace(
            path=str(crawl_dir), host=None, ip=None,
        )
        cmd_crawl(args, config_with_db)
        captured = capsys.readouterr()
        assert "Crawling" in captured.out
        assert "complete" in captured.out.lower()

    def test_crawl_nonexistent_path(self, config_with_db, capsys):
        args = argparse.Namespace(
            path="/nonexistent/directory", host=None, ip=None,
        )
        with pytest.raises(SystemExit):
            cmd_crawl(args, config_with_db)


class TestCmdCrawlAll:
    @patch("sonar_catalog.cli.FileCrawler")
    @patch("sonar_catalog.cli.MountResolver")
    @patch("sonar_catalog.cli.DiscoveryEngine")
    def test_crawl_all(self, mock_engine_cls, mock_resolver_cls, mock_crawler_cls,
                       config_with_db, capsys):
        mock_engine = MagicMock()
        mock_engine.run_full_discovery.return_value = ({}, [])
        mock_engine_cls.return_value = mock_engine

        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_crawler = MagicMock()
        mock_crawler_cls.return_value = mock_crawler

        args = argparse.Namespace()
        cmd_crawl_all(args, config_with_db)
        # Should not error


class TestCmdWeb:
    def test_web_runs(self, config_with_db, capsys):
        """Test web command starts the Flask app."""
        args = argparse.Namespace(host="127.0.0.1", port=8080, debug=False)
        mock_app = MagicMock()
        with patch("sonar_catalog.web.create_app", return_value=mock_app):
            cmd_web(args, config_with_db)
            mock_app.run.assert_called_once_with(
                host="127.0.0.1", port=8080, debug=False,
            )

    def test_web_no_flask(self, config_with_db, capsys):
        """Test web command when Flask isn't importable."""
        args = argparse.Namespace(host="127.0.0.1", port=8080, debug=False)
        import sonar_catalog.web as web_mod
        original = web_mod.create_app
        try:
            del web_mod.create_app
            with patch.dict("sys.modules", {"sonar_catalog.web": None}):
                with pytest.raises(SystemExit):
                    cmd_web(args, config_with_db)
        finally:
            web_mod.create_app = original


class TestMainErrorHandling:
    @pytest.fixture(autouse=True)
    def reset(self):
        from sonar_catalog.plugins import reset_plugins
        reset_plugins()
        yield
        reset_plugins()

    def test_keyboard_interrupt(self, tmp_path, capsys):
        """Test that KeyboardInterrupt is handled gracefully."""
        db_path = str(tmp_path / "test.db")
        with patch("sys.argv", ["sonar-catalog", "init"]), \
             patch("sonar_catalog.cli.Config.load") as mock_load, \
             patch("sonar_catalog.cli.cmd_init") as mock_cmd:
            config = Config()
            config.database = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
            mock_load.return_value = config
            mock_cmd.side_effect = KeyboardInterrupt

            from sonar_catalog.cli import main
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 130

    def test_generic_exception(self, tmp_path, capsys):
        """Test that generic exceptions are caught and reported."""
        db_path = str(tmp_path / "test.db")
        with patch("sys.argv", ["sonar-catalog", "init"]), \
             patch("sonar_catalog.cli.Config.load") as mock_load, \
             patch("sonar_catalog.cli.cmd_init") as mock_cmd:
            config = Config()
            config.database = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
            mock_load.return_value = config
            mock_cmd.side_effect = RuntimeError("test error")

            from sonar_catalog.cli import main
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1
            captured = capsys.readouterr()
            assert "test error" in captured.err
