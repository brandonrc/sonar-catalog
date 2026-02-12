"""Tests for configuration loading and saving."""

import json
import pytest

from sonar_catalog.config import (
    Config, DatabaseConfig, DiscoveryConfig, CrawlerConfig,
    MetadataConfig, NavExtractionConfig, PluginConfig,
    DEFAULT_CONFIG_PATH, DEFAULT_DB_PATH,
)


class TestDatabaseConfig:
    def test_defaults(self):
        c = DatabaseConfig()
        assert c.backend == "sqlite"
        assert c.pg_host == "localhost"
        assert c.pg_port == 5432
        assert c.sqlite_path == str(DEFAULT_DB_PATH)


class TestDiscoveryConfig:
    def test_defaults(self):
        c = DiscoveryConfig()
        assert c.ssh_timeout == 3
        assert c.ssh_auth_method == "key"
        assert c.use_autofs is True
        assert c.use_subnet_scan is False
        assert len(c.search_paths) > 0


class TestCrawlerConfig:
    def test_defaults(self):
        c = CrawlerConfig()
        assert c.hash_algorithm == "blake3"
        assert c.batch_size == 1000
        assert c.incremental is True
        assert ".tmp" in c.exclude_extensions
        assert ".git" in c.exclude_dirs

    def test_partial_hash_size(self):
        c = CrawlerConfig()
        assert c.partial_hash_size == 4 * 1024 * 1024


class TestNavExtractionConfig:
    def test_defaults(self):
        c = NavExtractionConfig()
        assert c.enabled is True
        assert c.max_track_points == 1000
        assert c.timeout_seconds == 30


class TestMetadataConfig:
    def test_defaults(self):
        c = MetadataConfig()
        assert c.use_file_command is True
        assert ".xtf" in c.sonar_extensions
        assert ".jsf" in c.sonar_extensions
        assert c.nav_extraction.enabled is True

    def test_custom_magic_bytes_default_empty(self):
        c = MetadataConfig()
        assert c.custom_magic_bytes == []
        assert c.custom_extension_map == {}


class TestPluginConfig:
    def test_defaults(self):
        c = PluginConfig()
        assert c.disabled_plugins == []


class TestConfig:
    def test_defaults(self):
        c = Config()
        assert c.database.backend == "sqlite"
        assert c.log_level == "INFO"
        assert c.log_file is None

    def test_save_and_load(self, tmp_path):
        config = Config()
        config.log_level = "DEBUG"
        config.database.backend = "sqlite"
        config.database.sqlite_path = str(tmp_path / "test.db")
        config.plugins.disabled_plugins = ["some-plugin"]

        config_path = tmp_path / "config.json"
        config.save(config_path)

        assert config_path.exists()
        loaded = Config.load(config_path)
        assert loaded.log_level == "DEBUG"
        assert loaded.database.sqlite_path == str(tmp_path / "test.db")
        assert loaded.plugins.disabled_plugins == ["some-plugin"]

    def test_load_nonexistent_returns_defaults(self, tmp_path):
        config = Config.load(tmp_path / "nonexistent.json")
        assert config.database.backend == "sqlite"
        assert config.log_level == "INFO"

    def test_save_creates_parent_dirs(self, tmp_path):
        config = Config()
        path = tmp_path / "nested" / "deep" / "config.json"
        config.save(path)
        assert path.exists()

    def test_load_with_all_sections(self, tmp_path):
        data = {
            "database": {"backend": "sqlite", "sqlite_path": "/tmp/test.db",
                         "pg_host": "dbhost", "pg_port": 5433,
                         "pg_database": "mydb", "pg_user": "user", "pg_password": "pass"},
            "discovery": {"ssh_user": "testuser", "ssh_timeout": 5,
                          "use_autofs": False, "use_ip_neigh": True,
                          "use_showmount": False, "use_subnet_scan": True,
                          "scan_subnets": ["10.0.0.0/24"],
                          "hostname_patterns": [], "ip_ranges": [],
                          "host_whitelist": [], "host_blacklist": [],
                          "search_paths": ["/data"],
                          "ssh_key_path": None, "ssh_auth_method": "key",
                          "ssh_password_file": None, "ssh_host_key_policy": "accept-new"},
            "crawler": {"hash_algorithm": "sha256", "partial_hash_size": 1048576,
                        "hash_workers": 2, "crawl_workers": 1, "batch_size": 500,
                        "min_file_size": 100, "max_file_size": 0,
                        "include_extensions": [], "exclude_extensions": [".tmp"],
                        "exclude_dirs": [".git"], "incremental": False,
                        "checkpoint_interval": 1000},
            "metadata": {"use_file_command": False, "use_magic": False,
                         "sonar_extensions": [".xtf"],
                         "custom_magic_bytes": [{"format": "test", "hex_bytes": "aabb"}],
                         "custom_extension_map": {".test": "test"},
                         "nav_extraction": {"enabled": False, "max_track_points": 500,
                                            "extract_from_binary": True,
                                            "timeout_seconds": 10,
                                            "sidecar_patterns": []}},
            "plugins": {"disabled_plugins": ["bad-plugin"]},
            "log_level": "WARNING",
            "log_file": "/tmp/test.log",
        }
        config_path = tmp_path / "full.json"
        with open(config_path, "w") as f:
            json.dump(data, f)

        config = Config.load(config_path)
        assert config.database.backend == "sqlite"
        assert config.database.pg_host == "dbhost"
        assert config.discovery.ssh_user == "testuser"
        assert config.discovery.use_autofs is False
        assert config.crawler.hash_algorithm == "sha256"
        assert config.crawler.incremental is False
        assert config.metadata.use_file_command is False
        assert config.metadata.nav_extraction.enabled is False
        assert config.metadata.nav_extraction.max_track_points == 500
        assert config.plugins.disabled_plugins == ["bad-plugin"]
        assert config.log_level == "WARNING"
        assert config.log_file == "/tmp/test.log"

    def test_load_partial_config(self, tmp_path):
        data = {"log_level": "ERROR"}
        config_path = tmp_path / "partial.json"
        with open(config_path, "w") as f:
            json.dump(data, f)

        config = Config.load(config_path)
        assert config.log_level == "ERROR"
        # Everything else should be defaults
        assert config.database.backend == "sqlite"
        assert config.crawler.hash_algorithm == "blake3"
