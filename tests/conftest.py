"""Shared test fixtures for sonar-catalog tests."""

import os
import tempfile

import pytest

from sonar_catalog.config import DatabaseConfig, CrawlerConfig, MetadataConfig
from sonar_catalog.database import CatalogDB
from sonar_catalog.mount_resolver import MountResolver, MountEntry


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary SQLite-backed CatalogDB."""
    db_path = str(tmp_path / "test_catalog.db")
    config = DatabaseConfig(backend="sqlite", sqlite_path=db_path)
    db = CatalogDB(config)
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def mock_resolver():
    """Create a MountResolver pre-loaded with test NFS mounts."""
    resolver = MountResolver()
    resolver._loaded = True

    resolver.add_mount(MountEntry(
        local_path="/auto/nfs/sonar01",
        remote_server="sonar-server-01",
        remote_path="/export/survey",
        fstype="nfs4",
        source="autofs_map",
    ))
    resolver.add_mount(MountEntry(
        local_path="/mnt/sonar02",
        remote_server="sonar-server-02",
        remote_path="/data/sidescan",
        fstype="nfs",
        source="proc_mounts",
    ))
    return resolver


@pytest.fixture
def crawler_config():
    """Default crawler config for tests."""
    return CrawlerConfig()


@pytest.fixture
def metadata_config():
    """Default metadata config for tests."""
    return MetadataConfig()
