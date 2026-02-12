"""
Configuration management for Sonar Catalog.
"""

import os
import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "sonar-catalog" / "config.json"
DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "sonar-catalog" / "catalog.db"


@dataclass
class DatabaseConfig:
    """Database connection settings."""
    # Use PostgreSQL by default; fall back to SQLite for single-machine setups
    backend: str = "postgresql"  # "postgresql" or "sqlite"
    # PostgreSQL settings
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_database: str = "sonar_catalog"
    pg_user: str = "sonar_catalog"
    pg_password: str = ""
    # SQLite fallback
    sqlite_path: str = str(DEFAULT_DB_PATH)


@dataclass
class DiscoveryConfig:
    """Host and mount discovery settings."""
    # SSH settings
    ssh_user: str = "xyz"
    ssh_timeout: int = 3  # seconds
    ssh_key_path: Optional[str] = None
    # Authentication method: "key" (default), "sshpass_file", "sshpass_env"
    #   key          = use SSH key (ssh-agent or ssh_key_path)
    #   sshpass_file = read password from ssh_password_file
    #   sshpass_env  = read password from SSHPASS environment variable
    ssh_auth_method: str = "key"
    ssh_password_file: Optional[str] = None  # path to file containing password (mode 0600)
    # Host key handling: "accept-new" (recommended), "no" (skip all checks), "yes" (strict)
    ssh_host_key_policy: str = "accept-new"
    # Network discovery
    scan_subnets: list = field(default_factory=list)  # e.g. ["192.168.1.0/24"]
    hostname_patterns: list = field(default_factory=list)  # e.g. ["sonar-*", "ss-*"]
    ip_ranges: list = field(default_factory=list)  # explicit IP ranges to include
    # Discovery methods to enable
    use_autofs: bool = True
    use_ip_neigh: bool = True
    use_showmount: bool = True
    use_subnet_scan: bool = False  # off by default, more aggressive
    # Host whitelist/blacklist (IPs or hostnames)
    host_whitelist: list = field(default_factory=list)
    host_blacklist: list = field(default_factory=list)
    # Paths to search for sonar data on discovered hosts
    search_paths: list = field(default_factory=lambda: [
        "/data", "/sonar", "/survey", "/mnt", "/export"
    ])


@dataclass
class CrawlerConfig:
    """File crawler settings."""
    # Hashing
    hash_algorithm: str = "blake3"  # "blake3" or "sha256"
    partial_hash_size: int = 4 * 1024 * 1024  # 4MB for quick partial hash
    hash_workers: int = 4  # parallel hashing threads
    # Crawling
    crawl_workers: int = 2  # parallel filesystem walks
    batch_size: int = 1000  # DB insert batch size
    # File filters
    min_file_size: int = 0  # skip files smaller than this
    max_file_size: int = 0  # 0 = no limit
    include_extensions: list = field(default_factory=list)  # empty = all
    exclude_extensions: list = field(default_factory=lambda: [
        ".tmp", ".swp", ".lock", ".pid"
    ])
    exclude_dirs: list = field(default_factory=lambda: [
        ".git", ".svn", "__pycache__", ".Trash", "lost+found"
    ])
    # Incremental scan: skip files whose mtime+size match catalog
    incremental: bool = True
    # Checkpoint interval (files processed between saves)
    checkpoint_interval: int = 5000


@dataclass
class MetadataConfig:
    """Metadata extraction settings."""
    use_file_command: bool = True
    use_magic: bool = True  # python-magic for MIME detection
    # Known sonar file extensions for deeper parsing
    sonar_extensions: list = field(default_factory=lambda: [
        ".xtf", ".jsf", ".s7k", ".all", ".wcd", ".kmall",
        ".db",   # Humminbird
        ".sl2", ".sl3",  # Lowrance
        ".son",  # Garmin
        ".raw",  # generic raw sonar
        ".sgy", ".segy",  # SEG-Y seismic/sub-bottom
        ".bag",  # bathymetric attributed grid
        ".tif", ".tiff",  # GeoTIFF (often sidescan mosaics)
        ".csv", ".xyz",  # point clouds / bathymetry exports
    ])
    # Custom magic byte signatures added at runtime via:
    #   sonar-catalog config add-magic-byte <sample_file>
    #
    # Stored as list of dicts:
    #   [{"format": "cool-custom", "hex_bytes": "89504e47", "byte_length": 4,
    #     "offset": 0, "extension": ".sonarfile", "description": "Cool custom format"}]
    #
    # hex_bytes = hex-encoded magic bytes extracted from a sample file
    # offset    = byte offset in the file where the signature starts (usually 0)
    custom_magic_bytes: list = field(default_factory=list)
    # Custom extension-to-format mappings (supplement the built-in ones)
    # e.g. {".sonarfile": "cool-custom", ".dat": "proprietary-sonar"}
    custom_extension_map: dict = field(default_factory=dict)


@dataclass
class Config:
    """Top-level configuration."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    metadata: MetadataConfig = field(default_factory=MetadataConfig)
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    def save(self, path: Optional[Path] = None):
        """Save configuration to JSON file."""
        path = Path(path or DEFAULT_CONFIG_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)
        logger.info(f"Configuration saved to {path}")

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        """Load configuration from JSON file, or return defaults."""
        path = Path(path or DEFAULT_CONFIG_PATH)
        if not path.exists():
            logger.info(f"No config at {path}, using defaults")
            return cls()

        with open(path) as f:
            data = json.load(f)

        config = cls()
        if "database" in data:
            config.database = DatabaseConfig(**data["database"])
        if "discovery" in data:
            config.discovery = DiscoveryConfig(**data["discovery"])
        if "crawler" in data:
            config.crawler = CrawlerConfig(**data["crawler"])
        if "metadata" in data:
            config.metadata = MetadataConfig(**data["metadata"])
        if "log_level" in data:
            config.log_level = data["log_level"]
        if "log_file" in data:
            config.log_file = data["log_file"]

        return config
