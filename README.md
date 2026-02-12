# Sonar Catalog

Petabyte-scale sonar file catalog with content-based deduplication across distributed NFS systems. Automatically discovers hosts, resolves NFS mount topologies, crawls filesystems, extracts navigation tracks, and serves everything through a searchable web UI with a CesiumJS 3D globe.

```
sonar-catalog init
sonar-catalog crawl /mnt/sonar-nas-01
sonar-catalog web
```

---

## Architecture

```mermaid
graph TB
    subgraph CLI["CLI (cli.py)"]
        init[init]
        discover[discover]
        crawl[crawl / crawl-all]
        search[search / dupes / where]
        extractnav[extract-nav]
        demo[demo]
        export[export]
        web[web]
    end

    subgraph Core["Core Engine"]
        DE[Discovery Engine]
        MR[Mount Resolver]
        FC[File Crawler]
        FH[File Hasher]
        CS[Catalog Search]
    end

    subgraph Plugins["Plugin System"]
        PM[Plugin Manager]
        HS[Hook Specs]
        BI[Built-in Plugin]
        TP[Third-Party Plugins]
    end

    subgraph Storage["Storage Layer"]
        DB[(SQLite / PostgreSQL)]
        FTS[FTS5 Full-Text Index]
    end

    subgraph Extractors["Nav Extractors"]
        JSF[JSF Parser]
        XTF[XTF Parser]
        NMEA[NMEA Parser]
        SC[Sidecar Reader]
    end

    subgraph WebUI["Web Interface"]
        Flask[Flask App]
        API[REST API]
        Globe[CesiumJS Globe]
        Search2[Search UI]
    end

    discover --> DE
    crawl --> FC
    FC --> FH
    FC --> MR
    search --> CS
    extractnav --> Extractors
    web --> Flask

    DE --> DB
    FC --> DB
    CS --> DB
    API --> DB
    FTS -.-> DB

    PM --> HS
    BI --> PM
    TP --> PM
    FC -.-> PM
    Extractors -.-> PM

    Flask --> API
    Flask --> Globe
    Flask --> Search2
```

---

## Data Flow

How a file goes from disk to searchable catalog entry:

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Discovery as Discovery Engine
    participant Resolver as Mount Resolver
    participant Crawler as File Crawler
    participant Hasher as File Hasher
    participant Extractor as Nav Extractor
    participant DB as Database

    User->>CLI: sonar-catalog crawl /mnt/nas01
    CLI->>Resolver: Load NFS mounts (proc, autofs, fstab)
    Resolver-->>CLI: Mount table ready

    CLI->>Crawler: crawl_local("/mnt/nas01")
    loop Each file in directory tree
        Crawler->>Crawler: Walk filesystem, apply filters
        Crawler->>Hasher: Partial hash (first 4MB)
        Hasher-->>Crawler: Fingerprint

        alt New fingerprint
            Crawler->>Hasher: Full content hash (BLAKE3)
            Hasher-->>Crawler: content_hash
        else Known fingerprint
            Crawler->>Crawler: Skip (already cataloged)
        end

        Crawler->>Resolver: Resolve /mnt/nas01/data/file.xtf
        Resolver-->>Crawler: nas01:/export/survey/data/file.xtf

        Crawler->>Extractor: Extract nav from .xtf
        Extractor-->>Crawler: Track [[lat,lon], ...]
    end

    Crawler->>DB: Batch insert (files + locations + nav)
    DB-->>User: Stats: 1,247 files, 892 new, 355 deduped
```

---

## Database Schema

```mermaid
erDiagram
    files ||--o{ locations : "content_hash"
    files ||--o| file_metadata : "content_hash"

    files {
        text content_hash PK "BLAKE3 / SHA-256"
        bigint file_size
        text partial_hash "First 4MB hash"
        text hash_algorithm
        text mime_type
        text sonar_format "xtf, jsf, s7k, ..."
        timestamp first_seen
        timestamp last_seen
    }

    locations {
        bigint id PK
        text content_hash FK
        text nfs_server "Origin NFS server"
        text nfs_export "Server export path"
        text remote_path "Full path on origin"
        text canonical_path UK "server:/full/path"
        boolean is_local
        text access_path "Local mount path"
        text access_hostname "Crawling machine"
        text mount_source "proc, autofs, fstab"
        text file_name
        text directory
        timestamp mtime
    }

    file_metadata {
        text content_hash PK
        text metadata "JSON (track, properties)"
        real lat_min
        real lat_max
        real lon_min
        real lon_max
        real lat_center
        real lon_center
        integer has_nav
    }

    hosts {
        text ip_address PK
        text hostname
        text discovery_method
        boolean ssh_accessible
        text scan_status
        timestamp last_scan_at
    }

    scans {
        bigint id PK
        text target_path
        text hostname
        text status
        integer files_found
        integer files_new
    }
```

**Key concept:** No data is copied. The catalog stores *pointers*. If the same file appears on 10 NFS servers, there is **one row in `files`** and **10 rows in `locations`**, each pointing back to its canonical NFS origin.

---

## Plugin Architecture

Inspired by [napari](https://github.com/napari/napari)'s plugin system. All built-in functionality (format detection, nav extraction, export) is registered through the same hook system that third-party plugins use.

```mermaid
graph LR
    subgraph Discovery["Plugin Discovery"]
        EP["entry_points()"]
        MF["sonar-plugin.yaml"]
    end

    subgraph Manager["Plugin Manager"]
        REG[Register]
        EN[Enable / Disable]
        CALL[Call Hook]
    end

    subgraph Hooks["Hook Specs (7 extension points)"]
        H1["detect_format (firstresult)"]
        H2["extract_nav (firstresult)"]
        H3["get_format_signatures (historic)"]
        H4["get_extension_map (historic)"]
        H5["export_data (firstresult)"]
        H6["get_export_formats (historic)"]
        H7["register_web_routes (historic)"]
    end

    subgraph Builtin["Built-in Plugin"]
        FMT[Format Detection]
        NAV[Nav Extraction]
        EXP[CSV / GeoJSON / JSON]
    end

    subgraph ThirdParty["Third-Party Plugin"]
        TP1["my_sonar_plugin"]
    end

    EP --> REG
    MF --> REG
    REG --> EN
    EN --> CALL
    CALL --> Hooks

    FMT --> H1
    FMT --> H3
    FMT --> H4
    NAV --> H2
    EXP --> H5
    EXP --> H6
    TP1 -.-> H1
    TP1 -.-> H2
```

### Hook Modes

| Mode | Behavior | Example |
|---|---|---|
| **firstresult** | First plugin to return non-`None` wins (short-circuits) | Format detection, nav extraction |
| **historic** | All plugins contribute results (collected into a list) | Signature registration, export formats |

### Writing a Plugin

Create a Python package with an entry point:

```toml
# pyproject.toml
[project.entry-points."sonar_catalog.plugins"]
my_plugin = "my_sonar_plugin"
```

```python
# my_sonar_plugin/__init__.py
def register(manager):
    manager.register_plugin(
        name="my-plugin",
        version="1.0.0",
        description="Adds FooBar sonar format support",
    )

    manager.register_hook_impl(
        "detect_format", "my-plugin", detect_foobar
    )
    manager.register_hook_impl(
        "extract_nav", "my-plugin", extract_foobar_nav
    )


def detect_foobar(file_path=None, header=None, extension=None, **kw):
    if header and header[:4] == b"\xFO\x0B\xAR":
        return "foobar"
    return None


def extract_foobar_nav(file_path=None, sonar_format=None, **kw):
    if sonar_format != "foobar":
        return None
    # ... parse binary nav data ...
    from sonar_catalog.extractors.base import NavResult
    return NavResult(track=[[56.0, 3.0], [56.1, 3.1]], source="foobar_nav")
```

Or use a YAML manifest instead of code:

```yaml
# sonar-plugin.yaml
name: my-sonar-plugin
version: 1.0.0
contributions:
  formats:
    - name: foobar
      extensions: [".fb", ".fbar"]
      magic_bytes: "f00bar"
      magic_offset: 0
  nav_extractors:
    - format: foobar
      python_name: my_package.extractors:FooBarExtractor
```

---

## NFS Mount Resolution

The mount resolver determines the canonical origin of every file by cross-referencing multiple mount sources:

```mermaid
flowchart TD
    FILE["/mnt/sonar01/project/line_001.xtf"]

    subgraph Sources["Mount Sources (loaded once)"]
        PROC["/proc/mounts"]
        FSTAB["/etc/fstab"]
        AUTOFS["automount -m"]
        MOUNT["mount command"]
    end

    PROC --> TABLE
    FSTAB --> TABLE
    AUTOFS --> TABLE
    MOUNT --> TABLE

    TABLE["Mount Table"]

    FILE --> MATCH{"Longest prefix match"}
    TABLE --> MATCH

    MATCH --> |"/mnt/sonar01 → nas01:/export/survey"| RESULT

    RESULT["Canonical: nas01:/export/survey/project/line_001.xtf"]

    style RESULT fill:#065f46,stroke:#10b981,color:#fff
```

This means the same file accessed from different machines (different local mount points) resolves to the same canonical path, enabling cross-machine deduplication.

---

## Host Discovery

```mermaid
flowchart LR
    subgraph Methods["Discovery Methods"]
        A["autofs maps"]
        B["showmount -e"]
        C["ip neigh (ARP)"]
        D["Subnet scan"]
    end

    A --> MERGE
    B --> MERGE
    C --> MERGE
    D --> MERGE

    MERGE["Merge & Deduplicate\n(by IP)"]

    MERGE --> FILTER["Apply hostname\npatterns & blacklist"]

    FILTER --> SSH["SSH Probe\n(parallel)"]

    SSH --> |accessible| READY["Ready to Crawl"]
    SSH --> |unreachable| SKIP["Skipped"]

    style READY fill:#065f46,stroke:#10b981,color:#fff
    style SKIP fill:#7f1d1d,stroke:#ef4444,color:#fff
```

---

## Nav Extraction Pipeline

```mermaid
flowchart TD
    FILE["Sonar File"]

    FILE --> CHECK{"Format?"}

    CHECK --> |".jsf"| JSF["JSF Parser\n(Message type 80: NMEA)"]
    CHECK --> |".xtf"| XTF["XTF Parser\n(PingHeader lat/lon)"]
    CHECK --> |any| SIDECAR["Sidecar Search\n({stem}.nav, {stem}.csv)"]

    JSF --> NMEA["NMEA Parser\n(GGA, RMC, GLL)"]
    NMEA --> TRACK
    XTF --> TRACK
    SIDECAR --> |found| CSV["CSV / JSON\ncompanion parser"]
    CSV --> TRACK
    SIDECAR --> |not found| NONE["No nav data"]

    TRACK["Raw Track\n[[lat,lon], ...]"]

    TRACK --> DS["Downsample\n(max 1000 points)"]
    DS --> BOUNDS["Compute Bounds\n(bbox + center)"]
    BOUNDS --> DB["Store in\nfile_metadata"]

    style DB fill:#065f46,stroke:#10b981,color:#fff
    style NONE fill:#7f1d1d,stroke:#ef4444,color:#fff
```

---

## Two-Pass Deduplication

The hasher uses a two-pass strategy to minimize I/O on large files:

```mermaid
flowchart LR
    FILE["File\n(500 MB)"] --> P1["Pass 1: Partial Hash\n(first 4 MB → BLAKE3)"]

    P1 --> CHECK{"Fingerprint\nknown?"}

    CHECK --> |"New"| P2["Pass 2: Full Hash\n(all 500 MB → BLAKE3)"]
    CHECK --> |"Seen before"| SKIP["Skip\n(already cataloged)"]

    P2 --> INSERT["Insert file +\nlocation"]

    style SKIP fill:#065f46,stroke:#10b981,color:#fff
    style INSERT fill:#1e3a5f,stroke:#3b82f6,color:#fff
```

For a typical NFS share with 80% unchanged files, this skips reading ~80% of bytes on incremental scans.

---

## Web Interface

```mermaid
graph TB
    subgraph Flask["Flask Application"]
        VBP["Views Blueprint\n/ and /globe"]
        ABP["API Blueprint\n/api/*"]
        PLUG["Plugin Routes\n(register_web_routes hook)"]
    end

    subgraph Pages["Pages"]
        SEARCH["Search UI\n(Tailwind CSS)"]
        GLOBE["CesiumJS Globe\n(3D track visualization)"]
    end

    subgraph Endpoints["REST API"]
        E1["GET /api/search"]
        E2["GET /api/stats"]
        E3["GET /api/files/:hash"]
        E4["GET /api/duplicates"]
        E5["GET /api/hosts"]
        E6["GET /api/geo/points"]
        E7["GET /api/geo/track/:hash"]
        E8["GET /api/geo/bounds"]
        E9["GET /api/servers"]
        E10["GET /api/formats"]
    end

    VBP --> SEARCH
    VBP --> GLOBE
    ABP --> Endpoints
    GLOBE --> E6
    GLOBE --> E7
    GLOBE --> E8
    SEARCH --> E1
    SEARCH --> E2

    style GLOBE fill:#1e3a5f,stroke:#3b82f6,color:#fff
```

The globe view renders file locations as color-coded markers (by sonar format) on a 3D CesiumJS globe. Clicking a marker loads and displays the navigation track as a polyline.

---

## Supported Sonar Formats

| Format | Extensions | Detection | Nav Extraction |
|---|---|---|---|
| XTF (eXtended Triton Format) | `.xtf` | Magic bytes `0x0100` | PingHeader lat/lon fields |
| JSF (EdgeTech) | `.jsf` | Magic bytes `0x1616` | NMEA from message type 80 |
| Kongsberg .all | `.all` | Magic bytes `0x49` | - |
| Kongsberg KMALL | `.kmall` | Magic bytes `0x4B4D` | - |
| Reson S7K | `.s7k` | Extension | - |
| BAG (Bathymetric Attributed Grid) | `.bag` | Extension | - |
| SEG-Y | `.sgy`, `.segy` | Extension | - |
| Humminbird | `.db` | Extension | - |
| Lowrance | `.sl2`, `.sl3` | Extension | - |
| Raw | `.raw` | Extension | - |
| Custom | configurable | Magic bytes + extension | Via plugin |

Add custom formats at runtime:
```bash
sonar-catalog add-magic-byte sample.myformat --format-name my_sonar --length 4
```

---

## Installation

```bash
# Minimal (SQLite only, no external dependencies)
pip install .

# With all optional features
pip install ".[all]"

# Individual extras
pip install ".[web]"       # Flask web UI + CesiumJS globe
pip install ".[blake3]"    # BLAKE3 hashing (faster than SHA-256)
pip install ".[postgres]"  # PostgreSQL backend
pip install ".[magic]"     # python-magic MIME detection

# Development
pip install -e ".[dev,all]"
```

Zero required dependencies. The core runs on Python 3.10+ stdlib only (sqlite3, hashlib, subprocess, socket).

---

## Quick Start

```bash
# Initialize the database
sonar-catalog init

# Option A: Crawl a real NFS mount
sonar-catalog crawl /mnt/sonar-nas-01

# Option B: Load synthetic demo data (no real sonar files needed)
sonar-catalog demo --num-files 100

# Extract navigation tracks from cataloged files
sonar-catalog extract-nav

# Explore
sonar-catalog stats
sonar-catalog search "line_001"
sonar-catalog dupes
sonar-catalog where <content_hash>

# Start the web UI
sonar-catalog web --port 8080
# Open http://localhost:8080        (search)
# Open http://localhost:8080/globe  (3D globe)
```

### Auto-Discovery Mode

```bash
# Discover all NFS hosts on the network, then crawl everything
sonar-catalog discover --deep
sonar-catalog crawl-all
```

---

## CLI Reference

| Command | Description |
|---|---|
| `init` | Initialize database and config |
| `discover` | Discover NFS hosts and mounts on the network |
| `crawl <path>` | Crawl and catalog a directory |
| `crawl-all` | Discover and crawl all accessible hosts |
| `search` | Search the catalog (supports FTS5) |
| `dupes` | Find duplicate files across servers |
| `where <hash>` | Show all locations for a file by content hash |
| `stats` | Show catalog statistics |
| `hosts` | List discovered hosts |
| `extract-nav` | Extract navigation data from cataloged sonar files |
| `export` | Export data to CSV, GeoJSON, or JSON |
| `demo` | Load synthetic demo data for exploring the UI |
| `plugins list` | List installed plugins and their hooks |
| `plugins enable/disable <name>` | Enable or disable a plugin |
| `add-magic-byte <file>` | Learn a new format's magic bytes from a sample file |
| `list-magic-bytes` | Show all registered magic byte signatures |
| `rebuild-index` | Rebuild the FTS5 search index |
| `config` | Show current configuration as JSON |
| `web` | Start the Flask web interface |

---

## Configuration

Configuration lives at `~/.config/sonar-catalog/config.json`. All fields are optional — defaults work out of the box.

```json
{
  "database": {
    "backend": "sqlite",
    "sqlite_path": "~/.local/share/sonar-catalog/catalog.db"
  },
  "discovery": {
    "ssh_user": "survey",
    "ssh_timeout": 3,
    "hostname_patterns": ["sonar-*", "nas-*"],
    "use_autofs": true,
    "use_showmount": true
  },
  "crawler": {
    "hash_algorithm": "blake3",
    "partial_hash_size": 4194304,
    "hash_workers": 4,
    "batch_size": 1000,
    "incremental": true
  },
  "metadata": {
    "sonar_extensions": [".xtf", ".jsf", ".s7k", ".all", ".kmall", ".bag"],
    "nav_extraction": {
      "enabled": true,
      "max_track_points": 1000,
      "sidecar_patterns": [
        {
          "pattern": "{stem}.nav",
          "format": "csv",
          "lat_field": "lat",
          "lon_field": "lon"
        }
      ]
    }
  },
  "plugins": {
    "disabled_plugins": []
  }
}
```

---

## Project Structure

```
sonar_catalog/
    __init__.py
    cli.py                 # CLI entry point (18 subcommands)
    config.py              # Dataclass-based configuration
    database.py            # SQLite + PostgreSQL dual backend
    search.py              # FTS5-powered search engine
    crawler.py             # Filesystem walker + batch processor
    hasher.py              # Two-pass BLAKE3/SHA-256 deduplication
    discovery.py           # Network host + NFS mount discovery
    mount_resolver.py      # NFS mount topology resolution
    demo.py                # Synthetic data generator

    extractors/
        __init__.py        # Dispatcher (plugin-aware)
        base.py            # NavExtractor ABC + NavResult dataclass
        jsf.py             # EdgeTech JSF binary parser
        xtf.py             # eXtended Triton Format parser
        nmea.py            # GGA/RMC/GLL sentence parser
        sidecar.py         # Companion file reader (CSV/JSON)

    plugins/
        __init__.py        # Global singleton + initialize/reset
        hooks.py           # HookSpec with firstresult + historic modes
        manager.py         # PluginManager (discover, register, enable/disable)
        manifest.py        # YAML manifest parser (sonar-plugin.yaml)
        builtin/
            __init__.py    # Built-in plugin registration
            formats.py     # Magic byte signatures + extension map
            nav.py         # Nav extraction hook
            exporters.py   # CSV, GeoJSON, JSON export hooks

    web/
        __init__.py        # Flask app factory
        api.py             # REST API (10 endpoints)
        views.py           # Page routes (/ and /globe)
        templates/
            base.html      # Tailwind CSS layout
            index.html     # Search + stats page
            globe.html     # CesiumJS 3D globe
        static/
            app.js         # Search UI logic
            app.css        # Custom styles
            globe.js       # Globe rendering + track display

tests/                     # 396 tests, 80% coverage
```

---

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=sonar_catalog --cov-report=term-missing

# Specific module
pytest tests/test_extractors.py -v
```

**396 tests** covering the full stack: CLI dispatch, database operations, NFS resolution, format detection, nav extraction, plugin lifecycle, web API, and export hooks.

---

## License

MIT
