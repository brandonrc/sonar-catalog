"""
Sonar Catalog - Petabyte-scale file deduplication and indexing system
for sonar data across distributed NFS-mounted systems.
"""

try:
    from ._version import version as __version__
    from ._version import version_tuple
except ImportError:
    # Fallback for running from source without install
    __version__ = "0.0.0.dev0"
    version_tuple = (0, 0, 0, "dev0")
