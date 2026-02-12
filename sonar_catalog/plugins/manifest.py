"""
Plugin manifest parser.

Plugins can declare their capabilities via a sonar-plugin.yaml manifest
instead of (or in addition to) a register() function. The manifest format:

    name: my-sonar-plugin
    version: 1.0.0
    description: Adds support for FooBar sonar format

    contributions:
      formats:
        - name: foobar
          extensions: [".fb", ".fbar"]
          magic_bytes: "464f4f42"
          magic_offset: 0

      nav_extractors:
        - format: foobar
          python_name: my_package.extractors:FooBarExtractor
"""

import importlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FormatContribution:
    """A format declared by a plugin manifest."""

    name: str
    extensions: list[str] = field(default_factory=list)
    magic_bytes: str = ""  # hex-encoded
    magic_offset: int = 0


@dataclass
class NavExtractorContribution:
    """A nav extractor declared by a plugin manifest."""

    format: str
    python_name: str  # "package.module:ClassName"


@dataclass
class PluginManifest:
    """Parsed plugin manifest."""

    name: str
    version: str = "0.0.0"
    description: str = ""
    formats: list[FormatContribution] = field(default_factory=list)
    nav_extractors: list[NavExtractorContribution] = field(default_factory=list)


def load_manifest(yaml_text: str) -> PluginManifest:
    """Parse a sonar-plugin.yaml manifest string."""
    try:
        import yaml
    except ImportError:
        # Fall back to basic parsing if PyYAML not installed
        raise ImportError(
            "PyYAML is required to load plugin manifests. "
            "Install it with: pip install pyyaml"
        )

    data = yaml.safe_load(yaml_text)
    if not isinstance(data, dict):
        raise ValueError("Manifest must be a YAML mapping")

    name = data.get("name")
    if not name:
        raise ValueError("Manifest must have a 'name' field")

    manifest = PluginManifest(
        name=name,
        version=str(data.get("version", "0.0.0")),
        description=data.get("description", ""),
    )

    contributions = data.get("contributions", {})

    for fmt_data in contributions.get("formats", []):
        manifest.formats.append(FormatContribution(
            name=fmt_data["name"],
            extensions=fmt_data.get("extensions", []),
            magic_bytes=fmt_data.get("magic_bytes", ""),
            magic_offset=fmt_data.get("magic_offset", 0),
        ))

    for nav_data in contributions.get("nav_extractors", []):
        manifest.nav_extractors.append(NavExtractorContribution(
            format=nav_data["format"],
            python_name=nav_data["python_name"],
        ))

    return manifest


def find_manifest_in_package(module) -> Optional[str]:
    """
    Look for sonar-plugin.yaml in a plugin module's package.

    Checks the module's directory for the manifest file.
    """
    try:
        module_path = Path(module.__file__).parent
        manifest_path = module_path / "sonar-plugin.yaml"
        if manifest_path.exists():
            return manifest_path.read_text()
    except (AttributeError, TypeError, OSError):
        pass
    return None


def _import_object(python_name: str):
    """
    Import an object from a 'module.path:ObjectName' string.

    Example: "my_package.extractors:FooBarExtractor" -> <class FooBarExtractor>
    """
    if ":" not in python_name:
        raise ValueError(f"python_name must be 'module:name', got: {python_name}")

    module_path, obj_name = python_name.rsplit(":", 1)
    module = importlib.import_module(module_path)
    return getattr(module, obj_name)


def register_from_manifest(manager, manifest: PluginManifest):
    """Register a plugin's contributions from its parsed manifest."""

    # Register format contributions
    if manifest.formats:
        # Build signatures and extension maps from manifest
        sigs = {}
        ext_map = {}

        for fmt in manifest.formats:
            if fmt.magic_bytes:
                try:
                    sig_bytes = bytes.fromhex(fmt.magic_bytes)
                    sigs[sig_bytes] = fmt.name
                except ValueError:
                    logger.warning(
                        f"Plugin {manifest.name}: invalid magic_bytes: {fmt.magic_bytes}"
                    )

            for ext in fmt.extensions:
                ext_map[ext.lower()] = fmt.name

        if sigs:
            manager.register_hook_impl(
                "get_format_signatures", manifest.name,
                lambda _sigs=sigs: dict(_sigs),
                priority=50,  # manifest plugins override builtin
            )

        if ext_map:
            manager.register_hook_impl(
                "get_extension_map", manifest.name,
                lambda _map=ext_map: dict(_map),
                priority=50,
            )

    # Register nav extractor contributions
    for nav_contrib in manifest.nav_extractors:
        try:
            extractor_cls = _import_object(nav_contrib.python_name)

            def _make_extract_func(cls, fmt):
                def extract_nav(file_path=None, sonar_format=None, **kwargs):
                    if sonar_format != fmt:
                        return None
                    ext = cls()
                    if ext.can_handle(file_path, sonar_format):
                        result = ext.extract(file_path, sonar_format)
                        if result and result.track:
                            return result
                    return None
                return extract_nav

            manager.register_hook_impl(
                "extract_nav", manifest.name,
                _make_extract_func(extractor_cls, nav_contrib.format),
                priority=50,
            )
        except Exception as e:
            logger.warning(
                f"Plugin {manifest.name}: failed to load nav extractor "
                f"{nav_contrib.python_name}: {e}"
            )
