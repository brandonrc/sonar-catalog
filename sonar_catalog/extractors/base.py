"""Base classes for navigation data extraction."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NavResult:
    """Result from a navigation extractor."""

    track: list[list[float]]  # [[lat, lon], ...]
    source: str  # extractor identifier, e.g. "jsf_nav", "sidecar:file.nav"
    point_count_original: int = 0


class NavExtractor(ABC):
    """Base class for navigation data extractors."""

    supported_formats: list[str] = []

    def can_handle(self, file_path: str, sonar_format: Optional[str] = None) -> bool:
        """Check if this extractor can handle the given file."""
        if sonar_format and sonar_format in self.supported_formats:
            return True
        return False

    @abstractmethod
    def extract(self, file_path: str, sonar_format: Optional[str] = None) -> Optional[NavResult]:
        """Extract navigation track from a file. Returns NavResult or None."""
        ...
