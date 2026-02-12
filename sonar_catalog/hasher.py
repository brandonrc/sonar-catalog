"""
Content-addressable hashing with two-pass deduplication.

Strategy:
1. Quick fingerprint: file size + BLAKE3 hash of first 4MB + last 4MB
2. If fingerprint is new, compute full BLAKE3 hash
3. Full hash becomes the content key in the catalog

This avoids hashing terabytes of data that we've already cataloged.
"""

import hashlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# Try to use blake3 native library (much faster), fall back to hashlib
try:
    import blake3 as _blake3
    HAS_NATIVE_BLAKE3 = True
    logger.debug("Using native blake3 library")
except ImportError:
    HAS_NATIVE_BLAKE3 = False
    logger.debug("Native blake3 not available, using hashlib fallback")


@dataclass
class FileFingerprint:
    """Quick fingerprint for fast dedup check."""
    size: int
    partial_hash: str  # hash of first+last chunks

    @property
    def key(self) -> str:
        return f"{self.size}:{self.partial_hash}"


@dataclass
class FileHash:
    """Full content hash result."""
    path: str
    size: int
    partial_hash: str
    full_hash: str
    algorithm: str


def _create_hasher(algorithm: str = "blake3"):
    """Create a new hash object."""
    if algorithm == "blake3":
        if HAS_NATIVE_BLAKE3:
            return _blake3.blake3()
        else:
            # Python 3.11+ has blake3 in hashlib on some builds
            try:
                return hashlib.new("blake3")
            except ValueError:
                logger.warning("BLAKE3 not available, falling back to SHA-256")
                return hashlib.sha256()
    elif algorithm == "sha256":
        return hashlib.sha256()
    else:
        raise ValueError(f"Unknown hash algorithm: {algorithm}")


class FileHasher:
    """Handles file hashing with two-pass dedup optimization."""

    def __init__(
        self,
        algorithm: str = "blake3",
        partial_size: int = 4 * 1024 * 1024,  # 4MB
        workers: int = 4,
        read_buffer: int = 1024 * 1024,  # 1MB read chunks
    ):
        self.algorithm = algorithm
        self.partial_size = partial_size
        self.workers = workers
        self.read_buffer = read_buffer

    def compute_fingerprint(self, path: str) -> Optional[FileFingerprint]:
        """
        Compute a quick fingerprint: size + hash of first/last chunks.
        This is fast even for huge files.
        """
        try:
            stat = os.stat(path)
            size = stat.st_size

            if size == 0:
                return FileFingerprint(size=0, partial_hash="empty")

            hasher = _create_hasher(self.algorithm)

            with open(path, "rb") as f:
                # Read first chunk
                hasher.update(f.read(self.partial_size))

                # If file is larger than 2x partial_size, also read last chunk
                if size > self.partial_size * 2:
                    f.seek(-self.partial_size, os.SEEK_END)
                    hasher.update(f.read(self.partial_size))

                    # Also mix in the file size to avoid collisions
                    hasher.update(str(size).encode())

            return FileFingerprint(
                size=size,
                partial_hash=hasher.hexdigest(),
            )

        except PermissionError:
            logger.debug(f"Permission denied: {path}")
            return None
        except FileNotFoundError:
            logger.debug(f"File not found: {path}")
            return None
        except OSError as e:
            logger.debug(f"OS error reading {path}: {e}")
            return None

    def compute_full_hash(self, path: str) -> Optional[FileHash]:
        """Compute the full content hash of a file."""
        try:
            stat = os.stat(path)
            size = stat.st_size

            if size == 0:
                return FileHash(
                    path=path, size=0,
                    partial_hash="empty",
                    full_hash="empty",
                    algorithm=self.algorithm,
                )

            # Compute partial hash at the same time
            partial_hasher = _create_hasher(self.algorithm)
            full_hasher = _create_hasher(self.algorithm)

            partial_done = False
            bytes_read = 0

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(self.read_buffer)
                    if not chunk:
                        break

                    full_hasher.update(chunk)
                    bytes_read += len(chunk)

                    # Build partial hash from first chunk
                    if not partial_done and bytes_read <= self.partial_size:
                        partial_hasher.update(chunk)

                    if not partial_done and bytes_read >= self.partial_size:
                        partial_done = True

            # For partial hash, also include last chunk if file is large enough
            if size > self.partial_size * 2:
                last_hasher = _create_hasher(self.algorithm)
                with open(path, "rb") as f:
                    # Read first chunk
                    last_hasher.update(f.read(self.partial_size))
                    # Read last chunk
                    f.seek(-self.partial_size, os.SEEK_END)
                    last_hasher.update(f.read(self.partial_size))
                    last_hasher.update(str(size).encode())
                partial_hash = last_hasher.hexdigest()
            else:
                partial_hash = partial_hasher.hexdigest()

            return FileHash(
                path=path,
                size=size,
                partial_hash=partial_hash,
                full_hash=full_hasher.hexdigest(),
                algorithm=self.algorithm,
            )

        except PermissionError:
            logger.debug(f"Permission denied: {path}")
            return None
        except FileNotFoundError:
            logger.debug(f"File not found: {path}")
            return None
        except OSError as e:
            logger.debug(f"OS error hashing {path}: {e}")
            return None

    def hash_files_batch(
        self,
        paths: list[str],
        known_fingerprints: set[str] = None,
        progress_callback: Optional[Callable] = None,
    ) -> list[FileHash]:
        """
        Hash a batch of files with two-pass dedup.

        Args:
            paths: List of file paths to hash.
            known_fingerprints: Set of fingerprint keys already in the catalog.
                               Files matching these skip full hashing.
            progress_callback: Called with (completed_count, total_count) updates.

        Returns:
            List of FileHash results (only for files needing full hash or new files).
        """
        known_fingerprints = known_fingerprints or set()
        results = []
        needs_full_hash = []
        skipped = 0

        # Phase 1: Quick fingerprint check
        logger.info(f"Phase 1: Fingerprinting {len(paths)} files...")
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self.compute_fingerprint, p): p
                for p in paths
            }
            for i, future in enumerate(as_completed(futures)):
                path = futures[future]
                try:
                    fp = future.result()
                    if fp is None:
                        continue

                    if fp.key in known_fingerprints:
                        skipped += 1
                    else:
                        needs_full_hash.append(path)
                except Exception as e:
                    logger.warning(f"Fingerprint error for {path}: {e}")

                if progress_callback and (i + 1) % 100 == 0:
                    progress_callback(i + 1, len(paths))

        logger.info(
            f"Phase 1 complete: {skipped} skipped (already known), "
            f"{len(needs_full_hash)} need full hash"
        )

        # Phase 2: Full hash for new files
        if needs_full_hash:
            logger.info(f"Phase 2: Full hashing {len(needs_full_hash)} files...")
            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                futures = {
                    executor.submit(self.compute_full_hash, p): p
                    for p in needs_full_hash
                }
                for i, future in enumerate(as_completed(futures)):
                    path = futures[future]
                    try:
                        fh = future.result()
                        if fh:
                            results.append(fh)
                    except Exception as e:
                        logger.warning(f"Hash error for {path}: {e}")

                    if progress_callback and (i + 1) % 100 == 0:
                        progress_callback(i + 1, len(needs_full_hash))

        logger.info(f"Phase 2 complete: {len(results)} new files hashed")
        return results
