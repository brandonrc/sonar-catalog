"""Tests for the file hashing system."""

import os
import pytest

from sonar_catalog.hasher import FileHasher, FileFingerprint, FileHash, _create_hasher


class TestCreateHasher:
    def test_sha256(self):
        h = _create_hasher("sha256")
        h.update(b"test")
        assert len(h.hexdigest()) == 64

    def test_blake3_fallback(self):
        """blake3 should work (either native or via hashlib or sha256 fallback)."""
        h = _create_hasher("blake3")
        h.update(b"test")
        digest = h.hexdigest()
        assert len(digest) > 0

    def test_unknown_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unknown hash algorithm"):
            _create_hasher("md5")


class TestFileFingerprint:
    def test_key_format(self):
        fp = FileFingerprint(size=1024, partial_hash="abc123")
        assert fp.key == "1024:abc123"


class TestFileHasher:
    @pytest.fixture
    def hasher(self):
        return FileHasher(algorithm="sha256", partial_size=64, workers=1, read_buffer=32)

    def test_compute_fingerprint_small_file(self, hasher, tmp_path):
        f = tmp_path / "small.txt"
        f.write_bytes(b"hello world")
        fp = hasher.compute_fingerprint(str(f))
        assert fp is not None
        assert fp.size == 11
        assert isinstance(fp.partial_hash, str)

    def test_compute_fingerprint_empty_file(self, hasher, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        fp = hasher.compute_fingerprint(str(f))
        assert fp is not None
        assert fp.size == 0
        assert fp.partial_hash == "empty"

    def test_compute_fingerprint_large_file(self, hasher, tmp_path):
        """File > 2 * partial_size triggers first+last chunk hashing."""
        f = tmp_path / "large.bin"
        f.write_bytes(b"A" * 200)  # 200 > 2 * 64
        fp = hasher.compute_fingerprint(str(f))
        assert fp is not None
        assert fp.size == 200

    def test_compute_fingerprint_missing_file(self, hasher):
        fp = hasher.compute_fingerprint("/nonexistent/path/file.bin")
        assert fp is None

    def test_compute_fingerprint_deterministic(self, hasher, tmp_path):
        f = tmp_path / "det.bin"
        f.write_bytes(b"deterministic content")
        fp1 = hasher.compute_fingerprint(str(f))
        fp2 = hasher.compute_fingerprint(str(f))
        assert fp1.partial_hash == fp2.partial_hash

    def test_compute_full_hash_small_file(self, hasher, tmp_path):
        f = tmp_path / "full_small.txt"
        f.write_bytes(b"test data for hashing")
        fh = hasher.compute_full_hash(str(f))
        assert fh is not None
        assert fh.path == str(f)
        assert fh.size == 21
        assert isinstance(fh.full_hash, str)
        assert isinstance(fh.partial_hash, str)
        assert fh.algorithm == "sha256"

    def test_compute_full_hash_empty_file(self, hasher, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        fh = hasher.compute_full_hash(str(f))
        assert fh is not None
        assert fh.size == 0
        assert fh.full_hash == "empty"

    def test_compute_full_hash_large_file(self, hasher, tmp_path):
        """File > 2 * partial_size uses separate last-chunk hashing."""
        f = tmp_path / "large.bin"
        content = bytes(range(256)) * 2  # 512 bytes > 2 * 64
        f.write_bytes(content)
        fh = hasher.compute_full_hash(str(f))
        assert fh is not None
        assert fh.size == 512
        assert fh.full_hash != "empty"
        assert fh.partial_hash != "empty"

    def test_compute_full_hash_missing_file(self, hasher):
        fh = hasher.compute_full_hash("/nonexistent/file.bin")
        assert fh is None

    def test_hash_files_batch(self, hasher, tmp_path):
        paths = []
        for i in range(5):
            f = tmp_path / f"file_{i}.bin"
            f.write_bytes(f"content_{i}".encode() * 10)
            paths.append(str(f))

        results = hasher.hash_files_batch(paths)
        assert len(results) == 5

    def test_hash_files_batch_with_known(self, hasher, tmp_path):
        """Files with known fingerprints should be skipped."""
        f1 = tmp_path / "known.bin"
        f1.write_bytes(b"known content")

        # First, compute its fingerprint
        fp = hasher.compute_fingerprint(str(f1))
        known = {fp.key}

        # Now batch hash - should skip it
        results = hasher.hash_files_batch([str(f1)], known_fingerprints=known)
        assert len(results) == 0

    def test_hash_files_batch_mixed(self, hasher, tmp_path):
        """Mix of known and unknown files."""
        f1 = tmp_path / "known.bin"
        f1.write_bytes(b"known content")
        f2 = tmp_path / "new.bin"
        f2.write_bytes(b"new content")

        fp1 = hasher.compute_fingerprint(str(f1))
        known = {fp1.key}

        results = hasher.hash_files_batch([str(f1), str(f2)], known_fingerprints=known)
        assert len(results) == 1
        assert results[0].path == str(f2)

    def test_hash_files_batch_with_progress(self, hasher, tmp_path):
        paths = []
        for i in range(3):
            f = tmp_path / f"prog_{i}.bin"
            f.write_bytes(f"prog_content_{i}".encode())
            paths.append(str(f))

        progress_calls = []
        results = hasher.hash_files_batch(
            paths, progress_callback=lambda c, t: progress_calls.append((c, t))
        )
        assert len(results) == 3

    def test_hash_files_batch_empty(self, hasher):
        results = hasher.hash_files_batch([])
        assert results == []
