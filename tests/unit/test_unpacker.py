import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest


class TestUnpack:

    def test_no_upx_returns_original(self, sample_pe_file):
        from unpacking.unpacker import UnpackFile
        with patch("unpacking.unpacker.UPX_PATH", None):
            path, tmp = UnpackFile.unpack(sample_pe_file)
        assert path == sample_pe_file
        assert tmp is None

    def test_missing_upx_binary(self, sample_pe_file):
        from unpacking.unpacker import UnpackFile
        with patch("unpacking.unpacker.UPX_PATH", "/no/such/file"):
            path, tmp = UnpackFile.unpack(sample_pe_file)
        assert path == sample_pe_file
        assert tmp is None

    def test_happy_path(self, sample_pe_file, tmp_path):
        from unpacking.unpacker import UnpackFile

        workdir = str(tmp_path / "wk")
        os.makedirs(workdir)

        unpacked = os.path.join(workdir, "unpacked_test_sample.exe")
        with open(unpacked, "wb") as fh:
            fh.write(b"decompressed")

        with patch("unpacking.unpacker.UPX_PATH", "/usr/bin/upx"), \
             patch("unpacking.unpacker.subprocess.run", return_value=MagicMock(returncode=0)), \
             patch("unpacking.unpacker.shutil.copy2"), \
             patch("unpacking.unpacker.tempfile.mkdtemp", return_value=workdir):
            path, tmp = UnpackFile.unpack(sample_pe_file)

        assert path == unpacked
        assert tmp == workdir

    def test_upx_nonzero_exit(self, sample_pe_file):
        from unpacking.unpacker import UnpackFile
        with patch("unpacking.unpacker.UPX_PATH", "/usr/bin/upx"), \
             patch("unpacking.unpacker.subprocess.run", return_value=MagicMock(returncode=1)), \
             patch("unpacking.unpacker.shutil.copy2"), \
             patch("unpacking.unpacker.shutil.rmtree") as rm, \
             patch("unpacking.unpacker.tempfile.mkdtemp", return_value="/tmp/fail"), \
             patch("unpacking.unpacker.os.path.exists", return_value=True):
            path, tmp = UnpackFile.unpack(sample_pe_file)

        assert path == sample_pe_file
        assert tmp is None
        rm.assert_called_once_with("/tmp/fail")

    def test_unexpected_exception(self, sample_pe_file):
        from unpacking.unpacker import UnpackFile
        with patch("unpacking.unpacker.UPX_PATH", "/usr/bin/upx"), \
             patch("unpacking.unpacker.subprocess.run", side_effect=OSError("nope")), \
             patch("unpacking.unpacker.shutil.copy2"), \
             patch("unpacking.unpacker.shutil.rmtree"), \
             patch("unpacking.unpacker.os.path.exists", return_value=True), \
             patch("unpacking.unpacker.tempfile.mkdtemp", return_value="/tmp/err"):
            path, tmp = UnpackFile.unpack(sample_pe_file)

        assert path == sample_pe_file
        assert tmp is None


class TestCleanup:

    def test_removes_directory(self):
        from unpacking.unpacker import UnpackFile
        d = tempfile.mkdtemp()
        assert os.path.isdir(d)
        UnpackFile.cleanup(d)
        assert not os.path.exists(d)

    def test_none_is_safe(self):
        from unpacking.unpacker import UnpackFile
        UnpackFile.cleanup(None)

    def test_missing_dir_is_safe(self):
        from unpacking.unpacker import UnpackFile
        UnpackFile.cleanup("/definitely/not/here")

    @patch("unpacking.unpacker.shutil.rmtree", side_effect=PermissionError)
    def test_os_error_swallowed(self, _):
        from unpacking.unpacker import UnpackFile
        UnpackFile.cleanup("/some/dir")  # should not raise

    def test_nested_contents_gone(self):
        from unpacking.unpacker import UnpackFile
        d = tempfile.mkdtemp()
        for i in range(5):
            with open(os.path.join(d, f"f{i}.txt"), "w") as fh:
                fh.write(str(i))
        UnpackFile.cleanup(d)
        assert not os.path.exists(d)
