import json
import math
from unittest.mock import MagicMock, patch

import pytest


class TestEntropyCalculation:
    """calculate_entropy helpers."""

    def test_empty_file(self, empty_file):
        from detection.packer_detection import calculate_entropy
        assert calculate_entropy(empty_file) == 0

    def test_all_same_bytes_gives_zero(self, tmp_path):
        from detection.packer_detection import calculate_entropy
        p = tmp_path / "uniform.bin"
        p.write_bytes(b"\x42" * 1024)
        assert calculate_entropy(str(p)) == 0.0

    def test_two_byte_pattern(self, tmp_path):
        from detection.packer_detection import calculate_entropy
        p = tmp_path / "two.bin"
        p.write_bytes(b"\x00\xFF" * 512)
        assert math.isclose(calculate_entropy(str(p)), 1.0, abs_tol=0.01)

    def test_uniform_content_low_entropy(self, low_entropy_file):
        from detection.packer_detection import calculate_entropy
        assert calculate_entropy(low_entropy_file) < 0.5

    def test_randomish_content_high_entropy(self, high_entropy_file):
        from detection.packer_detection import calculate_entropy
        assert calculate_entropy(high_entropy_file) > 7.0

    def test_never_negative(self, sample_pe_file):
        from detection.packer_detection import calculate_entropy
        assert calculate_entropy(sample_pe_file) >= 0


# -- helpers for detect_packer tests ------------------------------------------

def _make_section(name):
    sec = MagicMock()
    sec.Name = name
    return sec


def _fake_pe_with(section_name):
    pe = MagicMock()
    pe.sections = [_make_section(section_name)]
    return pe


def _detect(sample_pe_file, die_returns=None, pe_side_effect=None, entropy_val=5.0):
    """Shorthand to run detect_packer with controlled mocks."""
    from detection.packer_detection import detect_packer

    with patch("detection.packer_detection.die") as die_mod, \
         patch("detection.packer_detection.pefile") as pe_mod, \
         patch("detection.packer_detection.calculate_entropy", return_value=entropy_val):

        if die_returns is not None:
            die_mod.scan_file.return_value = json.dumps(die_returns)
        # else: leave scan_file default (returns MagicMock -> will fail json.loads)

        if pe_side_effect is not None:
            pe_mod.PE.side_effect = pe_side_effect
        else:
            pe_mod.PE.return_value = _fake_pe_with(b".text\x00\x00\x00")

        return detect_packer(sample_pe_file)


# -- detect_packer tests ------------------------------------------------------

@pytest.mark.unit
class TestDetectPacker:

    def test_clean_file_no_flags(self, sample_pe_file):
        r = _detect(sample_pe_file, die_returns={"detects": []})
        assert not r["die_match"]
        assert not r["section_match"]
        assert not r["high_entropy"]

    def test_packer_found_via_die(self, sample_pe_file):
        data = {"detects": [
            {"type": "Packer", "name": "UPX", "version": "1.0"},
            {"type": "Compiler", "name": "GCC"},
        ]}
        r = _detect(sample_pe_file, die_returns=data)
        assert r["die_match"]
        assert any("UPX" in d for d in r["details"])

    def test_protector_also_triggers_die(self, sample_pe_file):
        data = {"detects": [{"type": "Protector", "name": "Themida"}]}
        r = _detect(sample_pe_file, die_returns=data)
        assert r["die_match"]

    def test_upx_section_name(self, sample_pe_file):
        with patch("detection.packer_detection.pefile") as pe_mod, \
             patch("detection.packer_detection.die") as die_mod, \
             patch("detection.packer_detection.calculate_entropy", return_value=5.0):
            die_mod.scan_file.return_value = json.dumps({"detects": []})
            pe_mod.PE.return_value = _fake_pe_with(b"UPX0\x00\x00\x00\x00")
            r = _detect(sample_pe_file)

        # re-run with proper pe mock since _detect built its own
        with patch("detection.packer_detection.die") as die_mod, \
             patch("detection.packer_detection.pefile") as pe_mod, \
             patch("detection.packer_detection.calculate_entropy", return_value=5.0):
            die_mod.scan_file.return_value = json.dumps({"detects": []})
            pe_mod.PE.return_value = _fake_pe_with(b"UPX0\x00\x00\x00\x00")
            from detection.packer_detection import detect_packer
            r = detect_packer(sample_pe_file)

        assert r["section_match"]
        assert any("UPX0" in d for d in r["details"])

    def test_high_entropy_flagged(self, high_entropy_file):
        r = _detect(high_entropy_file, pe_side_effect=Exception("n/a"), entropy_val=8.0)
        assert r["high_entropy"]

    def test_die_crash_does_not_propagate(self, sample_pe_file):
        with patch("detection.packer_detection.die") as die_mod, \
             patch("detection.packer_detection.pefile") as pe_mod, \
             patch("detection.packer_detection.calculate_entropy", return_value=5.0):
            die_mod.scan_file.side_effect = RuntimeError("DIE blew up")
            pe_mod.PE.side_effect = Exception("not PE")
            from detection.packer_detection import detect_packer
            r = detect_packer(sample_pe_file)
        assert not r["die_match"]

    def test_pefile_crash_does_not_propagate(self, sample_pe_file):
        with patch("detection.packer_detection.die") as die_mod, \
             patch("detection.packer_detection.pefile") as pe_mod, \
             patch("detection.packer_detection.calculate_entropy", return_value=5.0):
            die_mod.scan_file.return_value = json.dumps({"detects": []})
            pe_mod.PE.side_effect = ValueError("bad PE")
            from detection.packer_detection import detect_packer
            r = detect_packer(sample_pe_file)
        assert not r["section_match"]

    def test_report_always_has_filename(self, sample_pe_file):
        r = _detect(sample_pe_file, die_returns={"detects": []}, pe_side_effect=Exception("x"))
        assert r["filename"] == "test_sample.exe"
