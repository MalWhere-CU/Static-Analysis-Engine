from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.integration
class TestYaraMatchFlow:

    def test_match_marks_malicious(self, sample_pe_file):
        from pipeline import StaticPipeline

        with patch("pipeline.generate_and_save_rule"), \
             patch("pipeline.XAIPipeline"), \
             patch("pipeline.MalWhereMalConv") as malconv_cls, \
             patch("pipeline.get_generated_rules", return_value=[]), \
             patch("pipeline.get_enabled_rules", return_value=[]):

            malconv_mock = malconv_cls()
            malconv_mock.return_value = MagicMock()

            pipe = StaticPipeline(sample_pe_file, use_xai=False)
            # inject a fake YARA engine that always matches
            pipe.imported_yara_engine = MagicMock()
            fake_hit = MagicMock(rule="test_rule", meta={
                "description": "d", "author": "a", "score": 85,
            }, tags=["malware"])
            pipe.imported_yara_engine.scan_file.return_value = [fake_hit]

            with patch("pipeline.detect_packer", return_value={
                "die_match": False, "section_match": False, "high_entropy": False,
            }):
                result = pipe.process_file()

        assert result["matched"] is True
        assert result["status"] == "malicious"
        assert result["match_source"] == "rules"
        assert "test_rule" in result["yara_matches"]

    def test_no_yara_goes_to_malconv(self, sample_pe_file):
        from pipeline import StaticPipeline

        with patch("pipeline.generate_and_save_rule"), \
             patch("pipeline.XAIPipeline") as xai_cls, \
             patch("pipeline.MalWhereMalConv") as malconv_cls, \
             patch("pipeline.get_generated_rules", return_value=[]), \
             patch("pipeline.get_enabled_rules", return_value=[]):

            malconv_instance = malconv_cls.return_value
            malconv_instance.predict.return_value = {
                "prediction": "malicious", "confidence": 0.9,
            }

            xai_mock = MagicMock()
            xai_cls.return_value = xai_mock
            xai_mock.to_json.return_value = {
                "file": sample_pe_file, "method": "deeplift",
                "top_regions": [], "pe_mapping": {},
            }

            pipe = StaticPipeline(sample_pe_file, use_xai=True, xai_method="deeplift")
            pipe.imported_yara_engine = MagicMock()
            pipe.imported_yara_engine.scan_file.return_value = []
            pipe.generated_yara_engine = MagicMock()
            pipe.generated_yara_engine.scan_file.return_value = []

            with patch("pipeline.detect_packer", return_value={
                "die_match": False, "section_match": False, "high_entropy": False,
            }):
                result = pipe.process_file()

        assert result["matched"] is True
        assert result["match_source"] == "malconv"

    def test_packed_file_triggers_unpack(self, sample_pe_file):
        from pipeline import StaticPipeline

        with patch("pipeline.generate_and_save_rule"), \
             patch("pipeline.XAIPipeline"), \
             patch("pipeline.MalWhereMalConv") as malconv_cls, \
             patch("pipeline.get_generated_rules", return_value=[]), \
             patch("pipeline.get_enabled_rules", return_value=[]):

            malconv_mock = malconv_cls()
            malconv_mock.return_value = MagicMock()
            malconv_mock.return_value.predict.return_value = {
                "prediction": "benign", "confidence": 0.8,
            }

            with patch("pipeline.detect_packer", return_value={
                "die_match": True, "section_match": False, "high_entropy": False,
            }), patch("pipeline.UnpackFile.unpack", return_value=(sample_pe_file, None)):
                pipe = StaticPipeline(sample_pe_file, use_xai=False)
                result = pipe.process_file()

        assert result["packed"] is True
        assert result["unpacked"] is True


@pytest.mark.integration
class TestReportBuilding:

    def test_multi_match_report(self, sample_pe_file, mock_yara_match, mock_yara_match_2):
        from reports_generation.yara_report_generator import YaraReportGenerator

        gen = YaraReportGenerator(sample_pe_file, yara_ai_explainer=False)
        gen.add_yara_matches([mock_yara_match, mock_yara_match_2])
        data = gen.get_report_data()

        assert data["summary"]["total_matches"] == 2
        names = [d["rule_name"] for d in data["detections"]]
        assert names == ["test_rule", "another_rule"]


@pytest.mark.integration
class TestPeMapperFlow:

    def test_summary_basics(self, sample_pe_file):
        from utils.pe_mapper import PEMapper
        s = PEMapper(sample_pe_file).get_full_summary()
        assert isinstance(s["is_pe"], bool)
        assert s["file_size"] > 0
        assert isinstance(s["sections"], list)

    def test_offset_mapping(self, sample_pe_file):
        from utils.pe_mapper import PEMapper
        m = PEMapper(sample_pe_file).map_offset_range(0, 50)
        assert m["start_offset"] == 0
        assert m["end_offset"] == 50
        assert "raw_hex" in m


@pytest.mark.integration
class TestXaiJsonRoundTrip:

    def test_to_json_with_real_attribution(self, sample_attribution_result):
        from xai.pipeline import XAIPipeline

        analysis = {
            "file": "/test.exe",
            "file_size": 1024,
            "method": "deeplift",
            "attribution": sample_attribution_result,
            "pe_mapping": {"file_info": {}, "region_mappings": []},
        }

        # Build an XAIPipeline without __init__ (skip heavy model setup)
        with patch("xai.pipeline.XAIPipeline.__init__", return_value=None):
            p = XAIPipeline.__new__(XAIPipeline)
            p.use_explainer = False
            p._explainer = None
            p.model = MagicMock()
            p.method_name = "deeplift"

        out = p.to_json(analysis)
        assert "top_regions" in out
        assert out["method"] == "deeplift"
