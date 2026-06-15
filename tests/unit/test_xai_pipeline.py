from unittest.mock import patch

import numpy as np
import pytest
import torch

from xai.base import AttributionResult
from xai.pipeline import AVAILABLE_METHODS, XAIPipeline


@pytest.mark.unit
class TestPipelineSetup:

    def test_deeplift_default(self, mock_malconv_model):
        p = XAIPipeline(mock_malconv_model, use_explainer=False)
        assert p.method_name == "deeplift"

    def test_explicit_method(self, mock_malconv_model):
        p = XAIPipeline(mock_malconv_model, method="deeplift", use_explainer=False)
        assert p.xai_method is not None

    def test_unknown_method_raises(self, mock_malconv_model):
        with pytest.raises(ValueError, match="Unknown XAI method"):
            XAIPipeline(mock_malconv_model, method="nope", use_explainer=False)

    def test_custom_window_and_topk(self, mock_malconv_model):
        p = XAIPipeline(mock_malconv_model, window_size=512, top_k=5, use_explainer=False)
        assert p.window_size == 512
        assert p.top_k == 5

    @patch("xai.pipeline.XAIExplainer")
    def test_explainer_created_when_asked(self, _, mock_malconv_model):
        XAIPipeline(mock_malconv_model, use_explainer=True)

    def test_no_explainer_by_default(self, mock_malconv_model):
        p = XAIPipeline(mock_malconv_model, use_explainer=False)
        assert p._explainer is None


@pytest.mark.unit
class TestAnalyzeFile:

    def test_missing_file(self, mock_malconv_model):
        p = XAIPipeline(mock_malconv_model, use_explainer=False)
        with pytest.raises(FileNotFoundError):
            p.analyze_file("/no/such/file.exe")

    def test_empty_file(self, mock_malconv_model, empty_file):
        p = XAIPipeline(mock_malconv_model, use_explainer=False)
        res = p.analyze_file(empty_file)
        assert "error" in res
        assert "Empty" in res["error"]

    def test_happy_path(self, mock_malconv_model, sample_pe_file):
        mock_malconv_model.return_value = (
            torch.randn(1, 2), torch.randn(1, 256), torch.randn(1, 256),
        )
        p = XAIPipeline(mock_malconv_model, use_explainer=False)
        res = p.analyze_file(sample_pe_file)
        assert all(k in res for k in ("file", "method", "attribution"))


@pytest.mark.unit
class TestToJson:

    def test_serializes_attribution_result(self, mock_malconv_model):
        p = XAIPipeline(mock_malconv_model, use_explainer=False)
        analysis = {
            "file": "/test.exe",
            "file_size": 1024,
            "method": "deeplift",
            "attribution": AttributionResult(
                file_path="/test.exe",
                method="deeplift",
                predicted_class="malicious",
                confidence=0.95,
                per_byte_scores=np.array([0.1, 0.2]),
                windowed_scores=np.array([0.15]),
                window_size=256,
            ),
            "pe_mapping": {"file_info": {}, "region_mappings": []},
        }
        out = p.to_json(analysis)
        assert isinstance(out, dict)
        assert "file" in out

    def test_error_passthrough(self, mock_malconv_model):
        p = XAIPipeline(mock_malconv_model, use_explainer=False)
        out = p.to_json({"error": "kaboom"})
        assert out["error"] == "kaboom"
