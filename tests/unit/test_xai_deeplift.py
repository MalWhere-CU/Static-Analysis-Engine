import numpy as np
import pytest
import torch

from xai.base import AttributionResult


class TestExtractedMLP:
    """Quick smoke tests on the standalone MLP module."""

    def test_output_shape(self):
        from xai.deeplift import ExtractedMLP
        net = ExtractedMLP(channels=256, out_size=2)
        out = net(torch.randn(1, 256))
        assert out.shape == (1, 2)

    def test_custom_dimensions(self):
        from xai.deeplift import ExtractedMLP
        net = ExtractedMLP(channels=128, out_size=3)
        out = net(torch.randn(1, 128))
        assert out.shape == (1, 3)


@pytest.mark.unit
class TestDeepLiftSetup:

    def test_mlp_extracted(self, mock_malconv_model):
        from xai.deeplift import DeepLiftXAI
        dl = DeepLiftXAI(mock_malconv_model)
        assert dl.mlp_model is not None

    def test_defaults(self, mock_malconv_model):
        from xai.deeplift import DeepLiftXAI
        dl = DeepLiftXAI(mock_malconv_model)
        assert dl.window_size == 256
        assert dl.top_k == 10

    def test_overrides(self, mock_malconv_model):
        from xai.deeplift import DeepLiftXAI
        dl = DeepLiftXAI(mock_malconv_model, window_size=512, top_k=5)
        assert dl.window_size == 512
        assert dl.top_k == 5


@pytest.mark.unit
class TestDeepLiftAttribute:

    def test_empty_gives_benign(self, mock_malconv_model):
        from xai.deeplift import DeepLiftXAI
        r = DeepLiftXAI(mock_malconv_model).attribute(b"")
        assert isinstance(r, AttributionResult)
        assert r.predicted_class == "benign"
        assert r.confidence == 0.0
        assert len(r.per_byte_scores) == 0

    def test_full_run(self, mock_malconv_model):
        from xai.deeplift import DeepLiftXAI
        mock_malconv_model.return_value = (
            torch.randn(1, 2), torch.randn(1, 256), torch.randn(1, 256),
        )
        dl = DeepLiftXAI(mock_malconv_model)
        r = dl.attribute(b"\x00\x01\x02\x03" * 256)
        assert r.method == "deeplift"
        assert len(r.per_byte_scores) > 0

    def test_method_tag(self, mock_malconv_model):
        from xai.deeplift import DeepLiftXAI
        r = DeepLiftXAI(mock_malconv_model).attribute(b"")
        assert r.method == "deeplift"
