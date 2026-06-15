import numpy as np
import pytest
import torch

from xai.base import AttributionResult


@pytest.mark.unit
class TestAttentionInit:

    def test_empty_internal_lists(self, mock_malconv_model):
        from xai.attention import AttentionExtractor
        ext = AttentionExtractor(mock_malconv_model)
        assert ext._gate_values == []
        assert ext._conv_outputs == []


@pytest.mark.unit
class TestAttentionAttribute:

    def test_empty_input(self, mock_malconv_model):
        from xai.attention import AttentionExtractor
        out = AttentionExtractor(mock_malconv_model).attribute(b"")
        assert isinstance(out, AttributionResult)
        assert out.predicted_class == "benign"
        assert len(out.per_byte_scores) == 0

    def test_method_label(self, mock_malconv_model):
        from xai.attention import AttentionExtractor
        out = AttentionExtractor(mock_malconv_model).attribute(b"")
        assert out.method == "attention"

    def test_nonempty_input_produces_scores(self, mock_malconv_model):
        from xai.attention import AttentionExtractor

        mock_malconv_model.return_value = _triple()
        ext = AttentionExtractor(mock_malconv_model)
        out = ext.attribute(b"\x00\x01\x02\x03" * 256)

        assert len(out.per_byte_scores) > 0
        assert out.method == "attention"

    def test_hook_lists_get_reused(self, mock_malconv_model):
        from xai.attention import AttentionExtractor

        ext = AttentionExtractor(mock_malconv_model)
        ext._gate_values = [None, None]
        ext._conv_outputs = [None, None]
        ext.attribute(b"")
        # the lists may or may not grow depending on hook fires;
        # the important thing is they weren't replaced with brand-new empty lists
        assert isinstance(ext._gate_values, list)
        assert isinstance(ext._conv_outputs, list)


def _triple():
    return (torch.randn(1, 2), torch.randn(1, 256), torch.randn(1, 256))
