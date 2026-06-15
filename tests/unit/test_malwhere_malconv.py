import os
from unittest.mock import MagicMock, patch

import pytest
import torch


_FAKE_CKPT = "/fake/checkpoint.checkpoint"
_TRIPLE = lambda: (torch.randn(1, 2), torch.randn(1, 256), torch.randn(1, 256))


@pytest.fixture(autouse=True)
def _stub_malconv():
    """Patch the three deps that MalWhereMalConv.__init__ touches."""
    with patch("models.malwhere_malconv.MalConvGCT") as mdl_cls, \
         patch("models.malwhere_malconv.os.path.exists") as exists, \
         patch("models.malwhere_malconv.torch.load") as load:
        mdl = MagicMock()
        mdl_cls.return_value = mdl
        load.return_value = {"model_state_dict": {}}
        yield mdl, exists, load


@pytest.mark.unit
class TestInit:
    def test_model_set_to_eval(self, _stub_malconv):
        mdl, exists, load = _stub_malconv
        exists.return_value = True
        from models.malwhere_malconv import MalWhereMalConv
        d = MalWhereMalConv(_FAKE_CKPT)
        assert d.model is mdl
        mdl.eval.assert_called_once()

    def test_missing_ckpt_raises(self, _stub_malconv):
        _, exists, _ = _stub_malconv
        exists.return_value = False
        from models.malwhere_malconv import MalWhereMalConv
        with pytest.raises(FileNotFoundError):
            MalWhereMalConv(_FAKE_CKPT)


@pytest.mark.unit
class TestPredict:
    def _make_detector(self, _stub_malconv):
        mdl, _, _ = _stub_malconv
        from models.malwhere_malconv import MalWhereMalConv
        return MalWhereMalConv(_FAKE_CKPT), mdl

    def test_basic_output_shape(self, _stub_malconv, tmp_path):
        det, mdl = self._make_detector(_stub_malconv)
        mdl.return_value = _TRIPLE()
        f = tmp_path / "a.bin"
        f.write_bytes(b"\x00\x01\x02\x03" * 256)
        res = det.predict(str(f))
        assert set(res) >= {"prediction", "confidence"}
        assert res["prediction"] in ("malicious", "benign")

    def test_empty_input_benign(self, _stub_malconv, tmp_path):
        det, _ = self._make_detector(_stub_malconv)
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        res = det.predict(str(f))
        assert res["prediction"] == "benign"
        assert res["confidence"] == 0.0
        assert "error" in res

    def test_model_crash_caught(self, _stub_malconv, tmp_path):
        det, mdl = self._make_detector(_stub_malconv)
        mdl.side_effect = RuntimeError("boom")
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        res = det.predict(str(f))
        assert res["prediction"] == "error"

    def test_high_logit_is_malicious(self, _stub_malconv, tmp_path):
        det, mdl = self._make_detector(_stub_malconv)
        logits = torch.tensor([[-1.0, 5.0]])
        mdl.return_value = (logits, torch.randn(1, 256), torch.randn(1, 256))
        f = tmp_path / "m.bin"
        f.write_bytes(b"\x00" * 1024)
        res = det.predict(str(f))
        assert res["prediction"] == "malicious"
        assert res["confidence"] > 0.5
