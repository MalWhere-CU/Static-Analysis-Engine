import os
import sys
from unittest.mock import MagicMock

import pytest
import numpy as np

_src = os.path.join(os.path.dirname(__file__), "..", "src")
if _src not in sys.path:
    sys.path.insert(0, os.path.abspath(_src))


@pytest.fixture
def sample_pe_file(tmp_path):
    exe = tmp_path / "test_sample.exe"
    exe.write_bytes(b"MZ" + b"\x90" * 100 + b"\x00" * 50)
    return str(exe)


@pytest.fixture
def empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    return str(p)


@pytest.fixture
def high_entropy_file(tmp_path):
    p = tmp_path / "high_entropy.bin"
    p.write_bytes(bytes(range(256)) * 40)
    return str(p)


@pytest.fixture
def low_entropy_file(tmp_path):
    p = tmp_path / "low_entropy.bin"
    p.write_bytes(b"\x00" * 4096)
    return str(p)


@pytest.fixture
def sample_yara_rule():
    return (
        'rule test_rule {\n'
        '    meta:\n'
        '        description = "Test YARA rule"\n'
        '        author = "Test Author"\n'
        '        date = "2024-01-01"\n'
        '        threat_level = "high"\n'
        '        score = 85\n'
        '        mitre_attck = "T1059"\n'
        '    strings:\n'
        '        $s1 = "malicious_string"\n'
        '        $hex1 = { 4D 5A 90 00 }\n'
        '    condition:\n'
        '        uint16(0) == 0x5a4d and $s1 and $hex1\n'
        '}'
    )


@pytest.fixture
def sample_yara_rule_2():
    return (
        'rule another_rule {\n'
        '    meta:\n'
        '        description = "Another test rule"\n'
        '        author = "Another Author"\n'
        '    strings:\n'
        '        $s1 = "another_pattern"\n'
        '    condition:\n'
        '        $s1\n'
        '}'
    )


@pytest.fixture
def mock_yara_match():
    m = MagicMock()
    m.rule = "test_rule"
    m.meta = {
        "description": "Test malware detection",
        "author": "Test Author",
        "date": "2024-01-01",
        "threat_level": "high",
        "score": 85,
        "mitre_attck": "T1059",
        "reference": "https://example.com",
    }
    m.tags = ["malware", "test"]
    return m


@pytest.fixture
def mock_yara_match_2():
    m = MagicMock()
    m.rule = "another_rule"
    m.meta = {
        "description": "Another detection",
        "author": "Another Author",
        "threat_level": "medium",
        "score": 60,
    }
    m.tags = ["trojan"]
    return m


@pytest.fixture
def mock_malconv_model():
    """Stub out a MalConvGCT-like model with just enough surface for the XAI classes."""
    import torch

    mdl = MagicMock()
    mdl.eval.return_value = mdl
    mdl.return_value = (torch.randn(1, 2), torch.randn(1, 256), torch.randn(1, 256))

    # fc layers — these get copied into the extracted MLP
    w1 = torch.randn(256, 256)
    b1 = torch.randn(256)
    w2 = torch.randn(2, 256)
    b2 = torch.randn(2)

    mdl.fc_1 = MagicMock(in_features=256, weight=w1, bias=b1)
    mdl.fc_2 = MagicMock(out_features=2, weight=w2, bias=b2)

    mdl.state_dict.return_value = {
        "fc_1.weight": w1, "fc_1.bias": b1,
        "fc_2.weight": w2, "fc_2.bias": b2,
    }

    mdl.determinRF.return_value = (256, 64, 256)
    mdl.chunk_size = 131072
    mdl.min_chunk_size = 256

    mdl.embd = MagicMock()
    mdl.embd.parameters.return_value = iter([torch.randn(1)])

    mdl.context_net = MagicMock()
    mdl.context_net.seq2fix.return_value = torch.randn(1, 256, 1)
    mdl.processRange.return_value = torch.randn(1, 256, 10)

    mdl.convs_share = []
    mdl.linear_atn = []
    return mdl


@pytest.fixture
def sample_attribution_result():
    from xai.base import AttributionRegion, AttributionResult

    scores = np.random.randn(1000) * 0.1
    scores[100:200] = np.random.randn(100) * 2.0
    scores[500:600] = np.random.randn(100) * 1.5

    return AttributionResult(
        file_path="/test/malware.exe",
        method="deeplift",
        predicted_class="malicious",
        confidence=0.92,
        per_byte_scores=scores,
        windowed_scores=np.random.randn(4),
        window_size=256,
        top_regions=[
            AttributionRegion(100, 200, 2.5, "malicious"),
            AttributionRegion(500, 600, 1.8, "malicious"),
        ],
        top_regions_bidirectional=[
            AttributionRegion(100, 200, 2.5, "malicious"),
            AttributionRegion(500, 600, 1.8, "malicious"),
            AttributionRegion(700, 800, 1.2, "benign"),
        ],
    )
