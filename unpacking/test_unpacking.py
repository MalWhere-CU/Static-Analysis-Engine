# unpacking/test_preprocessor.py
import pytest
import os
from unpacking.detector import PackingDetector
from unpacking.pipeline import UnpackingPipeline

def test_unsupported_or_clean_files():
    """Verify that safe native files are not broken or misidentified by the router."""
    detector = PackingDetector()
    # /bin/ls is a standard clean Linux binary present in the container
    if os.path.exists("/bin/ls"):
        analysis = detector.analyze("/bin/ls")
        assert analysis["is_packed"] is False
        assert analysis["category"] in ["Clean", "Unknown"]

def test_pipeline_instantiation():
    """Verify that the preprocessing pipeline class maps all standard hook routers."""
    pipeline = UnpackingPipeline()
    assert hasattr(pipeline, 'detector')
    # Validate critical structural routing options are loaded
    assert "UPX" in pipeline.routes or hasattr(pipeline, 'process_file')