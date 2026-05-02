import os
from typing import List, Optional, Dict, Any
import numpy as np

# Match training max_len — model never learned patterns beyond this offset
# MAX_INPUT_LEN = 4_000_000
from utils.pe_mapper import PEMapper

from .base import BaseXAI, AttributionResult, AttributionRegion
from .ig import IntegratedGradients
from .occlusion import OcclusionXAI
from .deeplift import DeepLiftXAI
from .gradient_shap import GradientSHAP
from .feature_ablation import FeatureAblation
from .smoothgrad import SmoothGradXAI
from .lime_xai import LimeXAI
from .explainer import XAIExplainer\

AVAILABLE_METHODS = {
    'deeplift': lambda model, ws, tk: DeepLiftXAI(model, ws, tk),
    'lime': lambda model, ws, tk: LimeXAI(model, ws, tk),
    'ig': lambda model, ws, tk: IntegratedGradients(model, ws, tk, n_steps=50),
    'smoothgrad': lambda model, ws, tk: SmoothGradXAI(model, ws, tk),
    # 'occlusion': lambda model, ws, tk: OcclusionXAI(model, ws, tk, stride=128),
    # 'gradient_shap': lambda model, ws, tk: GradientSHAP(model, ws, tk),
    # 'feature_ablation': lambda model, ws, tk: FeatureAblation(model, ws, tk),
}


class XAIPipeline:
    """Runs a single XAI method on a file with PE mapping."""

    def __init__(self, model, method: str = 'deeplift',
                 window_size: int = 256, top_k: int = 10,
                 use_explainer: bool = False):
        """
        Args:
            model: MalConvGCT model instance in eval mode.
            method: Which XAI method to use.
            window_size: Attribution window size.
            top_k: Number of top regions to extract.
            use_explainer: Whether to generate LLM explanations (requires GOOGLE_API_KEY).
        """
        self.model = model
        self.method_name = method
        self.window_size = window_size
        self.top_k = top_k
        self.use_explainer = use_explainer
        self._explainer = None

        if method not in AVAILABLE_METHODS:
            raise ValueError(f"Unknown XAI method: {method}. "
                             f"Available: {list(AVAILABLE_METHODS.keys())}")

        self.xai_method: BaseXAI = AVAILABLE_METHODS[method](model, window_size, top_k)

        if use_explainer:
            self._explainer = XAIExplainer()

    def analyze_file(self, file_path: str, target_class: Optional[int] = None) -> Dict[str, Any]:
        """
        Run the configured XAI method on a file.

        Args:
            file_path: Path to the binary file to analyze.
            target_class: Class to explain (0=benign, 1=malicious). None = predicted class.

        Returns:
            Dictionary with attribution result and PE mapping for this method.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, 'rb') as f:
            file_bytes = f.read()

        if len(file_bytes) == 0:
            return {"file": file_path, "method": self.method_name, "error": "Empty file"}

        # # Truncate to match training max_len
        # file_bytes = file_bytes[:MAX_INPUT_LEN]

        try:
            attribution = self.xai_method.attribute(file_bytes, target_class)
            attribution.file_path = file_path
            # Add bidirectional regions for visualization
            pred_class_int = 1 if attribution.predicted_class == "malicious" else 0
            attribution.top_regions_bidirectional = (
                self.xai_method._extract_top_regions_bidirectional(
                    attribution.per_byte_scores, pred_class_int
                )
            )
        except Exception as e:
            return {"file": file_path, "method": self.method_name, "error": str(e)}

        # PE mapping for this method's top regions only
        pe_mapping = self._map_to_pe(file_path, file_bytes, attribution)

        return {
            "file": file_path,
            "file_size": len(file_bytes),
            "method": self.method_name,
            "attribution": attribution,
            "pe_mapping": pe_mapping,
        }

    def _map_to_pe(self, file_path: str, file_bytes: bytes,
                   attribution: AttributionResult) -> Optional[Dict]:
        """Map this method's attribution regions to PE structures."""
        try:
            mapper = PEMapper(file_path)

            regions = attribution.top_regions
            if not regions:
                return mapper.get_full_summary()

            mapped_regions = []
            for region in regions:
                mapping = mapper.map_offset_range(region.start_offset, region.end_offset)
                mapped_regions.append(mapping)

            return {
                "file_info": mapper.get_full_summary(),
                "region_mappings": mapped_regions,
            }
        except Exception as e:
            return {"error": f"PE mapping failed: {str(e)}"}

    def to_json(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Convert analysis result to JSON-serializable dict."""
        if "error" in analysis_result:
            return analysis_result

        attribution = analysis_result.get("attribution")
        output = {
            "file": analysis_result.get("file", ""),
            "file_size": analysis_result.get("file_size", 0),
            "method": analysis_result.get("method", ""),
            "pe_mapping": analysis_result.get("pe_mapping"),
        }

        if isinstance(attribution, AttributionResult):
            output.update(attribution.to_dict())
        elif isinstance(attribution, dict):
            output["error"] = attribution.get("error", "unknown")

        # Generate LLM explanation if enabled
        if self.use_explainer and self._explainer and "error" not in output:
            try:
                explanation = self._explainer.explain(output)
                output["llm_explanation"] = explanation.model_dump()
            except Exception as e:
                output["llm_explanation"] = {"error": str(e)}

        return output
