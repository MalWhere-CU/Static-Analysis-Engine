"""Occlusion-based attribution for MalConv2.

Slides a window across the input, replaces bytes with baseline (padding=0),
and measures the change in prediction confidence. Regions where occlusion
causes the largest drop in malicious confidence are most important.
"""

from typing import Optional
import numpy as np
import torch
import torch.nn.functional as F

from .base import BaseXAI, AttributionResult


class OcclusionXAI(BaseXAI):
    """Sliding window occlusion attribution."""

    def __init__(self, model, window_size: int = 256, top_k: int = 10, stride: int = 128):
        """
        Args:
            model: MalConvGCT model.
            window_size: Size of occlusion window.
            top_k: Number of top regions.
            stride: Step size for sliding the occlusion window.
        """
        super().__init__(model, window_size, top_k)
        self.stride = stride

    def attribute(self, file_bytes: bytes, target_class: Optional[int] = None) -> AttributionResult:
        if len(file_bytes) == 0:
            return AttributionResult(
                file_path="", method="occlusion",
                predicted_class="benign", confidence=0.0,
                per_byte_scores=np.array([]), windowed_scores=np.array([]),
                window_size=self.window_size, top_regions=[]
            )

        data_tensor = self._prepare_input(file_bytes)
        n_bytes = len(file_bytes)

        # Get baseline prediction
        pred_class, base_confidence, base_probs = self._get_prediction(data_tensor)

        if target_class is None:
            target_class = pred_class

        base_score = base_probs[0, target_class].item()

        # Slide occlusion window and measure confidence drop
        per_byte_importance = np.zeros(n_bytes, dtype=np.float64)
        per_byte_count = np.zeros(n_bytes, dtype=np.float64)

        num_windows = (n_bytes - self.window_size) // self.stride + 1
        if num_windows <= 0:
            num_windows = 1

        for i in range(num_windows):
            start = i * self.stride
            end = min(start + self.window_size, n_bytes)

            # Create occluded input (replace with padding token 0)
            occluded = data_tensor.clone()
            occluded[0, start:end] = 0

            with torch.no_grad():
                output = self.model(occluded)
                if isinstance(output, tuple):
                    logits = output[0]
                else:
                    logits = output
                probs = F.softmax(logits, dim=-1)
                occluded_score = probs[0, target_class].item()

            # Importance = drop in target class probability when occluded
            importance = base_score - occluded_score

            per_byte_importance[start:end] += importance
            per_byte_count[start:end] += 1

        # Average overlapping contributions
        per_byte_count = np.maximum(per_byte_count, 1)
        per_byte_scores = per_byte_importance / per_byte_count

        windowed = self._aggregate_windows(per_byte_scores)
        top_regions = self._extract_top_regions(per_byte_scores, target_class)

        class_name = "malicious" if pred_class == 1 else "benign"
        return AttributionResult(
            file_path="",
            method="occlusion",
            predicted_class=class_name,
            confidence=base_confidence,
            per_byte_scores=per_byte_scores,
            windowed_scores=windowed,
            window_size=self.window_size,
            top_regions=top_regions,
        )
