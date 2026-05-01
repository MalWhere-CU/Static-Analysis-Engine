"""Abstract base class for XAI attribution methods on MalConv2."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional
import numpy as np


@dataclass
class AttributionRegion:
    """A contiguous region of bytes with an attribution score."""
    start_offset: int
    end_offset: int
    score: float
    direction: str  # 'malicious' or 'benign'


@dataclass
class AttributionResult:
    """Full attribution output for a single file."""
    file_path: str
    method: str
    predicted_class: str
    confidence: float
    per_byte_scores: np.ndarray  # shape (N,) — raw attribution per byte
    windowed_scores: np.ndarray  # shape (num_windows,) — aggregated per window
    window_size: int
    top_regions: List[AttributionRegion] = field(default_factory=list)
    top_regions_bidirectional: List[AttributionRegion] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to JSON-friendly dict (excludes large arrays by default)."""
        return {
            "file_path": self.file_path,
            "method": self.method,
            "predicted_class": self.predicted_class,
            "confidence": self.confidence,
            "num_bytes": len(self.per_byte_scores),
            "num_windows": len(self.windowed_scores),
            "window_size": self.window_size,
            "top_regions": [
                {
                    "start_offset": r.start_offset,
                    "end_offset": r.end_offset,
                    "score": round(float(r.score), 6),
                    "direction": r.direction,
                }
                for r in self.top_regions
            ],
            "top_regions_bidirectional": [
                {
                    "start_offset": r.start_offset,
                    "end_offset": r.end_offset,
                    "score": round(float(r.score), 6),
                    "direction": r.direction,
                }
                for r in self.top_regions_bidirectional
            ],
        }


class BaseXAI(ABC):
    """Abstract interface for XAI attribution methods."""

    def __init__(self, model, window_size: int = 256, top_k: int = 10):
        """
        Args:
            model: The MalConvGCT model instance (in eval mode).
            window_size: Size of attribution windows for aggregation.
            top_k: Number of top regions to extract.
        """
        self.model = model
        self.window_size = window_size
        self.top_k = top_k

    @abstractmethod
    def attribute(self, file_bytes: bytes, target_class: Optional[int] = None) -> AttributionResult:
        """
        Compute attribution scores for the given file bytes.

        Args:
            file_bytes: Raw binary content of the file.
            target_class: Class index to explain (0=benign, 1=malicious).
                          If None, explains the predicted class.

        Returns:
            AttributionResult with per-byte and windowed scores.
        """
        pass

    def _prepare_input(self, file_bytes: bytes):
        """Convert raw bytes to model input tensor."""
        import torch
        data_np = np.frombuffer(file_bytes, dtype=np.uint8).astype(np.int16) + 1
        data_tensor = torch.tensor(data_np, dtype=torch.long).unsqueeze(0)
        return data_tensor

    def _get_prediction(self, data_tensor):
        """Run forward pass and get predicted class + confidence."""
        import torch
        import torch.nn.functional as F

        with torch.no_grad():
            output = self.model(data_tensor)
            if isinstance(output, tuple):
                logits = output[0]
            else:
                logits = output
            probs = F.softmax(logits, dim=-1)
            pred_class = probs[0].argmax().item()
            confidence = probs[0, pred_class].item()
        return pred_class, confidence, probs

    def _aggregate_windows(self, per_byte_scores: np.ndarray) -> np.ndarray:
        """Aggregate per-byte scores into non-overlapping windows."""
        n = len(per_byte_scores)
        num_windows = (n + self.window_size - 1) // self.window_size
        padded = np.zeros(num_windows * self.window_size)
        padded[:n] = per_byte_scores
        windowed = padded.reshape(num_windows, self.window_size).mean(axis=1)
        return windowed

    def _extract_top_regions(
        self, per_byte_scores: np.ndarray, predicted_class: int
    ) -> List[AttributionRegion]:
        """Extract top-K regions by score magnitude.

        Uses peak-based extraction: finds the top-K individual byte positions
        by absolute score, then expands each to a window for context.
        This avoids diluting sparse attributions (e.g., from Captum methods
        that only produce 256 non-zero points across millions of bytes).
        """
        abs_scores = np.abs(per_byte_scores)
        n = len(abs_scores)

        # Find top-K peak positions (individual bytes with highest score)
        k = min(self.top_k, max(1, int(np.count_nonzero(abs_scores))))
        k = min(k, self.top_k)
        peak_indices = np.argsort(abs_scores)[-k:][::-1]

        # Determine the target direction based on predicted class
        # Only keep regions that contribute TO the predicted class
        if predicted_class == 1:
            target_direction = "malicious"
        else:
            target_direction = "benign"

        # Merge nearby peaks into regions (within window_size of each other)
        regions = []
        used = set()

        for peak_idx in peak_indices:
            if peak_idx in used:
                continue

            # Direction from the peak byte's sign
            peak_sign = per_byte_scores[peak_idx]
            if predicted_class == 1:
                direction = "malicious" if peak_sign > 0 else "benign"
            else:
                direction = "benign" if peak_sign > 0 else "malicious"

            # Skip regions that don't support the predicted class
            if direction != target_direction:
                used.add(int(peak_idx))
                continue

            # Define region centered on peak
            start = max(0, int(peak_idx) - self.window_size // 2)
            end = min(n, start + self.window_size)
            start = max(0, end - self.window_size)  # adjust if near end

            # Mark all peaks within this region as used
            for other_idx in peak_indices:
                if start <= other_idx < end:
                    used.add(int(other_idx))

            # Score = max absolute score in the region (not average)
            region_score = abs_scores[start:end].max()

            regions.append(AttributionRegion(
                start_offset=start,
                end_offset=end,
                score=float(region_score),
                direction=direction,
            ))

            if len(regions) >= self.top_k:
                break

        return regions

    def _extract_top_regions_bidirectional(
        self, per_byte_scores: np.ndarray, predicted_class: int
    ) -> List[AttributionRegion]:
        """Extract top-K regions in BOTH directions (malicious and benign).

        Returns regions sorted by absolute score regardless of direction.
        Useful for visualization where you want to see what pushes toward
        malicious AND what pushes toward benign.
        """
        abs_scores = np.abs(per_byte_scores)
        n = len(abs_scores)

        k = min(self.top_k * 2, max(1, int(np.count_nonzero(abs_scores))))
        peak_indices = np.argsort(abs_scores)[-k:][::-1]

        regions = []
        used = set()

        for peak_idx in peak_indices:
            if peak_idx in used:
                continue

            peak_sign = per_byte_scores[peak_idx]
            if predicted_class == 1:
                direction = "malicious" if peak_sign > 0 else "benign"
            else:
                direction = "benign" if peak_sign > 0 else "malicious"

            # Define region centered on peak
            start = max(0, int(peak_idx) - self.window_size // 2)
            end = min(n, start + self.window_size)
            start = max(0, end - self.window_size)

            for other_idx in peak_indices:
                if start <= other_idx < end:
                    used.add(int(other_idx))

            region_score = abs_scores[start:end].max()

            regions.append(AttributionRegion(
                start_offset=start,
                end_offset=end,
                score=float(region_score),
                direction=direction,
            ))

            if len(regions) >= self.top_k * 2:
                break

        return regions
