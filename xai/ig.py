from typing import Optional, Tuple
import numpy as np
import torch
import torch.nn.functional as F

from .base import BaseXAI, AttributionResult
from .deeplift import ExtractedMLP

try:
    from captum.attr import IntegratedGradients as CaptumIG
    HAS_CAPTUM = True
except ImportError:
    HAS_CAPTUM = False


class IntegratedGradients(BaseXAI):
    """Integrated Gradients on the extracted MLP via Captum."""

    def __init__(self, model, window_size: int = 256, top_k: int = 10, n_steps: int = 50):
        """
        Args:
            model: MalConvGCT model instance.
            window_size: Attribution aggregation window.
            top_k: Number of top regions to report.
            n_steps: Number of interpolation steps for IG.
        """
        super().__init__(model, window_size, top_k)
        self.n_steps = n_steps

        if not HAS_CAPTUM:
            raise ImportError("Captum required. Install: pip install captum")

        self.mlp_model = self._extract_mlp()
        self.ig = CaptumIG(self.mlp_model)

    def _extract_mlp(self) -> ExtractedMLP:
        """Extract fc_1 and fc_2 from the full model."""
        channels = self.model.fc_1.in_features
        out_size = self.model.fc_2.out_features
        mlp = ExtractedMLP(channels=channels, out_size=out_size)
        state = {}
        for k in ["fc_1.weight", "fc_1.bias", "fc_2.weight", "fc_2.bias"]:
            state[k] = self.model.state_dict()[k].clone()
        mlp.load_state_dict(state)
        mlp.eval()
        return mlp

    def attribute(self, file_bytes: bytes, target_class: Optional[int] = None) -> AttributionResult:
        if len(file_bytes) == 0:
            return AttributionResult(
                file_path="", method="integrated_gradients",
                predicted_class="benign", confidence=0.0,
                per_byte_scores=np.array([]), windowed_scores=np.array([]),
                window_size=self.window_size, top_regions=[]
            )

        data_tensor = self._prepare_input(file_bytes)
        n_bytes = len(file_bytes)

        pred_class, confidence, _ = self._get_prediction(data_tensor)
        if target_class is None:
            target_class = pred_class

        # Get post_conv features and winner indices
        post_conv, winner_indices = self._forward_with_indices(data_tensor)

        # Apply Captum IG on the MLP
        per_byte_scores = self._compute_ig(post_conv, winner_indices, target_class, n_bytes)

        windowed = self._aggregate_windows(per_byte_scores)
        top_regions = self._extract_top_regions(per_byte_scores, target_class)

        class_name = "malicious" if pred_class == 1 else "benign"
        return AttributionResult(
            file_path="",
            method="integrated_gradients",
            predicted_class=class_name,
            confidence=confidence,
            per_byte_scores=per_byte_scores,
            windowed_scores=windowed,
            window_size=self.window_size,
            top_regions=top_regions,
        )

    def _forward_with_indices(self, data_tensor: torch.Tensor) -> Tuple[torch.Tensor, np.ndarray]:
        """Run model forward and capture post_conv + winner indices."""
        self.model.eval()
        batch_size = data_tensor.shape[0]
        length = data_tensor.shape[1]

        receptive_window, stride, out_channels = self.model.determinRF()

        if length < receptive_window:
            data_tensor = F.pad(data_tensor, (0, receptive_window - length), value=0)
            length = data_tensor.shape[1]

        with torch.no_grad():
            global_context = self.model.context_net.seq2fix(data_tensor)

        winner_values = np.zeros((batch_size, out_channels)) - 1.0
        winner_indices = np.zeros((batch_size, out_channels), dtype=np.int64)

        cur_device = next(self.model.embd.parameters()).device
        chunk_size = self.model.chunk_size

        start = 0
        end = min(start + chunk_size, length)

        with torch.no_grad():
            while start < end and (end - start) >= max(self.model.min_chunk_size, receptive_window):
                x_sub = data_tensor[:, start:end].to(cur_device)
                activs = self.model.processRange(x_sub.long(), gct=global_context)
                activ_win, activ_indx = F.max_pool1d(
                    activs, kernel_size=activs.shape[2], return_indices=True
                )
                activ_win_np = activ_win.cpu().numpy()[:, :, 0]
                activ_indx_np = activ_indx.cpu().numpy()[:, :, 0]
                selected = winner_values < activ_win_np
                winner_indices[selected] = activ_indx_np[selected] * stride + start
                winner_values[selected] = activ_win_np[selected]
                start = end
                end = min(start + chunk_size, length)

        with torch.no_grad():
            output = self.model(data_tensor)
            post_conv = output[2]

        return post_conv, winner_indices

    def _compute_ig(self, post_conv: torch.Tensor, winner_indices: np.ndarray,
                    target_class: int, n_bytes: int) -> np.ndarray:
        """Apply Captum IG on MLP and map to bytes via winner indices."""
        post_conv_attr = post_conv.detach().requires_grad_(True)
        baseline = torch.zeros_like(post_conv_attr)

        attr = self.ig.attribute(
            post_conv_attr,
            baselines=baseline,
            target=target_class,
            n_steps=self.n_steps,
        )

        attr_np = attr.detach().numpy()[0]  # (channels,)
        indices = winner_indices[0]  # (channels,)

        heatmap = np.zeros(n_bytes, dtype=np.float64)
        for channel_idx in range(len(attr_np)):
            byte_pos = int(indices[channel_idx])
            if 0 <= byte_pos < n_bytes:
                heatmap[byte_pos] += attr_np[channel_idx]

        max_val = np.abs(heatmap).max()
        if max_val > 0:
            heatmap = heatmap / max_val

        return heatmap
