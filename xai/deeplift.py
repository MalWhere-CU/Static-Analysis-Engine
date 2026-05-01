from typing import Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .base import BaseXAI, AttributionResult

from captum.attr import DeepLift


class ExtractedMLP(nn.Module):
    """Standalone MLP extracted from MalConvGCT (fc_1 → LeakyReLU → fc_2).

    This allows Captum's DeepLift to operate on just the classification head
    with continuous inputs (the post-conv pooled features).
    """

    def __init__(self, channels: int = 256, out_size: int = 2):
        super().__init__()
        self.fc_1 = nn.Linear(channels, channels)
        self.fc_2 = nn.Linear(channels, out_size)

    def forward(self, x):
        x = F.leaky_relu(self.fc_1(x))
        x = self.fc_2(x)
        return x


class DeepLiftXAI(BaseXAI):
    """DeepLift attribution using Captum on the extracted MLP.

    Strategy:
    1. Forward pass through full model → get post_conv features + winner indices
    2. Apply Captum DeepLift on MLP only (post_conv → logits)
    3. Each of 256 channels gets an attribution score
    4. Map channel scores to byte positions using winner_indices
    5. Result: per-byte attribution heatmap
    """

    def __init__(self, model, window_size: int = 256, top_k: int = 10):
        super().__init__(model, window_size, top_k)

        # Extract the MLP from the full model
        self.mlp_model = self._extract_mlp()
        self.dl = DeepLift(self.mlp_model)

    def _extract_mlp(self) -> ExtractedMLP:
        """Extract fc_1 and fc_2 weights from the full model into standalone MLP."""
        # Determine channel size from model
        channels = self.model.fc_1.in_features
        out_size = self.model.fc_2.out_features

        mlp = ExtractedMLP(channels=channels, out_size=out_size)

        # Copy weights
        state = {}
        for k in ["fc_1.weight", "fc_1.bias", "fc_2.weight", "fc_2.bias"]:
            state[k] = self.model.state_dict()[k].clone()
        mlp.load_state_dict(state)
        mlp.eval()
        return mlp

    def attribute(self, file_bytes: bytes, target_class: Optional[int] = None) -> AttributionResult:
        if len(file_bytes) == 0:
            return AttributionResult(
                file_path="", method="deeplift",
                predicted_class="benign", confidence=0.0,
                per_byte_scores=np.array([]), windowed_scores=np.array([]),
                window_size=self.window_size, top_regions=[]
            )

        data_tensor = self._prepare_input(file_bytes)
        n_bytes = len(file_bytes)

        # Get prediction
        pred_class, confidence, _ = self._get_prediction(data_tensor)
        if target_class is None:
            target_class = pred_class

        # Run forward pass capturing post_conv and winner indices
        post_conv, winner_indices = self._forward_with_indices(data_tensor)

        # Apply Captum DeepLift on the MLP
        per_byte_scores = self._compute_deeplift(
            post_conv, winner_indices, target_class, n_bytes
        )

        windowed = self._aggregate_windows(per_byte_scores)
        top_regions = self._extract_top_regions(per_byte_scores, target_class)

        class_name = "malicious" if pred_class == 1 else "benign"
        return AttributionResult(
            file_path="",
            method="deeplift",
            predicted_class=class_name,
            confidence=confidence,
            per_byte_scores=per_byte_scores,
            windowed_scores=windowed,
            window_size=self.window_size,
            top_regions=top_regions,
        )

    def _forward_with_indices(self, data_tensor: torch.Tensor) -> Tuple[torch.Tensor, np.ndarray]:
        """
        Run the model forward pass and capture:
        - post_conv: the pooled feature vector (B, channels)
        - winner_indices: which byte positions won max-pool per channel (B, channels)

        We replicate the seq2fix logic to capture winner_indices, since the
        standard forward() doesn't return them.
        """
        self.model.eval()
        batch_size = data_tensor.shape[0]
        length = data_tensor.shape[1]

        # Get model parameters
        receptive_window, stride, out_channels = self.model.determinRF()

        if length < receptive_window:
            data_tensor = F.pad(data_tensor, (0, receptive_window - length), value=0)
            length = data_tensor.shape[1]

        # First: compute global context (needed for GCT)
        with torch.no_grad():
            global_context = self.model.context_net.seq2fix(data_tensor)

        # Second: replicate seq2fix to capture winner_indices
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
                # Map local indices back to global byte positions
                winner_indices[selected] = activ_indx_np[selected] * stride + start
                winner_values[selected] = activ_win_np[selected]

                start = end
                end = min(start + chunk_size, length)

        # Now get the actual post_conv via normal forward
        with torch.no_grad():
            output = self.model(data_tensor)
            # forward returns (logits, penult, post_conv)
            post_conv = output[2]  # (B, channels)

        return post_conv, winner_indices

    def _compute_deeplift(self, post_conv: torch.Tensor, winner_indices: np.ndarray,
                          target_class: int, n_bytes: int) -> np.ndarray:
        """
        Apply Captum DeepLift on the extracted MLP and map back to bytes.

        Args:
            post_conv: (B, channels) pooled features from convolution layers
            winner_indices: (B, channels) byte positions that won max-pool
            target_class: class to explain
            n_bytes: total file length

        Returns:
            per_byte_scores: (n_bytes,) attribution heatmap
        """
        # DeepLift needs gradient-enabled input
        post_conv_attr = post_conv.detach().requires_grad_(True)

        # Baseline: zeros (what you'd get from an empty/padding-only input)
        baseline = torch.zeros_like(post_conv_attr)

        # Run Captum DeepLift
        attr, delta = self.dl.attribute(
            post_conv_attr,
            baselines=baseline,
            target=target_class,
            return_convergence_delta=True,
        )

        # attr shape: (B, channels) — one score per channel
        attr_np = attr.detach().numpy()[0]  # (channels,)
        indices = winner_indices[0]  # (channels,)

        # Map channel attributions to byte positions
        heatmap = np.zeros(n_bytes, dtype=np.float64)
        for channel_idx in range(len(attr_np)):
            byte_pos = int(indices[channel_idx])
            if 0 <= byte_pos < n_bytes:
                heatmap[byte_pos] += attr_np[channel_idx]

        # Scale heatmap relative to prediction confidence
        max_val = np.abs(heatmap).max()
        if max_val > 0:
            heatmap = heatmap / max_val

        return heatmap
