from typing import Optional, Tuple
import numpy as np
import torch
import torch.nn.functional as F

from .base import BaseXAI, AttributionResult
from .deeplift import ExtractedMLP

from captum.attr import Lime


class LimeXAI(BaseXAI):
    """LIME attribution using Captum on the extracted MLP.

    Strategy:
    1. Forward pass through full model → get post_conv features + winner indices
    2. Apply Captum Lime on MLP (post_conv → logits)
    3. Map 256 channel attributions to byte positions using winner_indices
    """

    def __init__(self, model, window_size: int = 256, top_k: int = 10,
                 n_samples: int = 100):
        super().__init__(model, window_size, top_k)
        self.n_samples = n_samples

        # Extract the MLP from the full model
        self.mlp_model = self._extract_mlp()
        self.lime = Lime(self.mlp_model)

    def _extract_mlp(self) -> ExtractedMLP:
        """Extract fc_1 and fc_2 weights from the full model into standalone MLP."""
        channels = self.model.fc_1.in_features
        out_size = self.model.fc_2.out_features

        mlp = ExtractedMLP(channels=channels, out_size=out_size)

        state = {}
        for k in ["fc_1.weight", "fc_1.bias", "fc_2.weight", "fc_2.bias"]:
            state[k] = self.model.state_dict()[k].clone()
        mlp.load_state_dict(state)
        mlp.eval()
        return mlp

    def _forward_with_indices(self, data_tensor: torch.Tensor) -> Tuple[torch.Tensor, np.ndarray]:
        """Run full model forward pass and capture post_conv + winner_indices."""
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

    def attribute(self, file_bytes: bytes, target_class: Optional[int] = None) -> AttributionResult:
        if len(file_bytes) == 0:
            return AttributionResult(
                file_path="", method="lime",
                predicted_class="benign", confidence=0.0,
                per_byte_scores=np.array([]), windowed_scores=np.array([]),
                window_size=self.window_size, top_regions=[]
            )

        data_tensor = self._prepare_input(file_bytes)
        n_bytes = len(file_bytes)

        pred_class, confidence, _ = self._get_prediction(data_tensor)
        if target_class is None:
            target_class = pred_class

        post_conv, winner_indices = self._forward_with_indices(data_tensor)

        # Apply LIME on the MLP
        post_conv_attr = post_conv.detach().requires_grad_(True)

        attr = self.lime.attribute(
            post_conv_attr,
            target=target_class,
            n_samples=self.n_samples,
        )

        # Map channel attributions to byte positions
        attr_np = attr.detach().numpy()[0]
        indices = winner_indices[0]

        heatmap = np.zeros(n_bytes, dtype=np.float64)
        for channel_idx in range(len(attr_np)):
            byte_pos = int(indices[channel_idx])
            if 0 <= byte_pos < n_bytes:
                heatmap[byte_pos] += attr_np[channel_idx]

        max_val = np.abs(heatmap).max()
        if max_val > 0:
            heatmap = heatmap / max_val

        windowed = self._aggregate_windows(heatmap)
        top_regions = self._extract_top_regions(heatmap, target_class)

        class_name = "malicious" if pred_class == 1 else "benign"
        return AttributionResult(
            file_path="",
            method="lime",
            predicted_class=class_name,
            confidence=confidence,
            per_byte_scores=heatmap,
            windowed_scores=windowed,
            window_size=self.window_size,
            top_regions=top_regions,
        )
