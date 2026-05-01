from typing import Optional, List, Tuple
import numpy as np
import torch

from .base import BaseXAI, AttributionResult


class AttentionExtractor(BaseXAI):
    """Extract GCT attention gate values from MalConvGCT."""

    def __init__(self, model, window_size: int = 256, top_k: int = 10):
        super().__init__(model, window_size, top_k)
        self._gate_values: List[torch.Tensor] = []
        self._conv_outputs: List[torch.Tensor] = []

    def attribute(self, file_bytes: bytes, target_class: Optional[int] = None) -> AttributionResult:
        if len(file_bytes) == 0:
            return AttributionResult(
                file_path="", method="attention",
                predicted_class="benign", confidence=0.0,
                per_byte_scores=np.array([]), windowed_scores=np.array([]),
                window_size=self.window_size, top_regions=[]
            )

        data_tensor = self._prepare_input(file_bytes)
        n_bytes = len(file_bytes)

        # Register hooks to capture gate values
        self._gate_values = []
        self._conv_outputs = []
        handles = self._register_hooks()

        try:
            pred_class, confidence, _ = self._get_prediction(data_tensor)
        finally:
            for h in handles:
                h.remove()

        if target_class is None:
            target_class = pred_class

        # Map gate values to per-byte scores
        per_byte_scores = self._map_gates_to_bytes(n_bytes)

        windowed = self._aggregate_windows(per_byte_scores)
        top_regions = self._extract_top_regions(per_byte_scores, target_class)

        class_name = "malicious" if pred_class == 1 else "benign"
        return AttributionResult(
            file_path="",
            method="attention",
            predicted_class=class_name,
            confidence=confidence,
            per_byte_scores=per_byte_scores,
            windowed_scores=windowed,
            window_size=self.window_size,
            top_regions=top_regions,
        )

    def _register_hooks(self) -> List:
        """Hook into linear_atn layers (which produce the GCT context vectors)
        and the convs_share layers (which produce post-gated outputs)."""
        handles = []

        # Strategy 1: Hook convs_share layers — their output is x after gating
        # The difference between input and output reveals gate effect
        if hasattr(self.model, 'convs_share'):
            for i, conv in enumerate(self.model.convs_share):
                handle = conv.register_forward_hook(self._make_conv_hook(i))
                handles.append(handle)

        # Strategy 2: Hook linear_atn to capture context vectors
        if hasattr(self.model, 'linear_atn'):
            for i, linear in enumerate(self.model.linear_atn):
                handle = linear.register_forward_hook(self._make_gate_hook(i))
                handles.append(handle)

        # Fallback: hook any Conv1d layers
        if not handles:
            conv_layers = []
            for name, module in self.model.named_modules():
                if isinstance(module, torch.nn.Conv1d):
                    conv_layers.append((name, module))
            if conv_layers:
                name, module = conv_layers[-1]
                handle = module.register_forward_hook(self._make_conv_hook(0))
                handles.append(handle)

        return handles

    def _make_gate_hook(self, layer_idx: int):
        """Hook that captures linear_atn output (context vector before sigmoid)."""
        def hook_fn(module, input, output):
            # output is tanh(linear(gct)) — the context vector
            # Shape: (B, channels) — one scalar gate per channel
            if isinstance(output, torch.Tensor):
                self._gate_values.append(output.detach().cpu())
        return hook_fn

    def _make_conv_hook(self, layer_idx: int):
        """Hook that captures conv output (post-gating activation map)."""
        def hook_fn(module, input, output):
            # output shape: (B, channels, seq_len) — gated conv activations
            if isinstance(output, torch.Tensor):
                self._conv_outputs.append(output.detach().cpu())
        return hook_fn

    def _map_gates_to_bytes(self, n_bytes: int) -> np.ndarray:
        """Map captured activations back to per-byte importance scores."""
        per_byte = np.zeros(n_bytes)

        # Use conv_share outputs (post-gated activations) as importance signal
        if self._conv_outputs:
            # Take the last layer's output as most task-relevant
            activations = self._conv_outputs[-1]  # (B, C, L)
            if activations.dim() == 3:
                # Mean absolute activation across channels = importance per position
                window_scores = activations[0].abs().mean(dim=0).numpy()  # (L,)
            elif activations.dim() == 2:
                window_scores = activations[0].abs().numpy()
            else:
                window_scores = activations.abs().numpy()

            # Determine stride from model config
            # MalConvGCT: first conv uses specified stride, subsequent convs use stride=1
            # The output length tells us the effective stride
            if len(window_scores) > 1:
                effective_stride = max(1, n_bytes // len(window_scores))
            else:
                effective_stride = n_bytes

            # Map window positions back to bytes
            for i, score in enumerate(window_scores):
                start = i * effective_stride
                end = min(start + self.window_size, n_bytes)
                if start < n_bytes:
                    per_byte[start:end] += float(score)

            # Normalize overlapping regions
            count = np.zeros(n_bytes)
            for i in range(len(window_scores)):
                start = i * effective_stride
                end = min(start + self.window_size, n_bytes)
                if start < n_bytes:
                    count[start:end] += 1
            count = np.maximum(count, 1)
            per_byte = per_byte / count

        # If we also have gate values, use them as channel-level weighting
        elif self._gate_values:
            # gate_values[-1] shape: (B, channels) — per-channel importance
            gate = self._gate_values[-1]
            if gate.dim() >= 2:
                # Average gate activation indicates which channels matter
                channel_importance = gate[0].abs().mean().item()
                per_byte[:] = channel_importance

        # Normalize to [0, 1]
        max_val = per_byte.max()
        if max_val > 0:
            per_byte = per_byte / max_val

        return per_byte
