import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

from xai.base import AttributionResult


def visualize_attributions(
    attribution: AttributionResult,
    output_path: str = "xai_attribution_plot.png",
    heatmap_bins: int = 512,
    dpi: int = 150,
):
    """
    Plot XAI attribution results as a heatmap + scatter/line plot.

    Args:
        attribution: An AttributionResult object from the XAI pipeline.
        output_path: Where to save the figure.
        heatmap_bins: Number of bins for the heatmap (collapses bytes if file is large).
        dpi: Figure resolution.
    """
    scores = attribution.per_byte_scores
    n_bytes = len(scores)

    # Bin scores for heatmap if file is larger than heatmap_bins
    if n_bytes > heatmap_bins:
        bin_size = n_bytes / heatmap_bins
        binned = np.array([
            scores[int(i * bin_size):int((i + 1) * bin_size)].mean()
            for i in range(heatmap_bins)
        ])
    else:
        binned = scores.copy()
        heatmap_bins = n_bytes

    # Collect top-k offsets from bidirectional regions
    top_offsets = set()
    regions = attribution.top_regions_bidirectional or attribution.top_regions
    for r in regions:
        mid = (r.start_offset + r.end_offset) // 2
        top_offsets.add(mid)

    # --- Figure with 2 subplots: heatmap (with colorbar), line/scatter ---
    fig, (ax_heat, ax_line) = plt.subplots(
        2, 1, figsize=(18, 9), gridspec_kw={"height_ratios": [1, 1]},
    )

    # Color normalization symmetric around 0
    vmax = max(abs(binned.min()), abs(binned.max())) or 1e-8
    norm = mcolors.TwoSlopeNorm(vmin=-vmax, vcenter=0, vmax=vmax)

    # Colormap direction depends on predicted class:
    #   malicious predicted: positive (red=malicious), negative (blue=benign) → RdBu_r
    #   benign predicted:    positive (blue=benign), negative (red=malicious) → RdBu
    if attribution.predicted_class == "malicious":
        cmap = plt.cm.RdBu_r
        cbar_label = "Attribution Score  (← benign | malicious →)"
    else:
        cmap = plt.cm.RdBu
        cbar_label = "Attribution Score  (← malicious | benign →)"

    # --- Top: Heatmap ---
    heatmap_data = binned.reshape(1, -1)
    im = ax_heat.imshow(
        heatmap_data, aspect="auto", cmap=cmap, norm=norm,
        extent=[0, n_bytes, 0, 1],
    )
    ax_heat.set_yticks([])
    ax_heat.set_xlabel("Byte Offset")
    ax_heat.set_title(
        f"Attribution Heatmap — {attribution.method} | "
        f"Pred: {attribution.predicted_class} ({attribution.confidence:.3f})",
        fontsize=11,
    )

    # Highlight full matched regions on heatmap
    for r in regions:
        color = "red" if r.direction == "malicious" else "blue"
        ax_heat.axvspan(r.start_offset, r.end_offset, alpha=0.25, color=color, linewidth=0)

    # Colorbar attached to heatmap
    fig.colorbar(im, ax=ax_heat, orientation="horizontal", pad=0.2, label=cbar_label)

    # --- Bottom: Line + scatter ---
    x = np.arange(n_bytes)
    ax_line.plot(x, scores, linewidth=0.5, color="navy", label="Attribution")
    ax_line.axhline(0, color="gray", linewidth=0.5, linestyle="--")

    # Highlight top-k midpoints colored by direction
    if top_offsets:
        top_idx = np.array(sorted(top_offsets))
        top_idx = top_idx[top_idx < n_bytes]
        # Separate into malicious/benign for distinct legend entries
        mal_idx = []
        ben_idx = []
        for idx in top_idx:
            if attribution.predicted_class == "malicious":
                (mal_idx if scores[idx] > 0 else ben_idx).append(idx)
            else:
                (ben_idx if scores[idx] > 0 else mal_idx).append(idx)
        if mal_idx:
            mal_idx = np.array(mal_idx)
            ax_line.scatter(
                mal_idx, scores[mal_idx], color="red", s=15, zorder=5,
                label="Malicious",
            )
        if ben_idx:
            ben_idx = np.array(ben_idx)
            ax_line.scatter(
                ben_idx, scores[ben_idx], color="blue", s=15, zorder=5,
                label="Benign",
            )

    ax_line.set_xlabel("Byte Offset")
    ax_line.set_ylabel("Attribution Score")
    ax_line.set_xlim(0, n_bytes)
    ax_line.legend(loc="upper right", fontsize=9)
    ax_line.set_title("Per-Byte Attribution Scores", fontsize=11)
    ax_line.grid(True, alpha=0.2)

    fig.tight_layout()
    plt.savefig(output_path, dpi=dpi)
    plt.close(fig)
    print(f"[*] Saved attribution plot to: {output_path}")
