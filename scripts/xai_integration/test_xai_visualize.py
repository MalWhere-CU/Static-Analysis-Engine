import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.malwhere_malconv import MalWhereMalConv
from xai.pipeline import XAIPipeline
from utils.xai_visualize import visualize_attributions


def run_visualization(
    sample_path: str = "test_samples/Windows_10.exe",
    method: str = "deeplift",
    output_path: str = "xai_results/Windows_10.png",
    window_size: int = 256,
    top_k: int = 10,
    heatmap_bins: int = 512,
    dpi: int = 150,
):
    
    # Resolve relative paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(sample_path):
        sample_path = os.path.join(base_dir, sample_path)
    if not os.path.isabs(output_path):
        output_path = os.path.join(base_dir, output_path)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"[*] Sample: {sample_path}")
    print(f"[*] Method: {method}")
    print(f"[*] Output: {output_path}")

    # Load model
    print("[*] Loading MalConv2 model...")
    detector = MalWhereMalConv()
    model = detector.model

    # Run XAI pipeline
    print(f"[*] Running {method} attribution...")
    pipeline = XAIPipeline(model=model, method=method, window_size=window_size, top_k=top_k)
    analysis = pipeline.analyze_file(sample_path, target_class=None)

    if "error" in analysis:
        print(f"[!] Error: {analysis['error']}")
        return

    attribution = analysis["attribution"]
    print(f"[*] Prediction: {attribution.predicted_class} (conf={attribution.confidence:.4f})")
    print(f"[*] Bidirectional regions: {len(attribution.top_regions_bidirectional)}")

    # Visualize
    visualize_attributions(
        attribution=attribution,
        output_path=output_path,
        heatmap_bins=heatmap_bins,
        dpi=dpi,
    )


if __name__ == "__main__":
    run_visualization()
