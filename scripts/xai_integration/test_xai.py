"""
Usage:
    python test_xai.py                    # Run all methods
    python test_xai.py deeplift           # Run only deeplift
    python test_xai.py deeplift attention # Run specific methods
"""

import os
import sys
import json
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch

from models.malwhere_malconv import MalWhereMalConv
from xai.pipeline import XAIPipeline, AVAILABLE_METHODS
from utils.pe_mapper import PEMapper


OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xai_results")
TEST_SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_samples")


def get_test_files(samples_dir: str) -> list:
    """Collect all files from test_samples directory."""
    files = []
    if not os.path.isdir(samples_dir):
        print(f"[!] test_samples directory not found: {samples_dir}")
        return files
    for entry in os.listdir(samples_dir):
        full_path = os.path.join(samples_dir, entry)
        if os.path.isfile(full_path):
            files.append(full_path)
    return sorted(files)


def run_single_method(method_name: str, model, test_files: list,
                      use_explainer: bool = False) -> list:
    """Run a single XAI method on all test files as one experiment."""
    print(f"\n{'#'*60}")
    print(f"  EXPERIMENT: {method_name.upper()}")
    print(f"{'#'*60}")

    pipeline = XAIPipeline(
        model=model,
        method=method_name,
        window_size=256,
        top_k=10,
        use_explainer=use_explainer,
    )

    # Create method-specific output directory
    method_dir = os.path.join(OUTPUT_DIR, method_name)
    os.makedirs(method_dir, exist_ok=True)

    results = []
    total_time = 0

    for file_path in test_files:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        print(f"\n  {'─'*50}")
        print(f"  File: {file_name} ({file_size:,} bytes)")

        start = time.time()
        try:
            analysis = pipeline.analyze_file(file_path, target_class=None)
            elapsed = time.time() - start
            total_time += elapsed

            output = pipeline.to_json(analysis)
            output["analysis_time_seconds"] = round(elapsed, 3)
            output["file_name"] = file_name

            # Print summary
            if "error" not in output:
                pred = output.get("predicted_class", "?")
                conf = output.get("confidence", 0)
                n_regions = len(output.get("top_regions", []))
                print(f"  Prediction: {pred} (confidence={conf:.4f})")
                print(f"  Time: {elapsed:.2f}s | Top regions: {n_regions}")

                # Print top 5 regions
                regions = output.get("top_regions", [])
                if regions:
                    print(f"  Top Attribution Regions:")
                    for i, r in enumerate(regions[:5]):
                        print(f"    #{i+1}: 0x{r['start_offset']:06X}-0x{r['end_offset']:06X} "
                              f"score={r['score']:.6f} dir={r['direction']}")

                # Print PE mapping
                pe_map = output.get("pe_mapping")
                if pe_map and isinstance(pe_map, dict) and "region_mappings" in pe_map:
                    print(f"  PE Mapping:")
                    for mapping in pe_map["region_mappings"][:3]:
                        sec = mapping.get("section")
                        sec_name = sec["name"] if sec else "UNKNOWN"
                        strings = mapping.get("strings", [])
                        imports = mapping.get("imports", [])
                        print(f"    0x{mapping['start_offset']:06X}: section={sec_name}, "
                              f"strings={len(strings)}, imports={len(imports)}")
                        for s in strings[:2]:
                            print(f"      \"{s['value'][:60]}\" @ 0x{s['offset']:06X}")
                        for imp in imports[:2]:
                            print(f"      {imp['dll']}!{imp['function']}")

                # Print LLM explanation if available
                explanation = output.get("llm_explanation")
                if explanation and "error" not in explanation:
                    print(f"  LLM Explanation:")
                    print(f"    Summary: {explanation['summary']}")
                    print(f"    Risk: {explanation['risk_assessment']}")
                    print(f"    Indicators:")
                    for indicator in explanation.get('key_indicators', [])[:5]:
                        print(f"      - {indicator}")
                    print(f"    Confidence: {explanation['confidence_note']}")
                elif explanation and "error" in explanation:
                    print(f"  LLM Explanation Error: {explanation['error']}")
            else:
                print(f"  ERROR: {output['error']}")

            results.append(output)

            # Save individual file result
            individual_path = os.path.join(method_dir, f"{file_name}.json")
            with open(individual_path, 'w') as f:
                json.dump(output, f, indent=2, default=str)

        except Exception as e:
            elapsed = time.time() - start
            total_time += elapsed
            print(f"  ERROR: {e}")
            results.append({
                "file": file_path,
                "file_name": file_name,
                "method": method_name,
                "error": str(e),
            })

   
    print(f"\n  {'─'*50}")
    print(f"  {method_name.upper()} complete: {len(results)} files in {total_time:.2f}s")
    print(f"  Results: {method_dir}/")

    return results


def main():
    print("=" * 60)
    print("  MalConv2 XAI Attribution Pipeline")
    print("  Independent Method Testing")
    print("=" * 60)

    # Parse --explain flag
    use_explainer = '--explain' in sys.argv
    args = [a for a in sys.argv[1:] if a != '--explain']

    # Parse command-line arguments for method selection
    if args:
        methods_to_run = args
        # Validate
        for m in methods_to_run:
            if m not in AVAILABLE_METHODS:
                print(f"[!] Unknown method: {m}")
                print(f"    Available: {list(AVAILABLE_METHODS.keys())}")
                print(f"    Flags: --explain (enable LLM explanation)")
                sys.exit(1)
    else:
        methods_to_run = list(AVAILABLE_METHODS.keys())

    print(f"\n[*] Methods to run: {methods_to_run}")
    if use_explainer:
        print("[*] LLM Explainer: ENABLED (Gemini 2.5 Flash)")

    # Initialize model (shared across all methods)
    print("[*] Loading MalConv2 model...")
    try:
        detector = MalWhereMalConv()
        model = detector.model
    except FileNotFoundError as e:
        print(f"[!] Model checkpoint not found: {e}")
        sys.exit(1)

    # Collect test files
    test_files = get_test_files(TEST_SAMPLES_DIR)
    if not test_files:
        print("[!] No test samples found.")
        sys.exit(1)
    print(f"[*] Found {len(test_files)} test sample(s)")

    # Run each method independently
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    all_experiments = {}

    for method_name in methods_to_run:
        all_experiments[method_name] = run_single_method(
            method_name, model, test_files, use_explainer=use_explainer
        )

    # Summary
    print(f"\n\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    for method_name, results in all_experiments.items():
        n_files = len(results)
        n_errors = sum(1 for r in results if "error" in r)
        avg_time = np.mean([r.get("analysis_time_seconds", 0) for r in results if "analysis_time_seconds" in r])
        print(f"  {method_name:20s}: {n_files} files, {n_errors} errors, avg {avg_time:.2f}s/file")

    print(f"\n[*] All results in: {OUTPUT_DIR}/")
    print(f"[*] Each method has its own subdirectory with per-file JSON outputs.")


if __name__ == "__main__":
    main()
