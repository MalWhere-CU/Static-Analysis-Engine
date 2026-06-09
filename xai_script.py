"""
Usage:
    python xai_script.py <input_dir> <output_dir>
    python xai_script.py <input_dir> <output_dir> --method deeplift

Examples:
    python xai_script.py ./final_dataset ./XAI_outputs
    python xai_script.py ./final_dataset ./XAI_outputs --method attention
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch

from detection.malconv_detection import MalConvDetector
from xai.pipeline import XAIPipeline, AVAILABLE_METHODS

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def collect_files(input_dir: str) -> list[tuple[str, str]]:
    """
    Walk the input directory and collect all files.

    Returns a list of (absolute_file_path, relative_path_from_input_dir) tuples.
    Only goes one level deep (family/sample.exe), but works for any depth.
    """
    collected = []
    input_path = Path(input_dir).resolve()

    for root, dirs, files in os.walk(input_path):
        dirs.sort()   # deterministic ordering
        for file_name in sorted(files):
            abs_path = Path(root) / file_name
            rel_path = abs_path.relative_to(input_path)   # e.g. Agensla/sample1.exe
            collected.append((str(abs_path), str(rel_path)))

    return collected

def build_output_path(output_dir: str, rel_path: str) -> Path:
    """
    Mirror the relative input path into the output directory,
    replacing the file extension with .json.

    Example:
        rel_path   = "Agensla/sample1.exe"
        output_dir = "./XAI_outputs"
        → ./XAI_outputs/Agensla/sample1.json
    """
    rel = Path(rel_path)
    json_name = rel.stem + ".json"          # sample1.exe  →  sample1.json
    out_path = Path(output_dir) / rel.parent / json_name
    return out_path

def save_json(data: dict, path: Path) -> None:
    """Create parent directories if needed and write JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

# ─────────────────────────────────────────────
#  Core processing
# ─────────────────────────────────────────────

def process_file(
    pipeline: XAIPipeline,
    abs_path: str,
    rel_path: str,
    output_dir: str,
    method_name: str,
) -> dict:
    """
    Run XAI attribution on a single file, save the result, and return it.
    """
    file_name = os.path.basename(abs_path)
    file_size = os.path.getsize(abs_path)
    out_path  = build_output_path(output_dir, rel_path)

    # print(f"  ├─ {rel_path}  ({file_size:,} bytes)")

    start = time.time()
    try:
        analysis = pipeline.analyze_file(abs_path, target_class=None)
        elapsed  = time.time() - start

        output = pipeline.to_json(analysis)
        output["analysis_time_seconds"] = round(elapsed, 3)
        output["file_name"]             = file_name
        output["relative_path"]         = rel_path

        if "error" in output:
            print(f"  │    ERROR: {output['error']}")

    except Exception as exc:
        elapsed = time.time() - start
        print(f"  │    EXCEPTION: {exc}")
        output = {
            "file":             abs_path,
            "file_name":        file_name,
            "relative_path":    rel_path,
            "method":           method_name,
            "error":            str(exc),
            "analysis_time_seconds": round(elapsed, 3),
        }

    save_json(output, out_path)
    return output

def run_batch(
    input_dir:   str,
    output_dir:  str,
    method_name: str,
    model,
) -> None:
    """
    Iterate over every file in input_dir, run attribution, and mirror
    the directory structure into output_dir.
    """
    files = collect_files(input_dir)

    if not files:
        print(f"[!] No files found in: {input_dir}")
        sys.exit(1)

    print(f"\n[*] Found {len(files)} file(s) across all sub-directories.")
    print(f"[*] Method  : {method_name}")
    print(f"[*] Input   : {Path(input_dir).resolve()}")
    print(f"[*] Output  : {Path(output_dir).resolve()}")

    # Build pipeline once — reused for every file
    pipeline = XAIPipeline(
        model=model,
        method=method_name,
        window_size=256,
        top_k=10,
        use_explainer=False,          # LLM explanation disabled
    )

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # ── Group files by their parent folder for nicer console output ──
    from itertools import groupby
    key_fn = lambda t: str(Path(t[1]).parent)   # e.g. "Agensla"

    total_start  = time.time()
    all_results  = []
    total_errors = 0

    for family, group in groupby(files, key=key_fn):
        group_list = list(group)
        print(f"\n[Family] {family}  ({len(group_list)} file(s))")

        for abs_path, rel_path in group_list:
            result = process_file(
                pipeline, abs_path, rel_path, output_dir, method_name
            )
            all_results.append(result)
            if "error" in result:
                total_errors += 1

    total_elapsed = time.time() - total_start

    # ── Final summary ──────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  BATCH COMPLETE")
    print(f"{'='*60}")
    print(f"  Total files   : {len(all_results)}")
    print(f"  Errors        : {total_errors}")
    print(f"  Total time    : {total_elapsed:.2f}s")
    if all_results:
        avg = total_elapsed / len(all_results)
        print(f"  Avg per file  : {avg:.2f}s")
    print(f"  Output dir    : {Path(output_dir).resolve()}")
    print(f"{'='*60}\n")

# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch XAI attribution — mirrors input directory structure to output.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "input_dir",
        help="Root directory containing family sub-folders with PE samples.",
    )
    parser.add_argument(
        "output_dir",
        help="Root directory where JSON reports will be written.",
    )
    parser.add_argument(
        "--method",
        default="deeplift",
        choices=list(AVAILABLE_METHODS.keys()),
        help="XAI attribution method to use (default: deeplift).",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()

    # ── Validate input directory ───────────────────────────────────
    if not os.path.isdir(args.input_dir):
        print(f"[!] Input directory not found: {args.input_dir}")
        sys.exit(1)

    print("=" * 60)
    print("  MalConv2 XAI — Batch Attribution")
    print("=" * 60)

    # ── Load model ─────────────────────────────────────────────────
    print("\n[*] Loading MalConv2 model...")
    try:
        detector = MalConvDetector()
        model    = detector.model
        print("[*] Model loaded successfully.")
    except FileNotFoundError as exc:
        print(f"[!] Model checkpoint not found: {exc}")
        sys.exit(1)

    # ── Run ────────────────────────────────────────────────────────
    run_batch(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        method_name=args.method,
        model=model,
    )

if __name__ == "__main__":
    main()