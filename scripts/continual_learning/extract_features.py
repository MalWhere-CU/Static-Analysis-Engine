#!/usr/bin/env python3
"""
Usage:
    python extract_features.py <input_dir> <output_dir>

Output:
    output_dir/features.csv  (columns: filename, family, feat_0, feat_1, ..., feat_N)
"""

import sys
import os
import csv
import numpy as np
import torch
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), 'MalConv2'))

from MalConvGCT_nocat import MalConvGCT

MAX_LEN = 4_000_000  # 4MB max file size (matches training)
BATCH_SAVE_INTERVAL = 100  # Save to CSV every N samples


def load_model(checkpoint_path=None):
    if checkpoint_path is None:
        checkpoint_path = os.path.join(os.path.dirname(__file__), 'MalConv2', 'malconvGCT_nocat.checkpoint')

    model = MalConvGCT(channels=256, window_size=256, stride=64)
    checkpoint = torch.load(checkpoint_path, map_location='cpu')
    model.load_state_dict(checkpoint['model_state_dict'], strict=False)
    model.eval()
    print(f"[+] Model loaded from {checkpoint_path}")
    return model


def extract_embedding(model, file_path):
    """Extract penultimate layer embedding from a single file."""
    with open(file_path, 'rb') as f:
        data = f.read(MAX_LEN)

    if len(data) == 0:
        return None

    data_np = np.frombuffer(data, dtype=np.uint8).astype(np.int16) + 1
    data_tensor = torch.tensor(data_np, dtype=torch.long).unsqueeze(0)

    with torch.no_grad():
        _, penult, _ = model(data_tensor)

    return penult.squeeze(0).numpy()


def collect_samples(input_dir):
    """Collect all (file_path, family) pairs from the input directory."""
    samples = []
    input_path = Path(input_dir)
    for family_dir in sorted(input_path.iterdir()):
        if not family_dir.is_dir():
            continue
        family = family_dir.name
        for sample_file in sorted(family_dir.iterdir()):
            if sample_file.is_file():
                samples.append((str(sample_file), family))
    return samples


def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <input_dir> <output_dir>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.isdir(input_dir):
        print(f"[!] Input directory not found: {input_dir}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    output_csv = os.path.join(output_dir, 'features.csv')
    temp_csv = output_csv + '.tmp'

    model = load_model()

    samples = collect_samples(input_dir)
    total = len(samples)
    print(f"[+] Found {total} samples across families")

    if total == 0:
        print("[!] No samples found. Exiting.")
        sys.exit(1)

    # Determine embedding dimension from first valid sample
    emb_dim = None
    for file_path, _ in samples:
        try:
            emb = extract_embedding(model, file_path)
            if emb is not None:
                emb_dim = emb.shape[0]
                break
        except Exception:
            continue

    if emb_dim is None:
        print("[!] Could not determine embedding dimension. No valid samples.")
        sys.exit(1)

    print(f"[+] Embedding dimension: {emb_dim}")

    header = ['filename', 'family'] + [f'feat_{i}' for i in range(emb_dim)]

    # Write to temp file, rename on completion for crash safety
    written = 0
    failed = 0

    with open(temp_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for idx, (file_path, family) in enumerate(samples):
            try:
                emb = extract_embedding(model, file_path)
                if emb is None:
                    print(f"  [{idx+1}/{total}] SKIP (empty): {os.path.basename(file_path)}")
                    failed += 1
                    continue

                filename = os.path.basename(file_path)
                row = [filename, family] + emb.tolist()
                writer.writerow(row)
                written += 1

                if written % 200 == 0:
                    print(f"  [{idx+1}/{total}] Processed: {filename} ({family})")

                # Flush to disk periodically for safety
                if written % BATCH_SAVE_INTERVAL == 0:
                    f.flush()
                    os.fsync(f.fileno())

            except Exception as e:
                failed += 1
                print(f"  [{idx+1}/{total}] ERROR: {os.path.basename(file_path)} - {e}")
                continue

        # Final flush
        f.flush()
        os.fsync(f.fileno())

    # Atomic rename: temp -> final
    os.replace(temp_csv, output_csv)

    print(f"\n[+] Done! Written {written} rows, {failed} failures.")
    print(f"[+] Output: {output_csv}")


if __name__ == "__main__":
    main()
