import die
import pefile
import os
import json
import math

def calculate_entropy(file_path):
    """Measures how 'random' a file is. Packed files usually have entropy > 7.0."""
    with open(file_path, 'rb') as f:
        data = f.read()
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def detect_packer(file_path):
    report = {
        "filename": os.path.basename(file_path),
        "die_match": False,
        "section_match": False,
        "high_entropy": False,
        "details": []
    }

    # 1. check signatures (DIE)
    try:
        raw = die.scan_file(file_path, die.ScanFlags.DEEP_SCAN | die.ScanFlags.RESULT_AS_JSON)
        res = json.loads(raw) if isinstance(raw, str) else raw
        
        for d in res.get('detects', []):
            if d.get('type') in ['Packer', 'Protector']:
                report["die_match"] = True
                report["details"].append(f"Signature: {d['name']} {d.get('version', '')}")
    except: pass

    # 2. check structure (sections)
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            name = section.Name.decode().strip("\x00")
            if any(p in name.upper() for p in ["UPX", "ASPACK", "MEW", "THEMIDA", "PESPIN"]):
                report["section_match"] = True
                report["details"].append(f"Section Name: {name}")
    except: pass

    # 3. check entropy
    entropy = calculate_entropy(file_path)
    if entropy > 7.1:
        report["high_entropy"] = True
        report["details"].append(f"High Entropy: {entropy:.2f}")

    return report

