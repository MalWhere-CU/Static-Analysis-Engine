#!/usr/bin/env python3
"""
Test script for MalConv2 integration in Static Analysis Engine
Demonstrates the full pipeline: YARA → MalConv → XAI → LLM Explanation
"""

import sys
import os
import json
from pathlib import Path

sys.path.append(os.path.dirname(__file__))

from detection.malconv_detection import MalConvDetector


# ============================================================
#  CONFIGURATION FLAGS
# ============================================================
YARA_AI_EXPLAINER = True       
USE_XAI = True                 
XAI_EXPLAINER = True           
XAI_METHOD = 'deeplift'        # XAI method: 'deeplift', 'lime', 'smoothgrad', 'ig'
# ============================================================


def test_pipeline_integration(target_file="test.exe"):
    """Test the full pipeline with MalConv fallback + XAI"""
    from pipeline import StaticPipeline
    from dotenv import load_dotenv

    load_dotenv()
    db_path = os.getenv("DB_PATH")

    if not db_path:
        print("  [!] Skipping - DB_PATH not set in .env")
        return None

    base_dir = Path(__file__).resolve().parent
    sample_file = base_dir / "test_samples" / target_file

    if not sample_file.exists():
        print(f"  [!] File not found: {sample_file}")
        return None

    pipeline = StaticPipeline(
        str(sample_file),
        yara_ai_explainer=YARA_AI_EXPLAINER,
        use_xai=USE_XAI,
        xai_explainer=XAI_EXPLAINER,
        xai_method=XAI_METHOD,
    )

    result = pipeline.process_file()

    # Print consistent output
    print(f"\n  Pipeline Result for file '{target_file}':")
    print(f"    Status: {result['status'].upper()}")
    print(f"    Packed: {result['packed']}")
    print(f"    YARA Matches: {result['yara_matches'] or 'None'}")
    print(f"    Scan Time: {result['scan_time']}s")

    if result['malconv_result']:
        mc = result['malconv_result']
        print(f"    MalConv Prediction: {mc['prediction']} (confidence={mc.get('confidence', 0):.4f})")

    if result.get('xai_result') and 'error' not in result['xai_result']:
        xai = result['xai_result']
        print(f"    XAI Method: {xai.get('method', '?')}")
        regions = xai.get('top_regions', [])
        if regions:
            print(f"    XAI Top Regions ({len(regions)}):")
            for i, r in enumerate(regions[:5]):
                print(f"      #{i+1}: 0x{r['start_offset']:06X}-0x{r['end_offset']:06X} "
                      f"score={r['score']:.4f} dir={r['direction']}")

        # PE mapping
        pe_map = xai.get('pe_mapping')
        if pe_map and isinstance(pe_map, dict) and 'region_mappings' in pe_map:
            print(f"    PE Mapping:")
            for mapping in pe_map['region_mappings'][:5]:
                sec = mapping.get('section')
                sec_name = sec['name'] if sec else 'UNKNOWN'
                strings = mapping.get('strings', [])
                imports = mapping.get('imports', [])
                print(f"      0x{mapping['start_offset']:06X}: section={sec_name}, "
                      f"strings={len(strings)}, imports={len(imports)}")
                for s in strings[:2]:
                    print(f"        \"{s['value'][:60]}\" @ 0x{s['offset']:06X}")
                for imp in imports[:2]:
                    print(f"        {imp['dll']}!{imp['function']}")

        # LLM Explanation
        explanation = xai.get('llm_explanation')
        if explanation and 'error' not in explanation:
            print(f"\n  AI Explanation Generated:")
            print(f"    Summary: {explanation['summary']}")
            print(f"    Risk: {explanation['risk_assessment']}")
            print(f"    Indicators:")
            for ind in explanation.get('key_indicators', [])[:5]:
                print(f"      - {ind}")
            print(f"    Confidence: {explanation['confidence_note']}")
        elif explanation and 'error' in explanation:
            print(f"\n  AI Explanation Error: {explanation['error']}")

    elif result.get('xai_result') and 'error' in result['xai_result']:
        print(f"    XAI Error: {result['xai_result']['error']}")

    # YARA AI explanation
    if result.get('report_data') and YARA_AI_EXPLAINER:
        report_path = result['report_data']
        if os.path.exists(report_path):
            with open(report_path) as f:
                report = json.load(f)
            yara_explanation = report.get('yara_ai_explainer', '')
            if yara_explanation and 'not enabled' not in yara_explanation:
                print(f"\n  YARA AI Explanation Generated:")
                print(f"    {yara_explanation}")

    if result.get('error'):
        print(f"    Error: {result['error']}")

    print(f"  {'─'*50}")
    return result


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  MalConv2 Integration Test Suite".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "═" * 58 + "╝")

    print(f"\n  Config:")
    print(f"    YARA AI Explainer: {YARA_AI_EXPLAINER}")
    print(f"    Use XAI: {USE_XAI}")
    print(f"    XAI Explainer: {XAI_EXPLAINER}")
    print(f"    XAI Method: {XAI_METHOD}")
    print(f"  {'─'*50}")

    test_files = ["test.exe", "mal_1.exe", "softonic103.exe"]

    for target in test_files:
        print(f"\n{'='*60}")
        print(f"  Processing: {target}")
        print(f"{'='*60}")
        test_pipeline_integration(target_file=target)

    print(f"\n{'='*60}")
    print("  All tests completed!")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()