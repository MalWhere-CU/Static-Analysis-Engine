#!/usr/bin/env python3
"""
Test script for MalConv2 integration in Static Analysis Engine
Demonstrates the fallback behavior: YARA first, then MalConv if no matches
"""

import sys
import os
import json
from pathlib import Path

sys.path.append(os.path.dirname(__file__))

from detection.malconv_detection import MalConvDetector


def test_pipeline_integration():
    """Test the full pipeline with MalConv fallback"""
    print("\n" + "=" * 60)
    print("Testing Pipeline Integration")
    print("=" * 60)
    
    try:
        from pipeline import StaticPipeline
        from dotenv import load_dotenv
        
        load_dotenv()
        db_path = os.getenv("DB_PATH")
        
        if not db_path:
            print("   Skipping full pipeline test - DB_PATH not set in .env")
            print("   To run this test, ensure .env file is configured with:")
            print("   - OPENAI_API_KEY")
            print("   - DB_PATH")
            print("   - REDIS_HOST")
            return None
        
        base_dir = Path(__file__).resolve().parent
        sample_file = base_dir / "test_samples" / "test.exe"

        if not sample_file.exists():
            print(f"   Skipping full pipeline test - sample file not found: {sample_file}")
            return None

        print("Initializing StaticPipeline...")
        pipeline = StaticPipeline(str(sample_file))
        
        print("Processing file through pipeline...\n")
        result = pipeline.process_file()
        
        print(f"Pipeline Result:")
        print(json.dumps(result, indent=2, default=str))
        
        return result
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_with_sample_exe():
    """Test MalConv with actual exe files from test_samples/"""
    print("\n" + "=" * 60)
    print("Testing with Sample EXE Files")
    print("=" * 60)
    
    base_dir = Path(__file__).resolve().parent
    sample_dir = base_dir / "test_samples"
    
    if not sample_dir.exists():
        print(f"  Sample directory not found: {sample_dir}")
        return None
    
    try:
        detector = MalConvDetector()
        exe_files = [f for f in os.listdir(sample_dir) if f.endswith('.exe')]
        
        if not exe_files:
            print(f"  No .exe files found in {sample_dir}")
            return None
        
        print(f"\nFound {len(exe_files)} sample files\n")
        
        for exe_file in exe_files[:]:  # Test first 5 files
            file_path = sample_dir / exe_file
            file_size = os.path.getsize(file_path)
            
            print(f"Analyzing: {exe_file} ({file_size} bytes)")
            result = detector.predict(str(file_path))
            
            print(f"  → Prediction: {result['prediction'].upper()}")
            print(f"  → Confidence: {result.get('confidence', 'N/A'):.4f}")
            
            if result.get('error'):
                print(f"  → Error: {result['error']}")
            print()
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_different_thresholds():
    """Test predictions with different confidence thresholds"""
    print("\n" + "=" * 60)
    print("Testing Different Thresholds")
    print("=" * 60)
    
    try:
        detector = MalConvDetector()
        
        base_dir = Path(__file__).resolve().parent
        test_file = base_dir / "test_samples" / "test.exe"
        
        if not test_file.exists():
            print(f"  Skipping threshold test - file not found: {test_file}")
            return None
        
        thresholds = [0.3, 0.5, 0.7, 0.9]
        
        print(f"\nTesting file: {test_file}\n")
        
        for threshold in thresholds:
            result = detector.predict(str(test_file), threshold=threshold)
            print(f"Threshold: {threshold:.1f} → Prediction: {result['prediction']} (confidence: {result['confidence']:.4f})")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Run all tests"""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  MalConv2 Integration Test Suite".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "═" * 58 + "╝")
    print()
    
    
    # Test 1: Test with sample exe files
    test_with_sample_exe()

    # Test 2: Different thresholds
    test_different_thresholds()
    
    # Test 3: Full pipeline integration (requires .env)
    test_pipeline_integration()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()