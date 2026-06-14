# run_tests.py
import os
import sys
from pipeline import StaticPipeline

def test_full_pipeline(samples_dir):
    print("====================================================")
    print(" 🧪 RUNNING ENGINE INTEGRATION TESTS (FULL PIPELINE) ")
    print("====================================================\n")
    
    if not os.path.exists(samples_dir):
        print(f"[!] Error: The directory '{samples_dir}' does not exist.")
        return False

    pipeline_failures = 0
    files = [f for f in os.listdir(samples_dir) if os.path.isfile(os.path.join(samples_dir, f))]
    
    if not files:
        print(f"[-] No samples detected inside {samples_dir}. Drop test binaries there!")
        return False

    for sample in files:
        file_path = os.path.join(samples_dir, sample)
        print(f"[*] Processing sample through whole pipeline: {sample}")
        
        try:
            # Emulate options used in your pipeline.py
            engine = StaticPipeline(file_path=file_path, use_xai=False)
            analysis_output = engine.process_file()
            
            print(f"    ├─ Packed Detected?   : {analysis_output['packed']}")
            print(f"    ├─ Packer Type        : {analysis_output['packer_category']}")
            print(f"    ├─ Unpacking Success  : {analysis_output['unpacked']}")
            print(f"    ├─ Match Verdict Source: {analysis_output['match_source']}")
            print(f"    └─ Pipeline Status    : {analysis_output['status']}\n")
        except Exception as e:
            print(f"[!] CRITICAL FAILURE parsing {sample}: {e}\n")
            pipeline_failures += 1

    print(f"[#] Test Run Complete. Total Crashes/Exceptions: {pipeline_failures}")
    return pipeline_failures == 0

if __name__ == "__main__":
    # Internal mapped docker volume folder
    TARGET_DIR = "/test_samples/unpacking"
    success = test_full_pipeline(TARGET_DIR)
    sys.exit(0 if success else 1)