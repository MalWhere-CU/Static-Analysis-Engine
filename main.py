import sys
import json
import os
from pipeline import StaticPipeline


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <file1> <file2> ...")
        sys.exit(1)

    files = sys.argv[1:]

    pipeline = StaticPipeline(files[0], yara_ai_explainer=True)  # Initialize pipeline with the first file for AI explaination

    results = []

    for file_path in files:
        if not os.path.exists(file_path):
            results.append({
                "file": file_path,
                "error": "File does not exist"
            })
            continue

        result = pipeline.process_file()
        results.append(result)

    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
