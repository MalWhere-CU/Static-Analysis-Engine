import sys
import json
from pathlib import Path
from pipeline import StaticPipeline


REPORTS_DIR = Path("/home/abdallah/malware-unpacking-and-yara-detection-sys/data/reports")


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <file1> <file2> ...")
        sys.exit(1)

    sample_path = sys.argv[1]

    pipeline = StaticPipeline(file_path=sample_path, yara_ai_explainer=False)
    result = pipeline.process_file()

    print(json.dumps(result, indent=4))

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    sample_name = Path(sample_path).stem
    report_name = "".join(sample_name) + ".json"

    report_file = REPORTS_DIR / report_name

    with open(report_file, "w") as f:
        json.dump(result, f, indent=4)

    print(f"Report saved to: {report_file}")


if __name__ == "__main__":
    main()