import csv
import json

class PhishGuardReporter:
    @staticmethod
    def export_csv(results, filename="phishguard_report.csv"):
        keys = ["raw_url", "normalized_url", "risk_score", "risk_level"]
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "raw_url": r["raw_url"],
                    "normalized_url": r["normalized_url"],
                    "risk_score": r["risk_score"],
                    "risk_level": r["risk_level"]
                })
        return filename

    @staticmethod
    def export_json(results, filename="phishguard_report.json"):
        with open(filename, mode='w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        return filename
