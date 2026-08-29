import json
from datetime import datetime


def generate_json(results, filename="pulse_report.json"):

    report = {
        "metadata": {
            "generated_at": str(datetime.now())
        },
        "hosts": results
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    return filename
