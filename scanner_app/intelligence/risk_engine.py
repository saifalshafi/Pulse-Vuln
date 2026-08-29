class RiskEngine:

    @staticmethod
    def calculate(scan_results):

        total_score = 0

        for host, data in scan_results.items():

            for cve in data.get("cves", []):
                total_score += float(cve.get("score", 0))

            for issue in data.get("misconfigurations", []):
                if issue["risk"] == "HIGH":
                    total_score += 8
                elif issue["risk"] == "MEDIUM":
                    total_score += 5
                elif issue["risk"] == "LOW":
                    total_score += 2

        return round(total_score, 2)

    @staticmethod
    def classify(score):

        if score == 0:
            return "LOW"
        elif score < 20:
            return "MEDIUM"
        elif score < 50:
            return "HIGH"
        else:
            return "CRITICAL"
