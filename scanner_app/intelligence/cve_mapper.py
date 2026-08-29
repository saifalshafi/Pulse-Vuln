import requests
import time
import threading


class CVEMapper:

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # 🔥 Cache لمنع تكرار البحث لنفس الإصدار
    _cache = {}
    _lock = threading.Lock()

    def __init__(self):
        self.delay = 1  # قللنا التأخير

    def search(self, product_string):

        if not product_string:
            return []

        clean_string = product_string.replace("/", " ")

        # ============================
        # Prevent duplicate lookups
        # ============================
        with CVEMapper._lock:
            if clean_string in CVEMapper._cache:
                return CVEMapper._cache[clean_string]

        params = {
            "keywordSearch": clean_string,
            "resultsPerPage": 5
        }

        try:
            # ❌ تم حذف print المزعج هنا

            response = requests.get(self.BASE_URL, params=params, timeout=15)

            if response.status_code != 200:
                return []

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            results = []

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id")

                description = ""
                descriptions = cve.get("descriptions", [])
                if descriptions:
                    description = descriptions[0].get("value", "")

                metrics = cve.get("metrics", {})
                severity = "UNKNOWN"
                score = 0.0

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                    score = cvss.get("baseScore", 0.0)

                results.append({
                    "cve_id": cve_id,
                    "description": description[:300],
                    "severity": severity,
                    "score": score,
                    "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })

            # حفظ في الكاش
            with CVEMapper._lock:
                CVEMapper._cache[clean_string] = results

            time.sleep(self.delay)
            return results

        except:
            return []
