class MisconfigurationEngine:

    @staticmethod
    def run(host, ports):

        findings = []

        if 21 in ports:
            findings.append({
                "title": "FTP Anonymous Access Possible",
                "risk": "HIGH"
            })

        if 445 in ports:
            findings.append({
                "title": "SMB Service Exposed",
                "risk": "HIGH"
            })

        if 80 in ports and 443 not in ports:
            findings.append({
                "title": "HTTP Without HTTPS",
                "risk": "MEDIUM"
            })

        if 23 in ports:
            findings.append({
                "title": "Telnet Enabled",
                "risk": "HIGH"
            })

        if 3389 in ports:
            findings.append({
                "title": "RDP Exposed",
                "risk": "MEDIUM"
            })

        return findings
