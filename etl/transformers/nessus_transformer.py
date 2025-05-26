from datetime import datetime
from typing import Dict, List, Any
import json
import logging

logger = logging.getLogger(__name__)

class NessusTransformer:
    def __init__(self):
        self.severity_mapping = {
            "0": "Info",
            "1": "Low",
            "2": "Medium",
            "3": "High",
            "4": "Critical"
        }
    
    def transform_vulnerabilities(self, raw_vulns: List[Dict]) -> List[Dict]:
        transformed = []
        for vuln in raw_vulns:
            severity = str(vuln.get("Severity", "0"))
            transformed_vuln = {
                "Asset_Name": vuln.get("Asset_Name", ""),
                "Vulnerability_Name": vuln.get("Vulnerability_Name", ""),
                "Status": "Open",
                "Risk": self.severity_mapping.get(severity, "Info"),
                "Risk_Score": vuln.get("CVSS_Score", 0),
                "CVSS_Score": vuln.get("CVSS_Score"),
                "First_Seen": datetime.now().isoformat(),
                "Last_Seen": datetime.now().isoformat(),
                "Inclusion_Date": datetime.now().isoformat(),
                "Sources": json.dumps(["Nessus"]),
                "Threats": json.dumps([]),
                "Tags": json.dumps([self.severity_mapping.get(severity, "Info")]),
                "Business_Groups": json.dumps(["Unassigned"]),
                "Owners": json.dumps(["Unassigned"]),
                "CVE": "",
                "Vulnerability_Description": "",
                "Solution": "",
                "Severity": self.severity_mapping.get(severity, "Info"),
                "Scanner": "Nessus",
                "IP": vuln.get("IP", ""),
            }
            transformed.append(transformed_vuln)
        return transformed
    
    def transform_assets(self, raw_assets: List[Dict]) -> List[Dict]:
        transformed = []
        for asset in raw_assets:
            transformed_asset = {
                "Asset_Name": asset.get("Asset_Name", ""),
                "Type": asset.get("Type", "Host"),
                "Asset_IP": asset.get("Asset_IP", ""),
                "Asset_First_Seen": datetime.now().isoformat(),
                "Asset_Last_Seen": datetime.now().isoformat(),
                "Inclusion_Date": datetime.now().isoformat(),
                "Asset_Tags": json.dumps([]),
                "Business_Groups": json.dumps(["Unassigned"]),
                "Owners": json.dumps(["Unassigned"]),
                "Asset_ID": asset.get("Asset_Name", "").replace(" ", "_").lower(),
            }
            transformed.append(transformed_asset)
        return transformed
