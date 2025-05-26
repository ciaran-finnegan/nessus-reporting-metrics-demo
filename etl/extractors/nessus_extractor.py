import xml.etree.ElementTree as ET
from typing import Dict, List, Any
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)

class NessusExtractor:
    def __init__(self, nessus_file_path: str):
        self.nessus_file_path = nessus_file_path
        self.tree = ET.parse(nessus_file_path)
        self.root = self.tree.getroot()
    
    def _get_host_properties(self, report_host):
        properties = {}
        properties["host-ip"] = report_host.get("name", "")
        host_properties = report_host.find("HostProperties")
        if host_properties is not None:
            for tag in host_properties.findall("tag"):
                name = tag.get("name", "")
                value = tag.text or ""
                properties[name] = value
        return properties
    
    def _get_element_text(self, parent, element_name):
        """Get text content from a child element"""
        element = parent.find(element_name)
        return element.text if element is not None else None
    
    def _map_severity_to_risk(self, severity):
        """Map Nessus severity numbers to risk levels"""
        severity_map = {
            "0": "None",
            "1": "Low", 
            "2": "Medium",
            "3": "High",
            "4": "Critical"
        }
        return severity_map.get(severity, "Unknown")
    
    def extract_vulnerabilities(self):
        vulnerabilities = []
        for report_host in self.root.findall(".//ReportHost"):
            host_properties = self._get_host_properties(report_host)
            for report_item in report_host.findall("ReportItem"):
                severity = report_item.get("severity", "0")
                if severity == "0":
                    continue
                vuln_data = {
                    "Asset_Name": host_properties.get("host-fqdn", host_properties.get("host-ip", "")),
                    "IP": host_properties.get("host-ip", ""),
                    "Asset_IP": host_properties.get("host-ip", ""),
                    "Plugin_ID": report_item.get("pluginID", ""),
                    "Vulnerability_Name": report_item.get("pluginName", ""),
                    "CVSS_Score": float(report_item.get("cvss_base_score", 0)) if report_item.get("cvss_base_score") else None,
                    "Severity": severity,
                    "Risk": self._map_severity_to_risk(severity),
                    "Family": report_item.get("pluginFamily", ""),
                    "Port": report_item.get("port", ""),
                    "Protocol": report_item.get("protocol", "tcp"),
                    "Service": report_item.get("svc_name", ""),
                    "Scanner": "Nessus",
                    # Extract additional details from child elements
                    "Description": self._get_element_text(report_item, "description"),
                    "Solution": self._get_element_text(report_item, "solution"),
                    "Synopsis": self._get_element_text(report_item, "synopsis"),
                    "Plugin_Output": self._get_element_text(report_item, "plugin_output"),
                }
                vulnerabilities.append(vuln_data)
        return vulnerabilities
    
    def extract_assets(self):
        assets = []
        for report_host in self.root.findall(".//ReportHost"):
            host_properties = self._get_host_properties(report_host)
            asset_data = {
                "Asset_Name": host_properties.get("host-fqdn", host_properties.get("host-ip", "")),
                "Asset_IP": host_properties.get("host-ip", ""),
                "Type": "Host",
            }
            assets.append(asset_data)
        return assets
