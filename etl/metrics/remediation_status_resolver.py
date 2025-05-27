"""
remediation_status_resolver.py

This module is responsible for determining the remediation status of vulnerabilities before any metrics are calculated.
It should be run as the first step in the metrics pipeline. It analyses vulnerability and asset data across scans to
set the 'remediation_status' field for each vulnerability record, which is then used by MTTR and other metrics modules.

Typical statuses:
- 'open': Vulnerability is present in the current scan
- 'remediated': Vulnerability was present in a previous scan but is not present in the current scan
- 'reopened': Vulnerability was remediated but has reappeared

Usage:
    from etl.metrics.remediation_status_resolver import resolve_remediation_status
    resolved_vulns = resolve_remediation_status(vulnerabilities, previous_vulnerabilities)
"""
from typing import List, Dict
from collections import defaultdict

def resolve_remediation_status(current_vulns: List[Dict], previous_vulns: List[Dict]) -> List[Dict]:
    """
    Annotate each vulnerability in current_vulns with a 'remediation_status' field.
    Args:
        current_vulns: List of vulnerabilities from the current scan.
        previous_vulns: List of vulnerabilities from the previous scan.
    Returns:
        List of vulnerabilities with 'remediation_status' set.
    """
    # Build lookup for previous vulnerabilities by unique key (e.g., asset_id + plugin_id)
    prev_lookup = {(v['asset_id'], v['plugin_id']): v for v in previous_vulns}
    curr_lookup = {(v['asset_id'], v['plugin_id']): v for v in current_vulns}

    resolved = []
    # Mark current vulnerabilities
    for vuln in current_vulns:
        key = (vuln['asset_id'], vuln['plugin_id'])
        if key in prev_lookup:
            # If present in both, still open (or possibly reopened)
            if prev_lookup[key].get('remediation_status') == 'remediated':
                vuln['remediation_status'] = 'reopened'
            else:
                vuln['remediation_status'] = 'open'
        else:
            vuln['remediation_status'] = 'open'
        resolved.append(vuln)

    # Mark remediated vulnerabilities (present in previous, not in current)
    for key, prev_vuln in prev_lookup.items():
        if key not in curr_lookup:
            remediated_vuln = prev_vuln.copy()
            remediated_vuln['remediation_status'] = 'remediated'
            resolved.append(remediated_vuln)

    return resolved 