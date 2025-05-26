#!/usr/bin/env python3
"""
Query Business Context Data

A simple script to query and display existing business context data
without loading any new data. Useful for checking current state.
"""

import os
import sys
import logging
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supabase import create_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def query_business_context():
    """Query and display business context data"""
    
    # Initialize Supabase client
    url = os.getenv('SUPABASE_URL')
    key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
    
    if not url or not key:
        logger.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env")
        return
    
    client = create_client(url, key)
    
    # 1. Business Groups
    logger.info("=== Business Groups ===")
    bg_result = client.table('business_groups').select('*').order('path').execute()
    
    if bg_result.data:
        for bg in bg_result.data:
            indent = "  " * bg['depth']
            logger.info(f"{indent}• {bg['name']} (ID: {bg['id'][:8]}...)")
            if bg['description']:
                logger.info(f"{indent}  {bg['description']}")
    else:
        logger.info("No business groups found")
    
    # 2. Asset Tags
    logger.info("\n=== Asset Tags ===")
    tags_result = client.table('asset_tags').select('*').order('name').execute()
    
    if tags_result.data:
        for tag in tags_result.data:
            logger.info(f"• {tag['name']} ({tag['tag_type']})")
            if tag['description']:
                logger.info(f"  {tag['description']}")
            if tag.get('rule_definition'):
                logger.info(f"  Rule: {tag['rule_definition']}")
    else:
        logger.info("No tags found")
    
    # 3. Assets with Context
    logger.info("\n=== Assets with Business Context ===")
    assets_result = client.table('assets_with_context').select(
        'asset_fingerprint, current_hostname, current_ip_address, '
        'assigned_business_groups, assigned_tags, effective_criticality, is_active'
    ).eq('is_active', True).limit(20).execute()
    
    if assets_result.data:
        for asset in assets_result.data:
            logger.info(f"\n• {asset['current_hostname']} ({asset['current_ip_address']})")
            logger.info(f"  Fingerprint: {asset['asset_fingerprint']}")
            logger.info(f"  Business Groups: {', '.join(asset.get('assigned_business_groups', []) or ['None'])}")
            logger.info(f"  Tags: {', '.join(asset.get('assigned_tags', []) or ['None'])}")
            logger.info(f"  Criticality: {asset.get('effective_criticality', 'N/A')}")
    else:
        logger.info("No assets found")
    
    # 4. Vulnerability Summary by Business Group
    logger.info("\n=== Vulnerability Summary by Business Group ===")
    vuln_summary = client.table('vulnerability_summary_by_business_group').select('*').execute()
    
    if vuln_summary.data:
        for group in vuln_summary.data:
            if group['total_assets'] > 0:
                logger.info(f"\n• {group['business_group_name']}:")
                logger.info(f"  Total Assets: {group['total_assets']}")
                logger.info(f"  Total Vulnerabilities: {group['total_vulnerabilities']}")
                logger.info(f"  Critical: {group['critical_vulns']}, High: {group['high_vulns']}, "
                          f"Medium: {group['medium_vulns']}, Low: {group['low_vulns']}")
                logger.info(f"  Avg Asset Criticality: {group.get('avg_asset_criticality', 'N/A')}")
                logger.info(f"  Risk Score: {group.get('risk_score', 0)}")
    else:
        logger.info("No vulnerability data by business group")
    
    # 5. Tag Statistics
    logger.info("\n=== Tag Assignment Statistics ===")
    
    # Get all tags
    tags_result = client.table('asset_tags').select('id, name, tag_type, metadata').execute()
    
    if tags_result.data:
        for tag in tags_result.data:
            # Count assignments for this tag
            assignments = client.table('asset_tag_assignments').select(
                'asset_id', count='exact'
            ).eq('tag_id', tag['id']).execute()
            
            asset_count = assignments.count if hasattr(assignments, 'count') else 0
            
            logger.info(f"• {tag['name']} ({tag['tag_type']}): {asset_count} assets")
            criticality_score = tag.get('metadata', {}).get('criticality_score')
            if criticality_score:
                logger.info(f"  Criticality Score: {criticality_score}")
    
    # 6. Recent Scan Sessions
    logger.info("\n=== Recent Scan Sessions ===")
    scans = client.table('scan_sessions').select('*').order(
        'scan_date', desc=True
    ).limit(5).execute()
    
    if scans.data:
        for scan in scans.data:
            logger.info(f"\n• {scan['scan_name']} - {scan['scan_date']}")
            logger.info(f"  Hosts: {scan.get('total_hosts_scanned', 'N/A')}, "
                      f"Vulnerabilities: {scan.get('total_vulnerabilities_found', 'N/A')}")
            if scan.get('metadata'):
                logger.info(f"  Metadata: {scan['metadata']}")
    else:
        logger.info("No scan sessions found")
    
    # 7. High-Risk Assets
    logger.info("\n=== High-Risk Assets (Criticality >= 4) ===")
    high_risk = client.table('assets_with_context').select(
        'current_hostname, assigned_tags, effective_criticality'
    ).gte('effective_criticality', 4).execute()
    
    if high_risk.data:
        for asset in high_risk.data:
            logger.info(f"• {asset['current_hostname']} - Criticality: {asset['effective_criticality']}")
            logger.info(f"  Tags: {', '.join(asset.get('assigned_tags', []) or ['None'])}")
    else:
        logger.info("No high-risk assets found")

if __name__ == "__main__":
    query_business_context() 