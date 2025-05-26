#!/usr/bin/env python3
"""
Test Business Context Integration with Nessus Data

This script demonstrates:
1. Loading Nessus data with time series support
2. Creating Business Groups hierarchy
3. Creating and applying Asset Tags (static and dynamic)
4. Querying data with business context
5. Generating business-aligned reports
"""

import os
import sys
from datetime import datetime
import yaml
import logging
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from etl.extractors import NessusExtractor
from etl.transformers import NessusTransformer
from etl.loaders import SupabaseTimeSeriesLoader, BusinessContextManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def test_complete_workflow():
    """Test the complete Business Context workflow"""
    
    # 1. Initialize components
    logger.info("=== Initializing ETL Components ===")
    
    # Find sample Nessus file
    sample_file = "data/nessus_reports/sample_files/nessus/nessus_v_unknown.nessus"
    if not os.path.exists(sample_file):
        logger.error(f"Sample file not found: {sample_file}")
        return
    
    # Initialize ETL components
    extractor = NessusExtractor(sample_file)
    transformer = NessusTransformer()
    loader = SupabaseTimeSeriesLoader()
    context_manager = BusinessContextManager(loader.client)
    
    # Test connection
    if not loader.test_connection():
        logger.error("Failed to connect to Supabase")
        return
    
    logger.info("✅ Successfully connected to Supabase")
    
    # 2. Create Business Groups Structure
    logger.info("\n=== Creating Business Groups ===")
    
    try:
        # Create root groups
        geographic_id = context_manager.create_business_group(
            name="Geographic Regions",
            description="Assets organized by geographic location"
        )
        
        departments_id = context_manager.create_business_group(
            name="Departments",
            description="Assets organized by department"
        )
        
        environments_id = context_manager.create_business_group(
            name="Environments",
            description="Assets organized by environment type"
        )
        
        # Create some child groups
        qa_env_id = context_manager.create_business_group(
            name="QA Environment",
            parent_id=environments_id,
            description="Quality Assurance testing environment"
        )
        
        it_dept_id = context_manager.create_business_group(
            name="IT Infrastructure",
            parent_id=departments_id,
            description="IT infrastructure and operations"
        )
        
        logger.info("✅ Created business group hierarchy")
        
    except Exception as e:
        logger.warning(f"Business groups might already exist: {e}")
    
    # 3. Create Asset Tags
    logger.info("\n=== Creating Asset Tags ===")
    
    try:
        # Static tags
        qa_tag_id = context_manager.create_tag(
            name="#qa-environment",
            tag_type="manual",
            description="QA testing environment assets",
            criticality_score=2,
            color="#3498db"
        )
        
        # Dynamic tags
        context_manager.create_tag(
            name="#high-vulnerabilities",
            tag_type="dynamic",
            description="Assets with high severity vulnerabilities",
            criticality_score=4,
            color="#ff9800",
            rule_definition={
                "type": "vulnerability_exists",
                "severity": ["High"]
            }
        )
        
        context_manager.create_tag(
            name="#qa-servers",
            tag_type="dynamic",
            description="QA application servers",
            rule_definition={
                "type": "asset_name_contains",
                "patterns": ["qa*app*"]
            }
        )
        
        context_manager.create_tag(
            name="#windows-systems",
            tag_type="dynamic",
            description="Windows-based systems",
            rule_definition={
                "type": "operating_system",
                "os_patterns": ["*Windows*", "*Microsoft*"]
            }
        )
        
        logger.info("✅ Created asset tags")
        
    except Exception as e:
        logger.warning(f"Tags might already exist: {e}")
    
    # 4. Load Nessus Data
    logger.info("\n=== Loading Nessus Data ===")
    
    # Extract data
    logger.info("Extracting data from Nessus file...")
    assets = extractor.extract_assets()
    vulnerabilities = extractor.extract_vulnerabilities()
    
    logger.info(f"Extracted {len(assets)} assets and {len(vulnerabilities)} vulnerabilities")
    
    # Transform data
    logger.info("Transforming data...")
    transformed_assets = transformer.transform_assets(assets)
    transformed_vulns = transformer.transform_vulnerabilities(vulnerabilities)
    
    # Create scan session
    scan_session_id = loader.create_scan_session(
        scan_name="Business Context Test Scan",
        scan_file_path=sample_file,
        metadata={
            "test_type": "business_context_integration",
            "environment": "qa"
        }
    )
    
    # Load with business context
    logger.info("Loading data with business context...")
    
    # First, let's add the QA environment tag to our assets before loading
    # This simulates tags coming from the scanner
    for asset in transformed_assets:
        asset['tags'] = ['qa-environment']
    
    result = loader.load_with_business_context(
        assets=transformed_assets,
        vulnerabilities=transformed_vulns,
        apply_dynamic_tags=True
    )
    
    logger.info(f"✅ Loaded {result['assets_loaded']} assets and {result['vulnerabilities_loaded']} vulnerabilities")
    
    # Update scan session stats
    loader.update_scan_session_stats(
        total_hosts=len(assets),
        total_vulnerabilities=len(vulnerabilities)
    )
    
    # 5. Assign Assets to Business Groups
    logger.info("\n=== Assigning Assets to Business Groups ===")
    
    # Get QA assets
    qa_assets_result = loader.client.table('assets').select('id, current_hostname').ilike(
        'current_hostname', 'qa%'
    ).execute()
    
    if qa_assets_result.data:
        qa_asset_ids = [asset['id'] for asset in qa_assets_result.data]
        
        # Assign to QA Environment business group
        count = context_manager.assign_assets_to_business_group(
            asset_ids=qa_asset_ids,
            business_group_id=qa_env_id,
            assigned_by="test_script"
        )
        
        logger.info(f"✅ Assigned {count} QA assets to QA Environment business group")
        
        # Also assign to IT Infrastructure
        context_manager.assign_assets_to_business_group(
            asset_ids=qa_asset_ids,
            business_group_id=it_dept_id,
            assigned_by="test_script"
        )
    
    # 6. Query and Display Results
    logger.info("\n=== Querying Business Context Data ===")
    
    # Query assets with context
    logger.info("\n📊 Assets with Business Context:")
    assets_with_context = loader.client.table('assets_with_context').select(
        'asset_fingerprint, current_hostname, assigned_business_groups, assigned_tags, effective_criticality'
    ).limit(10).execute()
    
    for asset in assets_with_context.data:
        logger.info(f"  • {asset['current_hostname']}:")
        logger.info(f"    - Business Groups: {asset.get('assigned_business_groups', [])}")
        logger.info(f"    - Tags: {asset.get('assigned_tags', [])}")
        logger.info(f"    - Criticality: {asset.get('effective_criticality', 'N/A')}")
    
    # Query vulnerability summary by business group
    logger.info("\n📊 Vulnerability Summary by Business Group:")
    vuln_summary = loader.client.table('vulnerability_summary_by_business_group').select('*').execute()
    
    for group in vuln_summary.data:
        if group['total_assets'] > 0:
            logger.info(f"  • {group['business_group_name']}:")
            logger.info(f"    - Total Assets: {group['total_assets']}")
            logger.info(f"    - Critical: {group['critical_vulns']}, High: {group['high_vulns']}")
            logger.info(f"    - Risk Score: {group.get('risk_score', 0)}")
    
    # Query assets by tag
    logger.info("\n📊 Assets by Tag:")
    
    # Get tag assignments
    tag_stats = loader.client.table('asset_tags').select(
        'id, name, tag_type'
    ).execute()
    
    for tag in tag_stats.data:
        # Count assignments for this tag
        assignments = loader.client.table('asset_tag_assignments').select(
            'asset_id', count='exact'
        ).eq('tag_id', tag['id']).execute()
        
        count = assignments.count if hasattr(assignments, 'count') else 0
        if count > 0:
            logger.info(f"  • {tag['name']} ({tag['tag_type']}): {count} assets")
    
    # 7. Test Dynamic Rules with Business Rules Configuration
    logger.info("\n=== Testing Business Rules Configuration ===")
    
    # Load business rules if available
    business_rules_file = "config/business_rules.yaml"
    if os.path.exists(business_rules_file):
        with open(business_rules_file, 'r') as f:
            business_rules = yaml.safe_load(f)
        
        logger.info("Loaded business rules configuration")
        
        # You could process another scan with these rules
        # loader.load_with_business_context(assets, vulns, business_rules=business_rules)
    
    # 8. Generate Summary Statistics
    logger.info("\n=== Summary Statistics ===")
    
    stats = loader.get_statistics()
    logger.info(f"  • Scan Sessions: {stats.get('scan_sessions', 0)}")
    logger.info(f"  • Total Assets: {stats.get('total_assets', 0)}")
    logger.info(f"  • Active Assets: {stats.get('active_assets', 0)}")
    logger.info(f"  • Vulnerability Definitions: {stats.get('vulnerability_definitions', 0)}")
    logger.info(f"  • Vulnerability Scans: {stats.get('vulnerability_scans', 0)}")
    logger.info(f"  • Open Vulnerabilities: {stats.get('open_vulnerabilities', 0)}")
    
    logger.info("\n✅ Business Context Integration Test Complete!")

if __name__ == "__main__":
    test_complete_workflow() 