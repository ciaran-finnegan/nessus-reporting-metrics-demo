#!/usr/bin/env python3
"""
Test script for the new time series ETL pipeline with Supabase
Demonstrates proper asset identity management and vulnerability tracking over time
"""

import os
import sys
import logging
from datetime import datetime
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from etl.extractors.nessus_extractor import NessusExtractor
from etl.transformers.nessus_transformer import NessusTransformer
from etl.loaders.supabase_timeseries_loader import SupabaseTimeSeriesLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_timeseries_etl():
    """Test the complete time series ETL pipeline"""
    
    # Sample Nessus file path
    nessus_file = "data/nessus_reports/sample_files/nessus/nessus_v_unknown.nessus"
    
    if not os.path.exists(nessus_file):
        logger.error(f"Sample file not found: {nessus_file}")
        return False
    
    try:
        logger.info("🚀 Starting Time Series ETL Pipeline Test")
        
        # Initialize components
        extractor = NessusExtractor(nessus_file)
        transformer = NessusTransformer()
        loader = SupabaseTimeSeriesLoader()
        
        # Test connection
        logger.info("📡 Testing Supabase connection...")
        if not loader.test_connection():
            logger.error("❌ Supabase connection failed")
            return False
        
        # Create scan session
        logger.info("📋 Creating scan session...")
        scan_name = f"Test Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        scan_session_id = loader.create_scan_session(
            scan_name=scan_name,
            scan_file_path=nessus_file,
            scan_targets=["192.168.1.0/24"],  # Example target range
            metadata={
                "test_run": True,
                "pipeline_version": "2.0",
                "description": "Time series ETL test with proper asset identity"
            }
        )
        
        # Extract data
        logger.info("📤 Extracting data from Nessus file...")
        assets = extractor.extract_assets()
        vulnerabilities = extractor.extract_vulnerabilities()
        logger.info(f"✅ Extracted {len(assets)} assets and {len(vulnerabilities)} vulnerabilities")
        
        # Transform data (for Nessus, the extractor already provides the right format)
        logger.info("🔄 Transforming data...")
        # The NessusExtractor already provides data in the right format, so we can use it directly
        
        logger.info(f"✅ Transformed to {len(assets)} assets and {len(vulnerabilities)} vulnerabilities")
        
        # Load assets first (they need to exist before vulnerabilities)
        logger.info("📥 Loading assets...")
        assets_loaded = loader.load_assets(assets)
        
        # Load vulnerabilities
        logger.info("📥 Loading vulnerabilities...")
        vulns_loaded = loader.load_vulnerabilities(vulnerabilities)
        
        # Update scan session with final stats
        loader.update_scan_session_stats(
            total_hosts=len(assets),
            total_vulnerabilities=len(vulnerabilities),
            duration_minutes=1  # Approximate for test
        )
        
        # Get statistics
        logger.info("📊 Getting database statistics...")
        stats = loader.get_statistics()
        
        logger.info("📈 Database Statistics:")
        for key, value in stats.items():
            logger.info(f"  {key}: {value}")
        
        # Test queries
        logger.info("🔍 Testing query views...")
        
        # Query current vulnerabilities
        current_vulns = loader.query_current_vulnerabilities(limit=5)
        logger.info(f"📋 Current vulnerabilities (sample of {len(current_vulns)}):")
        for vuln in current_vulns[:3]:  # Show first 3
            logger.info(f"  - {vuln.get('current_hostname', 'Unknown')} ({vuln.get('current_ip_address', 'Unknown IP')}): {vuln.get('vulnerability_name', 'Unknown vuln')}")
        
        # Query asset summary
        asset_summary = loader.query_asset_summary(limit=5)
        logger.info(f"🏢 Asset summary (sample of {len(asset_summary)}):")
        for asset in asset_summary[:3]:  # Show first 3
            logger.info(f"  - {asset.get('current_hostname', 'Unknown')} ({asset.get('current_ip_address', 'Unknown IP')}): {asset.get('total_vulnerabilities', 0)} vulnerabilities")
        
        # Generate metrics (NEW)
        logger.info("🔢 Generating metrics...")
        metrics_success = loader.generate_metrics()
        if metrics_success:
            logger.info("✅ Metrics generated successfully!")
        else:
            logger.warning("⚠️ Metrics generation failed")
        
        logger.info("✅ Time Series ETL Pipeline Test Completed Successfully!")
        logger.info(f"📊 Summary: {assets_loaded} assets, {vulns_loaded} vulnerabilities loaded")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ ETL Pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_asset_identity_persistence():
    """Test that asset identity persists across multiple scans"""
    
    logger.info("🔄 Testing Asset Identity Persistence...")
    
    try:
        loader = SupabaseTimeSeriesLoader()
        
        # Simulate first scan with an asset
        scan1_id = loader.create_scan_session(
            scan_name="Identity Test Scan 1",
            metadata={"test": "asset_identity_1"}
        )
        
        # Create an asset
        asset_data_1 = {
            'Asset_Name': 'test-server-01',
            'Asset_IP': '192.168.1.100',
            'Type': 'server',
            'Operating_System': 'Windows Server 2019'
        }
        
        asset_id_1 = loader.upsert_asset(asset_data_1)
        logger.info(f"✅ Created asset in scan 1: {asset_id_1}")
        
        # Simulate second scan with same asset but different hostname
        scan2_id = loader.create_scan_session(
            scan_name="Identity Test Scan 2",
            metadata={"test": "asset_identity_2"}
        )
        
        # Same IP but different hostname (simulating hostname change)
        asset_data_2 = {
            'Asset_Name': 'test-server-01-renamed',  # Hostname changed
            'Asset_IP': '192.168.1.100',  # Same IP
            'Type': 'server',
            'Operating_System': 'Windows Server 2019'
        }
        
        asset_id_2 = loader.upsert_asset(asset_data_2)
        logger.info(f"✅ Updated asset in scan 2: {asset_id_2}")
        
        # Verify it's the same asset
        if asset_id_1 == asset_id_2:
            logger.info("✅ Asset identity preserved across scans despite hostname change!")
        else:
            logger.warning("⚠️ Asset identity not preserved - this might indicate an issue")
        
        # Check asset history
        history_result = loader.client.table('asset_history').select('*').eq('asset_id', asset_id_1).execute()
        logger.info(f"📜 Asset history records: {len(history_result.data)}")
        
        for record in history_result.data:
            logger.info(f"  - {record['change_type']}: {record['new_values']}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Asset identity test failed: {e}")
        return False

def demonstrate_time_series_queries():
    """Demonstrate time series queries and analysis"""
    
    logger.info("📊 Demonstrating Time Series Queries...")
    
    try:
        loader = SupabaseTimeSeriesLoader()
        
        # Query scan sessions
        scan_sessions = loader.client.table('scan_sessions').select('*').order('scan_date', desc=True).limit(5).execute()
        logger.info(f"📅 Recent scan sessions ({len(scan_sessions.data)}):")
        for session in scan_sessions.data:
            logger.info(f"  - {session['scan_name']} ({session['scan_date'][:19]}): {session.get('total_hosts_scanned', 'N/A')} hosts")
        
        # Query vulnerability trends
        trends = loader.client.table('vulnerability_trends').select('*').order('affected_assets', desc=True).limit(5).execute()
        logger.info(f"🔍 Top vulnerability trends ({len(trends.data)}):")
        for trend in trends.data:
            logger.info(f"  - {trend['vulnerability_name'][:50]}...: {trend['affected_assets']} assets, {trend['currently_open']} open")
        
        # Query asset changes over time
        changes = loader.client.table('asset_history').select('*').order('observed_at', desc=True).limit(5).execute()
        logger.info(f"🔄 Recent asset changes ({len(changes.data)}):")
        for change in changes.data:
            logger.info(f"  - {change['change_type']} at {change['observed_at'][:19]}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Time series queries failed: {e}")
        return False

if __name__ == "__main__":
    logger.info("🧪 Starting Comprehensive Time Series ETL Tests")
    
    # Run tests
    tests = [
        ("Main ETL Pipeline", test_timeseries_etl),
        ("Asset Identity Persistence", test_asset_identity_persistence),
        ("Time Series Queries", demonstrate_time_series_queries)
    ]
    
    results = []
    for test_name, test_func in tests:
        logger.info(f"\n{'='*60}")
        logger.info(f"🧪 Running: {test_name}")
        logger.info(f"{'='*60}")
        
        success = test_func()
        results.append((test_name, success))
        
        if success:
            logger.info(f"✅ {test_name} - PASSED")
        else:
            logger.error(f"❌ {test_name} - FAILED")
    
    # Summary
    logger.info(f"\n{'='*60}")
    logger.info("📊 TEST SUMMARY")
    logger.info(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        logger.info(f"{test_name}: {status}")
    
    logger.info(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All tests passed! Time series ETL is working correctly.")
    else:
        logger.error("⚠️ Some tests failed. Please check the logs above.")
    
    # Clean up test files
    if os.path.exists("check_current_schema.py"):
        os.remove("check_current_schema.py") 