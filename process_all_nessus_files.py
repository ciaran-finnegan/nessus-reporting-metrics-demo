#!/usr/bin/env python3
"""
Process all Nessus file variations through the ETL pipeline to build comprehensive time series data.
This will demonstrate vulnerability management progression over the 5-week period.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime

# Add the project root to the path
sys.path.append(str(Path(__file__).parent))

from etl.extractors.nessus_extractor import NessusExtractor
from etl.transformers.nessus_transformer import NessusTransformer
from etl.loaders.supabase_timeseries_loader import SupabaseTimeSeriesLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def process_nessus_file(file_path: Path, scan_name: str, loader: SupabaseTimeSeriesLoader):
    """Process a single Nessus file through the ETL pipeline."""
    
    logger.info(f"🔄 Processing {file_path.name}...")
    
    try:
        # Extract
        extractor = NessusExtractor(str(file_path))
        assets = extractor.extract_assets()
        vulnerabilities = extractor.extract_vulnerabilities()
        logger.info(f"  📤 Extracted: {len(assets)} assets, {len(vulnerabilities)} vulnerabilities")
        
        # Transform (NessusExtractor already provides data in the right format)
        # No transformation needed - NessusExtractor output is already in the correct format
        transformed_assets = assets
        transformed_vulnerabilities = vulnerabilities
        logger.info(f"  🔄 Using extracted data directly: {len(transformed_assets)} assets, {len(transformed_vulnerabilities)} vulnerabilities")
        
        # Load
        scan_session_id = loader.create_scan_session(
            scan_name=scan_name,
            scan_file_path=str(file_path),
            metadata={"week_progression": True}
        )
        loader.load_assets(transformed_assets)
        loader.load_vulnerabilities(transformed_vulnerabilities)
        
        # Generate metrics
        metrics_snapshot_id = loader.generate_metrics()
        
        logger.info(f"  ✅ Completed: Session {scan_session_id}, Metrics {metrics_snapshot_id}")
        return scan_session_id, metrics_snapshot_id
        
    except Exception as e:
        logger.error(f"  ❌ Failed to process {file_path.name}: {e}")
        return None, None

def main():
    """Process all Nessus files in chronological order."""
    
    logger.info("🚀 Starting Comprehensive Nessus File Processing")
    logger.info("=" * 60)
    
    # Initialize loader
    loader = SupabaseTimeSeriesLoader()
    
    # Test connection
    logger.info("📡 Testing Supabase connection...")
    if not loader.test_connection():
        logger.error("❌ Failed to connect to Supabase")
        return
    
    # Define files to process in chronological order
    nessus_dir = Path("data/nessus_reports/sample_files/nessus")
    files_to_process = [
        {
            "file": "nessus_scan_week1.nessus",
            "scan_name": "Week 1 - Initial Discovery Scan (2024-01-01)",
            "description": "Baseline security assessment - all vulnerabilities present"
        },
        {
            "file": "nessus_scan_week2.nessus", 
            "scan_name": "Week 2 - Remediation + New Critical (2024-01-08)",
            "description": "Fixed RDP issues, discovered SSL certificate expiry"
        },
        {
            "file": "nessus_scan_week3.nessus",
            "scan_name": "Week 3 - Critical Fixed + SSH Issue (2024-01-15)", 
            "description": "SSL certificate renewed, SSH encryption weakness found"
        },
        {
            "file": "nessus_scan_week4.nessus",
            "scan_name": "Week 4 - SSH Fixed + HTTP Headers (2024-01-22)",
            "description": "SSH encryption improved, HTTP security headers missing"
        },
        {
            "file": "nessus_scan_week5.nessus",
            "scan_name": "Week 5 - Major Cleanup Complete (2024-01-29)",
            "description": "Most issues resolved, only RDP MITM remains"
        }
    ]
    
    # Process each file
    results = []
    for i, file_info in enumerate(files_to_process, 1):
        file_path = nessus_dir / file_info["file"]
        
        if not file_path.exists():
            logger.error(f"❌ File not found: {file_path}")
            continue
            
        logger.info(f"\n📅 Week {i}: {file_info['description']}")
        logger.info(f"📁 File: {file_info['file']}")
        
        session_id, metrics_id = process_nessus_file(
            file_path, 
            file_info["scan_name"], 
            loader
        )
        
        results.append({
            "week": i,
            "file": file_info["file"],
            "scan_name": file_info["scan_name"],
            "session_id": session_id,
            "metrics_id": metrics_id,
            "success": session_id is not None
        })
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("📊 PROCESSING SUMMARY")
    logger.info("=" * 60)
    
    successful = sum(1 for r in results if r["success"])
    total = len(results)
    
    logger.info(f"✅ Successfully processed: {successful}/{total} files")
    
    for result in results:
        status = "✅" if result["success"] else "❌"
        logger.info(f"  {status} Week {result['week']}: {result['file']}")
    
    if successful == total:
        logger.info("\n🎉 All files processed successfully!")
        logger.info("📈 Time series data is now available for comprehensive analysis")
        logger.info("\nNext steps:")
        logger.info("  - View vulnerability trends in your dashboard")
        logger.info("  - Analyze MTTR patterns across the 5-week period")
        logger.info("  - Compare remediation effectiveness by severity")
        logger.info("  - Generate executive reports on security improvement")
    else:
        logger.warning(f"\n⚠️ {total - successful} files failed to process")
        logger.info("Check the logs above for specific error details")

if __name__ == "__main__":
    main() 