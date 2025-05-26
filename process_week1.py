#!/usr/bin/env python3
"""Process Week 1 Nessus file through the ETL pipeline."""

import sys
from pathlib import Path

# Add the project root to the path
sys.path.append(str(Path(__file__).parent))

from etl.extractors.nessus_extractor import NessusExtractor
from etl.loaders.supabase_timeseries_loader import SupabaseTimeSeriesLoader

def main():
    print('🚀 Processing Week 1 - Initial Discovery Scan (2024-01-01)')
    print('=' * 60)

    # Initialize loader
    loader = SupabaseTimeSeriesLoader()

    # Test connection
    print('📡 Testing Supabase connection...')
    if not loader.test_connection():
        print('❌ Failed to connect to Supabase')
        return False

    # Process Week 1 file
    file_path = 'data/nessus_reports/sample_files/nessus/nessus_scan_week1.nessus'
    scan_name = 'Week 1 - Initial Discovery Scan (2024-01-01)'

    print(f'🔄 Processing {file_path}...')

    try:
        # Extract
        extractor = NessusExtractor(file_path)
        assets = extractor.extract_assets()
        vulnerabilities = extractor.extract_vulnerabilities()
        print(f'📤 Extracted: {len(assets)} assets, {len(vulnerabilities)} vulnerabilities')

        # Load
        scan_session_id = loader.create_scan_session(
            scan_name=scan_name,
            scan_file_path=file_path,
            metadata={'week': 1, 'description': 'Baseline security assessment - all vulnerabilities present'}
        )
        print(f'📝 Created scan session: {scan_session_id}')

        assets_loaded = loader.load_assets(assets)
        vulns_loaded = loader.load_vulnerabilities(vulnerabilities)
        print(f'💾 Loaded: {assets_loaded} assets, {vulns_loaded} vulnerabilities')

        # Generate metrics
        metrics_snapshot_id = loader.generate_metrics()
        print(f'📊 Generated metrics snapshot: {metrics_snapshot_id}')

        # Update scan session stats
        loader.update_scan_session_stats(
            total_hosts=len(assets),
            total_vulnerabilities=len(vulnerabilities)
        )

        print('✅ Week 1 processing completed successfully!')
        print(f'   Session ID: {scan_session_id}')
        print(f'   Metrics ID: {metrics_snapshot_id}')
        print(f'   Assets: {assets_loaded}')
        print(f'   Vulnerabilities: {vulns_loaded}')
        
        return True

    except Exception as e:
        print(f'❌ Error processing Week 1: {e}')
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 