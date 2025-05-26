#!/usr/bin/env python3
"""
Test script for the Nessus ETL pipeline using sample files
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def setup_logging():
    """Set up logging for the test"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('test_pipeline.log')
        ]
    )

def find_nessus_files():
    """Find all .nessus files in the sample_files directory"""
    sample_dir = project_root / "sample_files" / "nessus"
    nessus_files = list(sample_dir.glob("*.nessus"))
    return nessus_files

def test_pipeline():
    """Test the ETL pipeline with sample Nessus files"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Nessus ETL Pipeline Test")
    
    # Find sample files
    nessus_files = find_nessus_files()
    
    if not nessus_files:
        logger.error("No .nessus files found in sample_files/nessus directory")
        return False
    
    logger.info(f"Found {len(nessus_files)} .nessus files:")
    for file in nessus_files:
        logger.info(f"  - {file.name} ({file.stat().st_size / 1024:.1f} KB)")
    
    # Test each file
    success_count = 0
    for nessus_file in nessus_files:
        logger.info(f"\n{'='*60}")
        logger.info(f"Testing file: {nessus_file.name}")
        logger.info(f"{'='*60}")
        
        try:
            # Here we would normally import and run the ETL pipeline
            # For now, let's just validate the file structure
            
            # Basic XML validation
            import xml.etree.ElementTree as ET
            
            logger.info("Parsing XML structure...")
            tree = ET.parse(nessus_file)
            root = tree.getroot()
            
            logger.info(f"Root element: {root.tag}")
            
            # Count key elements
            policies = root.findall('.//Policy')
            reports = root.findall('.//Report')
            hosts = root.findall('.//ReportHost')
            items = root.findall('.//ReportItem')
            
            logger.info(f"Found {len(policies)} policies")
            logger.info(f"Found {len(reports)} reports")
            logger.info(f"Found {len(hosts)} hosts")
            logger.info(f"Found {len(items)} vulnerability items")
            
            # Sample host information
            if hosts:
                first_host = hosts[0]
                host_name = first_host.get('name', 'Unknown')
                logger.info(f"First host: {host_name}")
                
                # Count vulnerabilities for first host
                host_items = first_host.findall('.//ReportItem')
                logger.info(f"Vulnerabilities for {host_name}: {len(host_items)}")
                
                if host_items:
                    # Sample vulnerability
                    first_vuln = host_items[0]
                    plugin_id = first_vuln.get('pluginID', 'Unknown')
                    plugin_name = first_vuln.get('pluginName', 'Unknown')
                    severity = first_vuln.get('severity', 'Unknown')
                    logger.info(f"Sample vulnerability: {plugin_name} (ID: {plugin_id}, Severity: {severity})")
            
            logger.info(f"✅ Successfully processed {nessus_file.name}")
            success_count += 1
            
        except ET.ParseError as e:
            logger.error(f"❌ XML parsing error in {nessus_file.name}: {e}")
        except Exception as e:
            logger.error(f"❌ Error processing {nessus_file.name}: {e}")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Test Summary: {success_count}/{len(nessus_files)} files processed successfully")
    logger.info(f"{'='*60}")
    
    return success_count == len(nessus_files)

if __name__ == "__main__":
    success = test_pipeline()
    sys.exit(0 if success else 1) 