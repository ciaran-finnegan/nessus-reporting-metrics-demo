#!/usr/bin/env python3
"""
Enhanced ETL Pipeline Runner with Metrics Generation
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from etl.pipeline.enhanced_nessus_etl_pipeline import EnhancedNessusETLPipeline

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main pipeline execution"""
    
    logger.info("🚀 Starting Enhanced ETL Pipeline with Metrics Generation")
    
    try:
        # Initialize pipeline
        pipeline = EnhancedNessusETLPipeline()
        
        # Test connection
        if not pipeline.loader.test_connection():
            logger.error("❌ Database connection failed")
            return False
        
        # Process sample file (you can change this path)
        sample_file = "data/nessus_reports/sample_files/nessus/nessus_v_unknown.nessus"
        
        if os.path.exists(sample_file):
            logger.info(f"📁 Processing sample file: {sample_file}")
            result = pipeline.process_nessus_file(sample_file, generate_metrics=True)
            
            if result["success"]:
                logger.info("✅ Pipeline completed successfully!")
                logger.info(f"📊 Assets loaded: {pipeline.stats['assets_loaded']}")
                logger.info(f"📊 Vulnerabilities loaded: {pipeline.stats['vulnerabilities_loaded']}")
                logger.info(f"📊 Metrics generated: {pipeline.stats['metrics_generated']}")
            else:
                logger.error(f"❌ Pipeline failed: {result.get('error', 'Unknown error')}")
                
        else:
            logger.warning(f"Sample file not found: {sample_file}")
            logger.info("You can also process a directory:")
            logger.info("python run_enhanced_pipeline.py --directory /path/to/nessus/files")
            
            # Or just generate metrics from existing data
            logger.info("🔢 Generating metrics from existing data...")
            success = pipeline.generate_metrics_only()
            if success:
                logger.info("✅ Metrics generated successfully!")
            else:
                logger.error("❌ Metrics generation failed")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Pipeline execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced ETL Pipeline with Metrics")
    parser.add_argument("--directory", "-d", help="Directory containing .nessus files")
    parser.add_argument("--file", "-f", help="Single .nessus file to process")
    parser.add_argument("--metrics-only", action="store_true", help="Only generate metrics from existing data")
    
    args = parser.parse_args()
    
    if args.metrics_only:
        logger.info("🔢 Running metrics generation only...")
        pipeline = EnhancedNessusETLPipeline()
        success = pipeline.generate_metrics_only()
        sys.exit(0 if success else 1)
    elif args.directory:
        logger.info(f"📁 Processing directory: {args.directory}")
        pipeline = EnhancedNessusETLPipeline()
        result = pipeline.process_directory(args.directory)
        logger.info(f"📊 Summary: {result}")
        sys.exit(0 if result['successful_files'] > 0 else 1)
    elif args.file:
        logger.info(f"📄 Processing file: {args.file}")
        pipeline = EnhancedNessusETLPipeline()
        result = pipeline.process_nessus_file(args.file)
        sys.exit(0 if result['success'] else 1)
    else:
        main()