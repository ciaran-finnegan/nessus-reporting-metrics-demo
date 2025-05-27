from etl.extractors.nessus_extractor import NessusExtractor
from etl.transformers.nessus_transformer import NessusTransformer
from etl.loaders.supabase_timeseries_loader import SupabaseTimeSeriesLoader
from etl.metrics.mttr_calculator import MTTRCalculator
from etl.metrics.metrics_generator import MetricsGenerator
from etl.metrics.reporting_tables import ReportingTablesManager
from etl.metrics.remediation_status_resolver import resolve_remediation_status
from typing import List, Dict, Any
import logging
import os
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class EnhancedNessusETLPipeline:
    """
    Enhanced ETL Pipeline that includes metrics generation
    """
    
    def __init__(self):
        self.transformer = NessusTransformer()
        self.loader = SupabaseTimeSeriesLoader()
        self.mttr_calculator = MTTRCalculator(self.loader.client)
        self.metrics_generator = MetricsGenerator(self.loader.client)
        self.reporting_manager = ReportingTablesManager(self.loader.client)
        
        self.stats = {
            "files_processed": 0,
            "assets_loaded": 0,
            "vulnerabilities_loaded": 0,
            "metrics_generated": False,
            "errors": []
        }
    
    def process_nessus_file(self, nessus_file_path: str, generate_metrics: bool = True) -> Dict[str, Any]:
        """
        Process a single Nessus file, load data, and optionally generate metrics.
        This now includes a remediation status resolution step that must run before metrics.
        
        Args:
            nessus_file_path: Path to the .nessus file
            generate_metrics: Whether to generate metrics after loading data
            
        Returns:
            Dictionary with processing results
        """
        file_stats = {
            "file_path": nessus_file_path,
            "success": False,
            "error": None,
            "metrics_generated": False,
            "assets_loaded": 0,
            "vulnerabilities_loaded": 0,
        }
        
        try:
            logger.info(f"Processing Nessus file: {nessus_file_path}")
            
            if not os.path.exists(nessus_file_path):
                raise FileNotFoundError(f"Nessus file not found: {nessus_file_path}")
            
            # Create scan session
            scan_name = f"Nessus Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            scan_session_id = self.loader.create_scan_session(
                scan_name=scan_name,
                scan_file_path=nessus_file_path,
                metadata={
                    "pipeline_version": "2.1",
                    "metrics_enabled": generate_metrics
                }
            )
            
            # Extract
            extractor = NessusExtractor(nessus_file_path)
            raw_vulnerabilities = extractor.extract_vulnerabilities()
            raw_assets = extractor.extract_assets()
            
            # Transform
            transformed_vulnerabilities = self.transformer.transform_vulnerabilities(raw_vulnerabilities)
            transformed_assets = self.transformer.transform_assets(raw_assets)
            
            # 1. Resolve remediation status FIRST
            vulnerabilities = resolve_remediation_status(transformed_vulnerabilities, raw_vulnerabilities)
            
            # Load
            assets_loaded = self.loader.load_assets(transformed_assets)
            vulnerabilities_loaded = self.loader.load_vulnerabilities(vulnerabilities)
            
            # Update scan session stats
            self.loader.update_scan_session_stats(
                total_hosts=len(transformed_assets),
                total_vulnerabilities=len(vulnerabilities)
            )
            
            # Generate metrics if requested
            if generate_metrics:
                logger.info("🔢 Generating metrics...")
                metrics_success = self._generate_metrics()
                file_stats["metrics_generated"] = metrics_success
                self.stats["metrics_generated"] = metrics_success
            
            file_stats["success"] = True
            self.stats["files_processed"] += 1
            self.stats["assets_loaded"] += assets_loaded
            self.stats["vulnerabilities_loaded"] += vulnerabilities_loaded
            
            logger.info(f"Successfully processed {nessus_file_path}")
            
        except Exception as e:
            error_msg = f"Error processing {nessus_file_path}: {str(e)}"
            logger.error(error_msg)
            file_stats["error"] = error_msg
            self.stats["errors"].append(error_msg)
            raise
        
        return file_stats
    
    def _generate_metrics(self) -> bool:
        """
        Generate all metrics and store them in reporting tables
        
        Returns:
            True if metrics generation was successful
        """
        try:
            logger.info("📊 Calculating MTTR metrics...")
            
            # Calculate MTTR metrics
            mttr_overall = self.mttr_calculator.calculate_overall_mttr()
            mttr_by_risk = self.mttr_calculator.calculate_mttr_by_risk_level()
            mttr_by_group = self.mttr_calculator.calculate_mttr_by_business_group()
            mttr_by_type = self.mttr_calculator.calculate_mttr_by_asset_type()
            
            logger.info("📈 Generating comprehensive metrics...")
            
            # Generate comprehensive metrics
            metrics = self.metrics_generator.generate_comprehensive_metrics()
            
            logger.info("💾 Storing metrics in reporting tables...")
            
            # Store metrics snapshot
            snapshot_id = self.reporting_manager.store_metrics_snapshot(metrics)
            
            # Update MTTR history
            if mttr_overall is not None:
                self.reporting_manager.update_mttr_history(
                    mttr_days=mttr_overall,
                    mttr_by_risk_level=mttr_by_risk,
                    mttr_by_business_group=mttr_by_group,
                    mttr_by_asset_type=mttr_by_type
                )
            
            logger.info(f"✅ Metrics generated successfully (snapshot: {snapshot_id})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to generate metrics: {e}")
            return False
    
    def process_directory(self, directory_path: str, generate_metrics: bool = True) -> Dict[str, Any]:
        """
        Process all .nessus files in a directory
        
        Args:
            directory_path: Path to directory containing .nessus files
            generate_metrics: Whether to generate metrics after processing all files
            
        Returns:
            Summary of processing results
        """
        directory = Path(directory_path)
        
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        nessus_files = list(directory.glob("*.nessus"))
        
        if not nessus_files:
            logger.warning(f"No .nessus files found in {directory_path}")
            return {"total_files": 0, "successful_files": 0, "failed_files": 0}
        
        file_results = []
        for file_path in nessus_files:
            try:
                # Process each file but only generate metrics after the last one
                is_last_file = file_path == nessus_files[-1]
                result = self.process_nessus_file(
                    str(file_path), 
                    generate_metrics=(generate_metrics and is_last_file)
                )
                file_results.append(result)
            except Exception:
                file_results.append({"file_path": str(file_path), "success": False})
        
        summary = {
            "total_files": len(nessus_files),
            "successful_files": len([r for r in file_results if r.get("success", False)]),
            "failed_files": len([r for r in file_results if not r.get("success", False)]),
            "total_assets_loaded": self.stats["assets_loaded"],
            "total_vulnerabilities_loaded": self.stats["vulnerabilities_loaded"],
            "metrics_generated": self.stats["metrics_generated"]
        }
        
        return summary
    
    def generate_metrics_only(self) -> bool:
        """
        Generate metrics without processing new data
        Useful for updating metrics based on existing data
        
        Returns:
            True if successful
        """
        logger.info("🔢 Generating metrics from existing data...")
        return self._generate_metrics()