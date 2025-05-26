from etl.extractors.nessus_extractor import NessusExtractor
from etl.transformers.nessus_transformer import NessusTransformer
from etl.loaders.database_loader import DatabaseLoader
from typing import List, Dict, Any
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class NessusETLPipeline:
    def __init__(self, db_connection_string: str):
        self.transformer = NessusTransformer()
        self.loader = DatabaseLoader(db_connection_string)
        self.stats = {
            "files_processed": 0,
            "assets_loaded": 0,
            "vulnerabilities_loaded": 0,
            "errors": []
        }
    
    def process_nessus_file(self, nessus_file_path: str) -> Dict[str, Any]:
        file_stats = {
            "file_path": nessus_file_path,
            "success": False,
            "error": None
        }
        
        try:
            logger.info(f"Processing Nessus file: {nessus_file_path}")
            
            if not os.path.exists(nessus_file_path):
                raise FileNotFoundError(f"Nessus file not found: {nessus_file_path}")
            
            # Extract
            extractor = NessusExtractor(nessus_file_path)
            raw_vulnerabilities = extractor.extract_vulnerabilities()
            raw_assets = extractor.extract_assets()
            
            # Transform
            transformed_vulnerabilities = self.transformer.transform_vulnerabilities(raw_vulnerabilities)
            transformed_assets = self.transformer.transform_assets(raw_assets)
            
            # Load
            assets_loaded = self.loader.load_assets(transformed_assets)
            vulnerabilities_loaded = self.loader.load_vulnerabilities(transformed_vulnerabilities)
            
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
    
    def process_directory(self, directory_path: str) -> Dict[str, Any]:
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
                result = self.process_nessus_file(str(file_path))
                file_results.append(result)
            except Exception:
                file_results.append({"file_path": str(file_path), "success": False})
        
        summary = {
            "total_files": len(nessus_files),
            "successful_files": len([r for r in file_results if r.get("success", False)]),
            "failed_files": len([r for r in file_results if not r.get("success", False)]),
            "total_assets_loaded": self.stats["assets_loaded"],
            "total_vulnerabilities_loaded": self.stats["vulnerabilities_loaded"]
        }
        
        return summary
