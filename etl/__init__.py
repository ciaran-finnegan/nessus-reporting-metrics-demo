"""
ETL (Extract, Transform, Load) package for Nessus vulnerability data processing.

This package provides components for:
- Extracting data from Nessus .nessus XML files
- Transforming data to standardised schemas
- Loading data into databases
- Orchestrating the complete ETL pipeline
"""

__version__ = "1.0.0"
__author__ = "Nessus Reporting Metrics Demo"

# Import main components for easy access
from .extractors.nessus_extractor import NessusExtractor
from .transformers.nessus_transformer import NessusTransformer
from .loaders.database_loader import DatabaseLoader
from .pipeline.nessus_etl_pipeline import NessusETLPipeline

__all__ = [
    "NessusExtractor",
    "NessusTransformer", 
    "DatabaseLoader",
    "NessusETLPipeline"
] 