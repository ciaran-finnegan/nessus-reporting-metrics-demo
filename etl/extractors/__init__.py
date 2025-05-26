"""
Extractors module for ETL pipeline.

Contains extractors for various data sources.
"""

from .nessus_extractor import NessusExtractor

__all__ = ["NessusExtractor"]
