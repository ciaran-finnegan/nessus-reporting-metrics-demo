import os
import sys
import pytest
import logging
from pathlib import Path
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from etl.extractors.nessus_extractor import NessusExtractor
from etl.transformers.nessus_transformer import NessusTransformer
from etl.pipeline.nessus_etl_pipeline import NessusETLPipeline

class TestNessusExtractor:
    """Test the Nessus extractor component"""
    
    @pytest.fixture
    def sample_nessus_file(self):
        """Get the path to the sample .nessus file"""
        sample_dir = project_root / "data" / "nessus_reports" / "sample_files" / "nessus"
        nessus_files = list(sample_dir.glob("*.nessus"))
        if not nessus_files:
            pytest.skip("No .nessus files found in data/nessus_reports/sample_files/nessus directory")
        return str(nessus_files[0])
    
    def test_nessus_file_parsing(self, sample_nessus_file):
        """Test that the Nessus file can be parsed correctly"""
        extractor = NessusExtractor(sample_nessus_file)
        
        # Check that the XML is parsed correctly
        assert extractor.root is not None
        assert extractor.root.tag == "NessusClientData_v2"
    
    def test_extract_vulnerabilities(self, sample_nessus_file):
        """Test vulnerability extraction from Nessus file"""
        extractor = NessusExtractor(sample_nessus_file)
        vulnerabilities = extractor.extract_vulnerabilities()
        
        # Should extract some vulnerabilities
        assert isinstance(vulnerabilities, list)
        assert len(vulnerabilities) > 0
        
        # Check structure of first vulnerability
        first_vuln = vulnerabilities[0]
        required_fields = ["Asset_Name", "IP", "Vulnerability_Name", "Severity", "Scanner"]
        for field in required_fields:
            assert field in first_vuln
        
        # Check that severity is not "0" (informational)
        assert first_vuln["Severity"] != "0"
        assert first_vuln["Scanner"] == "Nessus"
    
    def test_extract_assets(self, sample_nessus_file):
        """Test asset extraction from Nessus file"""
        extractor = NessusExtractor(sample_nessus_file)
        assets = extractor.extract_assets()
        
        # Should extract some assets
        assert isinstance(assets, list)
        assert len(assets) > 0
        
        # Check structure of first asset
        first_asset = assets[0]
        required_fields = ["Asset_Name", "Asset_IP", "Type"]
        for field in required_fields:
            assert field in first_asset
        
        assert first_asset["Type"] == "Host"

class TestNessusTransformer:
    """Test the Nessus transformer component"""
    
    @pytest.fixture
    def sample_vulnerability_data(self):
        """Sample vulnerability data for testing"""
        return [{
            "Asset_Name": "test-host",
            "IP": "192.168.1.100",
            "Vulnerability_Name": "Test Vulnerability",
            "CVSS_Score": 7.5,
            "Severity": "3",
            "Scanner": "Nessus"
        }]
    
    @pytest.fixture
    def sample_asset_data(self):
        """Sample asset data for testing"""
        return [{
            "Asset_Name": "test-host",
            "Asset_IP": "192.168.1.100",
            "Type": "Host"
        }]
    
    def test_transform_vulnerabilities(self, sample_vulnerability_data):
        """Test vulnerability transformation"""
        transformer = NessusTransformer()
        transformed = transformer.transform_vulnerabilities(sample_vulnerability_data)
        
        assert isinstance(transformed, list)
        assert len(transformed) == 1
        
        # Check that transformation preserves required fields
        transformed_vuln = transformed[0]
        assert "Asset_Name" in transformed_vuln
        assert "Vulnerability_Name" in transformed_vuln
    
    def test_transform_assets(self, sample_asset_data):
        """Test asset transformation"""
        transformer = NessusTransformer()
        transformed = transformer.transform_assets(sample_asset_data)
        
        assert isinstance(transformed, list)
        assert len(transformed) == 1
        
        # Check that transformation preserves required fields
        transformed_asset = transformed[0]
        assert "Asset_Name" in transformed_asset
        assert "Type" in transformed_asset

class TestNessusETLPipeline:
    """Test the complete ETL pipeline"""
    
    @pytest.fixture
    def mock_db_connection(self):
        """Mock database connection for testing"""
        return "sqlite:///:memory:"
    
    @pytest.fixture
    def sample_nessus_file(self):
        """Get the path to the sample .nessus file"""
        sample_dir = project_root / "data" / "nessus_reports" / "sample_files" / "nessus"
        nessus_files = list(sample_dir.glob("*.nessus"))
        if not nessus_files:
            pytest.skip("No .nessus files found in data/nessus_reports/sample_files/nessus directory")
        return str(nessus_files[0])
    
    @patch('etl.loaders.database_loader.DatabaseLoader')
    def test_pipeline_initialization(self, mock_loader, mock_db_connection):
        """Test that the pipeline initializes correctly"""
        pipeline = NessusETLPipeline(mock_db_connection)
        
        assert pipeline.transformer is not None
        assert pipeline.loader is not None
        assert pipeline.stats["files_processed"] == 0
        assert pipeline.stats["assets_loaded"] == 0
        assert pipeline.stats["vulnerabilities_loaded"] == 0
    
    @patch('etl.loaders.database_loader.DatabaseLoader')
    def test_process_nessus_file_success(self, mock_loader_class, mock_db_connection, sample_nessus_file):
        """Test successful processing of a Nessus file"""
        # Mock the loader
        mock_loader = Mock()
        mock_loader.load_assets.return_value = 5
        mock_loader.load_vulnerabilities.return_value = 20
        mock_loader_class.return_value = mock_loader
        
        pipeline = NessusETLPipeline(mock_db_connection)
        result = pipeline.process_nessus_file(sample_nessus_file)
        
        assert result["success"] is True
        assert result["error"] is None
        assert pipeline.stats["files_processed"] == 1
        assert pipeline.stats["assets_loaded"] == 5
        assert pipeline.stats["vulnerabilities_loaded"] == 20
    
    @patch('etl.loaders.database_loader.DatabaseLoader')
    def test_process_nonexistent_file(self, mock_loader, mock_db_connection):
        """Test processing of a non-existent file"""
        pipeline = NessusETLPipeline(mock_db_connection)
        
        with pytest.raises(FileNotFoundError):
            pipeline.process_nessus_file("/path/to/nonexistent/file.nessus")
    
    @patch('etl.loaders.database_loader.DatabaseLoader')
    def test_process_directory(self, mock_loader_class, mock_db_connection):
        """Test processing of a directory containing Nessus files"""
        # Mock the loader
        mock_loader = Mock()
        mock_loader.load_assets.return_value = 5
        mock_loader.load_vulnerabilities.return_value = 20
        mock_loader_class.return_value = mock_loader
        
        pipeline = NessusETLPipeline(mock_db_connection)
        sample_dir = project_root / "data" / "nessus_reports" / "sample_files" / "nessus"
        
        if not sample_dir.exists():
            pytest.skip("Sample files directory not found")
        
        result = pipeline.process_directory(str(sample_dir))
        
        assert "total_files" in result
        assert "successful_files" in result
        assert "failed_files" in result
        assert result["total_files"] >= 0

class TestNessusFileStructure:
    """Test the structure and content of sample Nessus files"""
    
    @pytest.fixture
    def sample_nessus_files(self):
        """Get all sample .nessus files"""
        sample_dir = project_root / "data" / "nessus_reports" / "sample_files" / "nessus"
        nessus_files = list(sample_dir.glob("*.nessus"))
        if not nessus_files:
            pytest.skip("No .nessus files found in data/nessus_reports/sample_files/nessus directory")
        return nessus_files
    
    def test_nessus_file_xml_structure(self, sample_nessus_files):
        """Test that all sample Nessus files have valid XML structure"""
        for nessus_file in sample_nessus_files:
            try:
                tree = ET.parse(nessus_file)
                root = tree.getroot()
                assert root.tag == "NessusClientData_v2"
            except ET.ParseError as e:
                pytest.fail(f"XML parsing error in {nessus_file.name}: {e}")
    
    def test_nessus_file_content(self, sample_nessus_files):
        """Test that sample Nessus files contain expected content"""
        for nessus_file in sample_nessus_files:
            tree = ET.parse(nessus_file)
            root = tree.getroot()
            
            # Should have at least one report
            reports = root.findall(".//Report")
            assert len(reports) > 0, f"No reports found in {nessus_file.name}"
            
            # Should have at least one host
            hosts = root.findall(".//ReportHost")
            assert len(hosts) > 0, f"No hosts found in {nessus_file.name}"
            
            # Should have some vulnerability items
            items = root.findall(".//ReportItem")
            assert len(items) > 0, f"No vulnerability items found in {nessus_file.name}"

if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v"]) 