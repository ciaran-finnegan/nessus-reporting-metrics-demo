# Tests Directory

This directory contains all test files for the Nessus Reporting Metrics Demo project.

## Test Files

### Core ETL Tests
- **`test_etl_pipeline.py`** - Tests the complete ETL pipeline including extractors, transformers, and loaders
- **`test_nessus_pipeline.py`** - Tests specific to Nessus file processing pipeline
- **`test_validation.py`** - Tests for asset type validation against the schema

### Business Context Tests
- **`test_business_context.py`** - Unit tests for BusinessContextManager with mocked dependencies
- **`test_business_context_integration.py`** - Integration test demonstrating full Business Context workflow with real data
- **`query_business_context.py`** - Utility script to query and display existing business context data (not a test, but a helper)

### Test Data
- **`test_001.json`**, **`test_002.json`** - Sample JSON files for validation testing

## Running Tests

### Run all tests:
```bash
pytest
```

### Run specific test file:
```bash
pytest tests/test_business_context.py -v
```

### Run integration test (requires Supabase connection):
```bash
python tests/test_business_context_integration.py
```

### Query existing data:
```bash
python tests/query_business_context.py
```

## Test Requirements
- All unit tests use mocks and don't require external dependencies
- Integration tests require:
  - Supabase connection (configured in `.env`)
  - Applied database schemas
  - Sample Nessus files in `data/nessus_reports/sample_files/nessus/`

## Test Coverage
The tests cover:
- ETL pipeline components (extractors, transformers, loaders)
- Business Groups creation and hierarchy
- Asset Tags (static and dynamic)
- Dynamic tag rule evaluation
- Asset assignments to business groups and tags
- Time series data loading
- Asset fingerprinting and deduplication
- Business context queries and reporting 