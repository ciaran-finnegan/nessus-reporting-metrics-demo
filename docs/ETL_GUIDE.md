# ETL Pipeline Guide

This guide provides detailed technical information about the Nessus ETL pipeline implementation.

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Setup and Configuration](#setup-and-configuration)
- [Usage Examples](#usage-examples)
- [Data Mapping](#data-mapping)
- [Error Handling](#error-handling)
- [Logging](#logging)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

The ETL pipeline processes Nessus .nessus XML files and loads vulnerability and asset data into a PostgreSQL database. It follows a modular architecture with separate components for extraction, transformation, and loading.

## Architecture

### Core Components

#### 1. Extractors (`etl/extract.py`)
- **NessusExtractor**: Parses .nessus XML files and extracts raw vulnerability and asset data
- Handles host properties, vulnerability details, CVE extraction, and plugin information
- Supports batch processing of multiple files

#### 2. Transformers (`etl/transform.py`)
- **NessusTransformer**: Transforms raw data to match database schemas
- Maps severity levels, extracts business groups, and formats data for database insertion
- Validates data integrity and applies business rules

#### 3. Loaders (`etl/load.py`)
- **DatabaseLoader**: Loads transformed data into PostgreSQL database
- Handles upsert operations to avoid duplicates
- Manages database connections and transactions

#### 4. Pipeline (`etl/pipeline.py`)
- **NessusETLPipeline**: Orchestrates the entire ETL process
- Processes single files or entire directories
- Provides progress tracking and error reporting

### Data Flow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   .nessus XML   │───▶│   Extractor     │───▶│   Transformer   │───▶│     Loader      │
│     Files       │    │                 │    │                 │    │                 │
└─────────────────┘    │ • Parse XML     │    │ • Map fields    │    │ • Upsert data   │
                       │ • Extract hosts │    │ • Validate      │    │ • Handle dupes  │
                       │ • Extract vulns │    │ • Transform     │    │ • Commit txns   │
                       └─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │                        │
                                                        ▼                        ▼
                                              ┌─────────────────┐    ┌─────────────────┐
                                              │   Validation    │    │   PostgreSQL    │
                                              │     Rules       │    │    Database     │
                                              └─────────────────┘    └─────────────────┘
```

## Setup and Configuration

### Prerequisites
- Python 3.8+
- PostgreSQL 12+ (or SQLite for development)
- Required Python packages (see `requirements.txt`)

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DB_HOST` | Database host | localhost | No |
| `DB_PORT` | Database port | 5432 | No |
| `DB_NAME` | Database name | vulnerability_db | No |
| `DB_USER` | Database user | postgres | No |
| `DB_PASSWORD` | Database password | password | Yes |
| `NESSUS_INPUT_DIR` | Default input directory | data/nessus_reports | No |
| `LOG_LEVEL` | Logging level | INFO | No |

### Database Setup

1. Create database tables using the SQL schemas:
   ```bash
   psql -U postgres -d vulnerability_db -f schemas/assets.sql
   psql -U postgres -d vulnerability_db -f schemas/vulnerabilities.sql
   psql -U postgres -d vulnerability_db -f schemas/metrics.sql
   ```

2. Verify table creation:
   ```sql
   \dt  -- List tables
   ```

## Usage Examples

### Basic Usage

#### Process a Single File
```bash
# Using module syntax
python -m etl.pipeline /path/to/scan_results.nessus

# Using direct script execution
python etl/pipeline.py /path/to/scan_results.nessus
```

#### Process Multiple Files
```bash
# Process all .nessus files in a directory
python -m etl.pipeline /path/to/nessus_reports/

# Process with custom database URL
DB_HOST=prod-db.example.com python -m etl.pipeline /path/to/reports/
```

### Advanced Usage

#### Custom Configuration
```python
from etl.pipeline import NessusETLPipeline
from etl.config import Config

# Custom configuration
config = Config(
    db_host='custom-host',
    db_port=5433,
    db_name='custom_db',
    log_level='DEBUG'
)

# Initialize pipeline
pipeline = NessusETLPipeline(config)

# Process files
pipeline.process_file('/path/to/file.nessus')
```

#### Batch Processing with Progress Tracking
```python
import os
from etl.pipeline import NessusETLPipeline

pipeline = NessusETLPipeline()
nessus_files = [f for f in os.listdir('/path/to/reports') if f.endswith('.nessus')]

for i, filename in enumerate(nessus_files):
    print(f"Processing {i+1}/{len(nessus_files)}: {filename}")
    try:
        pipeline.process_file(os.path.join('/path/to/reports', filename))
        print(f"✅ Successfully processed {filename}")
    except Exception as e:
        print(f"❌ Failed to process {filename}: {e}")
```

## Data Mapping

### Host Properties Extracted

| Nessus Field | Database Field | Description |
|--------------|----------------|-------------|
| `host-ip` | Asset_IP | Primary IP address |
| `host-fqdn` | Asset_Name | Fully qualified domain name |
| `netbios-name` | Asset_Name | NetBIOS name (fallback) |
| `operating-system` | Asset_OS | OS information |
| `os` | OS_Version | OS version details |
| `aws-instance-id` | Cloud_Instance_ID | AWS instance identifier |
| `azure-vm-id` | Cloud_Instance_ID | Azure VM identifier |
| `gcp-instance-id` | Cloud_Instance_ID | GCP instance identifier |

### Vulnerability Properties Extracted

| Nessus Field | Database Field | Description |
|--------------|----------------|-------------|
| `pluginName` | Vulnerability_Name | Vulnerability name |
| `severity` | Severity | Severity level (0-4) |
| `cvss_base_score` | CVSS_Score | CVSS base score |
| `port` | Port | Port number |
| `protocol` | Protocol | Network protocol |
| `svc_name` | Service | Service name |
| `pluginID` | Plugin_ID | Nessus plugin ID |
| `pluginFamily` | Plugin_Family | Plugin family |
| `description` | Vulnerability_Description | Vulnerability description |
| `solution` | Solution | Remediation solution |
| `see_also` | References | Additional references |

### Severity Mapping

| Nessus Severity | Database Severity | Risk Level |
|-----------------|-------------------|------------|
| 0 | Info | Informational |
| 1 | Low | Low |
| 2 | Medium | Medium |
| 3 | High | High |
| 4 | Critical | Critical |

### Business Group Extraction

The pipeline extracts business groups from various Nessus fields:
- Custom host properties
- Asset tags
- Organizational unit information
- Network segment mapping

## Error Handling

### Exception Types

The pipeline handles several types of errors:

1. **File Processing Errors**
   - Invalid XML format
   - Missing required fields
   - Corrupted files

2. **Database Errors**
   - Connection failures
   - Constraint violations
   - Transaction rollbacks

3. **Data Validation Errors**
   - Invalid data types
   - Missing required fields
   - Business rule violations

### Error Recovery

```python
# Example error handling in pipeline
try:
    pipeline.process_file(filename)
except FileNotFoundError:
    logger.error(f"File not found: {filename}")
except XMLParseError:
    logger.error(f"Invalid XML format: {filename}")
except DatabaseError as e:
    logger.error(f"Database error processing {filename}: {e}")
    # Rollback transaction
    db.rollback()
except Exception as e:
    logger.error(f"Unexpected error processing {filename}: {e}")
    # Continue with next file
    continue
```

### Retry Logic

The pipeline includes retry logic for transient failures:
- Database connection timeouts
- Network interruptions
- Temporary file locks

## Logging

### Log Configuration

Logs are written to both console and file (`etl.log`). The logging level can be controlled via the `LOG_LEVEL` environment variable.

### Log Levels

- **DEBUG**: Detailed debugging information
- **INFO**: General information about pipeline execution
- **WARNING**: Warning messages for non-critical issues
- **ERROR**: Error messages for failures
- **CRITICAL**: Critical errors that stop execution

### Log Format

```
2024-01-15 10:30:45,123 - etl.pipeline - INFO - Processing file: scan_results.nessus
2024-01-15 10:30:45,456 - etl.extract - DEBUG - Extracted 150 hosts from file
2024-01-15 10:30:45,789 - etl.transform - INFO - Transformed 1250 vulnerabilities
2024-01-15 10:30:46,012 - etl.load - INFO - Loaded 1250 vulnerabilities to database
```

### Custom Logging

```python
import logging
from etl.pipeline import NessusETLPipeline

# Configure custom logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('custom_etl.log'),
        logging.StreamHandler()
    ]
)

pipeline = NessusETLPipeline()
```

## Performance Considerations

### Batch Processing

For large datasets, consider:

1. **Batch Size**: Process files in batches to manage memory usage
2. **Database Connections**: Use connection pooling for multiple files
3. **Parallel Processing**: Process multiple files concurrently

### Memory Management

```python
# Example batch processing
def process_large_dataset(file_list, batch_size=10):
    for i in range(0, len(file_list), batch_size):
        batch = file_list[i:i + batch_size]
        for filename in batch:
            pipeline.process_file(filename)
        # Optional: garbage collection between batches
        import gc
        gc.collect()
```

### Database Optimization

1. **Indexes**: Ensure proper indexes on frequently queried fields
2. **Bulk Inserts**: Use bulk insert operations for large datasets
3. **Connection Pooling**: Reuse database connections

## Troubleshooting

### Common Issues

#### 1. Database Connection Errors
```
Error: could not connect to server: Connection refused
```
**Solution**: Check database server status and connection parameters.

#### 2. XML Parsing Errors
```
Error: XML syntax error at line 1234
```
**Solution**: Validate .nessus file integrity, check for corruption.

#### 3. Memory Issues
```
Error: MemoryError during processing
```
**Solution**: Process files in smaller batches, increase available memory.

#### 4. Permission Errors
```
Error: Permission denied accessing file
```
**Solution**: Check file permissions and user access rights.

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
LOG_LEVEL=DEBUG python -m etl.pipeline /path/to/file.nessus
```

### Performance Monitoring

Monitor pipeline performance:

```python
import time
from etl.pipeline import NessusETLPipeline

start_time = time.time()
pipeline = NessusETLPipeline()
pipeline.process_file('large_scan.nessus')
end_time = time.time()

print(f"Processing time: {end_time - start_time:.2f} seconds")
```

## Database Schema Compatibility

The pipeline is designed to work with the schemas defined in:
- `schemas/assets.sql`
- `schemas/vulnerabilities.sql`
- `schemas/metrics.sql`
- `schemas/relationships.sql`

Ensure your database tables are created using these schemas before running the ETL pipeline.

## Next Steps

- **API Integration**: Connect the pipeline to the REST API for real-time processing
- **Scheduling**: Set up automated processing with cron jobs or task schedulers
- **Monitoring**: Implement monitoring and alerting for pipeline health
- **Scaling**: Consider distributed processing for very large datasets 