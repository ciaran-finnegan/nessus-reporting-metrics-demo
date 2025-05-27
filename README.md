# nessus-reporting-metrics-demo
Generate vulnerability metrics from Nessus data

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [System Architecture](#system-architecture)
- [ETL Pipeline](#etl-pipeline)
- [Data Model](#data-model)
- [Asset Types Schema](#asset-types-schema)
- [Project Structure](#project-structure)
- [Documentation](#documentation)

## Overview

A proof of concept system that implements a series of Python scripts to perform extract, transform and load (ETL) services for vulnerability management data, with enterprise-grade business context features and comprehensive metrics generation capabilities.

## Key Features

### Core ETL Capabilities
- **Extract**: Parse Nessus .nessus XML files and extract vulnerability data
- **Transform**: Map fields to standardised schemas with data validation
- **Load**: Store data in PostgreSQL/Supabase with time series support
- **Metrics**: Generate MTTR and remediation capacity metrics automatically

### Business Context Features
- **Business Groups**: Hierarchical organisation matching your company structure
  - Geographic regions, departments, environments
  - Parent/child relationships for drill-down reporting
  - Asset assignment to multiple groups
  
- **Asset Tags**: Dynamic and static classification
  - Manual tags for custom categorisation
  - Dynamic tags with rule-based application
  - Imported tags from vulnerability scanners
  - Criticality scoring (1-5) with inheritance
  
- **Asset Management**
  - Multi-asset-type support (Host, Code Project, Website, Image, Cloud Resource)
  - Asset fingerprinting for identity persistence
  - Deduplication across scans
  - Change tracking and history

### Metrics & Reporting
- **MTTR Metrics**: Mean Time To Remediate calculations
  - Overall MTTR across all vulnerabilities
  - MTTR by risk level (Critical, High, Medium, Low)
  - MTTR by business group for organisational insights
  - MTTR by asset type for infrastructure planning
  
- **Remediation Capacity**: Organisational performance metrics
  - Average daily remediation rate
  - Remediation vs. introduction ratios
  - Campaign coverage and effectiveness
  - Capacity by risk level and business group
  
- **Historical Tracking**: Time series metrics storage
  - Point-in-time snapshots for trend analysis
  - Historical MTTR tracking
  - Remediation trend analysis
  - Dashboard-ready data structures

### Advanced Features
- **Time Series Data**: Track vulnerability lifecycle across multiple scans
- **Risk Scoring**: Business-aware vulnerability prioritisation
- **Reporting Views**: Pre-built database views for common queries
- **Scan Sessions**: Complete audit trail of all vulnerability scans
- **Extensible Design**: Easy to add new scanners and asset types

## Quick Start

### Prerequisites
- Python 3.8+
- Supabase account (for database) or PostgreSQL
- Virtual environment (recommended)

### Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd nessus-reporting-metrics-demo
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```bash
   # For Supabase (recommended)
   export SUPABASE_URL="your-supabase-url"
   export SUPABASE_ANON_KEY="your-anon-key"
   export SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"
   
   # For traditional PostgreSQL
   export DB_HOST=localhost
   export DB_PORT=5432
   export DB_NAME=vulnerability_db
   export DB_USER=postgres
   export DB_PASSWORD=password
   ```

5. Apply database schemas:
   - Run `schemas/supabase_timeseries_schema.sql` in your database
   - Run `schemas/business_context_schema.sql` for Business Groups and Tags support

### Basic Usage

#### 1. Run the complete ETL pipeline with metrics generation:
```bash
python test_timeseries_etl.py
```

#### 2. Process a single Nessus file with metrics:
```python
from etl.extractors import NessusExtractor
from etl.transformers import NessusTransformer
from etl.loaders import SupabaseTimeSeriesLoader

# Initialize components
extractor = NessusExtractor('path/to/file.nessus')
transformer = NessusTransformer()
loader = SupabaseTimeSeriesLoader()

# Create scan session
scan_session_id = loader.create_scan_session(
    scan_name="My Vulnerability Scan",
    scan_file_path='path/to/file.nessus'
)

# Extract and load data
assets = extractor.extract_assets()
vulnerabilities = extractor.extract_vulnerabilities()

assets_loaded = loader.load_assets(assets)
vulns_loaded = loader.load_vulnerabilities(vulnerabilities)

# Generate metrics automatically
metrics_success = loader.generate_metrics()

# Update scan session stats
loader.update_scan_session_stats(
    total_hosts=len(assets),
    total_vulnerabilities=len(vulnerabilities)
)
```

#### 3. Generate metrics from existing data:
```python
from etl.loaders import SupabaseTimeSeriesLoader

loader = SupabaseTimeSeriesLoader()
success = loader.generate_metrics()
```

#### 4. Query existing data and metrics:
```bash
python tests/query_business_context.py
```

For detailed usage, see:
- [ETL Pipeline Guide](docs/ETL_GUIDE.md) - Basic ETL operations
- [Business Context Guide](docs/BUSINESS_CONTEXT_GUIDE.md) - Business Groups and Tags

## Generating Time Series Nessus Files for Metrics Testing

To create a realistic time series of Nessus scan files for testing MTTR and remediation metrics, use the provided script:

### 1. Generate Weekly Nessus Files

From the `data/nessus_reports/sample_files/nessus/` directory, run:

```bash
python generate_time_series_nessus.py
```

This will create 8 new `.nessus` files, each simulating a weekly scan with realistic vulnerability lifecycle (some vulns close, some persist, some new ones appear). The scan dates will span the last 8 weeks up to the current date.

### 2. Process the Generated Files

You can then run the ETL pipeline on each generated file to populate your metrics tables and views:

```bash
python test_timeseries_etl.py nessus_scan_20250331.nessus
python test_timeseries_etl.py nessus_scan_20250407.nessus
# ...and so on for each generated file
```

This will ensure your MTTR and trend metrics are populated with rich, realistic data for your web app UI.

## System Architecture

### High Level Design

The system implements a classic ETL (Extract, Transform, Load) architecture:

1. **Extract** data from source systems (Nessus files)
2. **Transform** data by mapping fields to standardised schemas
3. **Load** transformed data into time series tables in a database
4. **Generate** additional metrics and reporting data
5. **Serve** data via API for web application consumption

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nessus Files  │───▶│   ETL Pipeline  │───▶│    Database     │
│   (.nessus XML) │    │                 │    │  (PostgreSQL/   │
└─────────────────┘    │  • Extract      │    │   Supabase)     │
                       │  • Transform    │    └─────────────────┘
┌─────────────────┐    │  • Load         │              │
│  Asset Types    │───▶│  • Tag Assets   │              ▼
│  Validation     │    │  • Apply Rules  │    ┌─────────────────┐
└─────────────────┘    │  • Generate     │    │Business Context │
                       │    Metrics      │    │  • Groups       │
┌─────────────────┐    └─────────────────┘    │  • Tags         │
│ Business Rules  │            ▲               │  • Criticality  │
│  Configuration  │            │               └─────────────────┘
└─────────────────┘            │                        │
                               │                        ▼
┌─────────────────┐            │               ┌─────────────────┐
│   Metrics       │────────────┘               │   Metrics &     │
│   Generation    │                            │   Reporting     │
│   • MTTR        │                            │   • Snapshots   │
│   • Capacity    │                            │   • History     │
│   • Trends      │                            │   • Views       │
└─────────────────┘                            └─────────────────┘
                                                        │
                                                        ▼
┌─────────────────┐                           ┌─────────────────┐
│   Web API       │◀──────────────────────────│   Dashboard     │
│                 │                           │   Visualisation │
└─────────────────┘                           └─────────────────┘
```

## ETL Pipeline

The ETL pipeline processes Nessus .nessus XML files and loads vulnerability and asset data into a PostgreSQL database.

### Architecture Components

1. **Extractors** (`etl/extractors/`)
   - **NessusExtractor**: Parses .nessus XML files and extracts raw vulnerability and asset data
   - Handles host properties, vulnerability details, CVE extraction, and plugin information

2. **Transformers** (`etl/transformers/`)
   - **NessusTransformer**: Transforms raw data to match database schemas
   - Maps severity levels, extracts business groups, and formats data for database insertion

3. **Loaders** (`etl/loaders/`)
   - **DatabaseLoader**: Loads transformed data into PostgreSQL database
   - **SupabaseTimeSeriesLoader**: Enhanced loader with time series support
   - **BusinessContextManager**: Manages Business Groups and Asset Tags
   - Handles upsert operations, asset fingerprinting, and deduplication

4. **Business Context**
   - **Business Groups**: Hierarchical asset organisation
   - **Asset Tags**: Dynamic and static asset classification
   - **Criticality Scoring**: Risk-based prioritisation

5. **Metrics Generation**
   - **MTTRCalculator**: Calculates Mean Time To Remediate metrics
   - **MetricsGenerator**: Generates comprehensive performance metrics
   - **ReportingTablesManager**: Manages metrics storage and history

6. **Pipeline** (`test_timeseries_etl.py`)
   - **Complete ETL Process**: Orchestrates extraction, transformation, loading, and metrics generation
   - **Time Series Support**: Proper asset identity management and vulnerability tracking
   - **Integrated Metrics**: Automatic metrics generation after data loading

### Configuration

Configuration is handled via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| **Supabase Configuration** | | |
| `SUPABASE_URL` | Supabase project URL | Required |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | Required |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key | Required |
| **PostgreSQL Configuration** | | |
| `DB_HOST` | Database host | localhost |
| `DB_PORT` | Database port | 5432 |
| `DB_NAME` | Database name | vulnerability_db |
| `DB_USER` | Database user | postgres |
| `DB_PASSWORD` | Database password | password |
| **General Configuration** | | |
| `NESSUS_INPUT_DIR` | Default input directory | data/nessus_reports |
| `LOG_LEVEL` | Logging level | INFO |

### Data Mapping

**Assets extracted:**
- Asset_Name, Asset_IP, Asset_OS, OS_Version
- Type, Asset_State, Cloud_Instance_ID
- Asset_Tags, Business_Groups, Owners
- **NEW**: Asset fingerprinting for identity persistence
- **NEW**: Multi-asset-type support (Host, Code Project, Website, Image, Cloud Resource)

**Vulnerabilities extracted:**
- Asset_Name, Vulnerability_Name, CVE, CVSS_Score
- Risk_Score, Severity, Status, First_Seen/Last_Seen
- Port/Protocol/Service, Description, Solution
- **NEW**: Time series tracking with proper relationships

**Business Context Features:**
- Hierarchical Business Groups matching organisational structure
- Dynamic Asset Tags with rule-based application
- Asset criticality scoring (1-5) with tag inheritance
- Business-aware vulnerability prioritisation

**Metrics Generated:**
- MTTR (Mean Time To Remediate) by risk level, business group, and asset type
- Remediation capacity and daily remediation rates
- Campaign coverage and effectiveness metrics
- Historical trend analysis and point-in-time snapshots
- Dashboard-ready reporting views and data structures

For detailed technical implementation, see [ETL Pipeline Guide](docs/ETL_GUIDE.md) and [Business Context Guide](docs/BUSINESS_CONTEXT_GUIDE.md).

## Data Model

### Schema Overview

The system uses standardised schemas for:

- **Vulnerability Schema** - Vulnerability details, CVEs, CVSS scores
- **Asset Schema** - Asset information, properties, and metadata  
- **Asset Category Schema** - Asset type classifications
- **Time Series Schema** - Scan sessions and vulnerability tracking over time
- **Business Context Schema** - Business Groups and Asset Tags
- **Relationships** - Asset and vulnerability relationships with proper foreign keys

### Key Tables:
- `assets` - Multi-asset-type support with fingerprinting
- `vulnerability_definitions` - Master list of vulnerabilities
- `vulnerability_scans` - Time series vulnerability findings
- `business_groups` - Hierarchical organisational structure
- `asset_tags` - Dynamic and static asset classification
- `scan_sessions` - Audit trail of all scans

### Key Views:
- `assets_with_context` - Assets with business groups, tags, and effective criticality
- `current_vulnerabilities` - Latest vulnerability state
- `vulnerability_summary_by_business_group` - Business-aligned reporting
- `asset_summary` - Asset overview with vulnerability counts

For schema details, see [schemas/supabase_timeseries_schema.sql](schemas/supabase_timeseries_schema.sql) and [schemas/business_context_schema.sql](schemas/business_context_schema.sql).

## Asset Types Schema

This project uses a standardised schema for categorising assets, based on Vulcan Cyber ExposureOS™ documentation. Below are the permitted asset types and their descriptions, along with examples and subcategories where relevant.

### Asset Types

| Type           | Description                                                                 | Examples / Subtypes                                                                 |
|----------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| Host           | Physical or virtual machines, network devices, IoT, and related endpoints.  | Servers, Workstations, NAS Devices, Printers, Scanners, IoT Devices, Network Devices, Virtual Machines, Physical Machines, Laptops, Desktops, Firewalls, Routers, Switches, Load Balancers, Storage Devices, Mobile Devices, Appliances |
| Code Project   | Software codebases, repositories, and related development projects.         | GitHub/GitLab/Bitbucket Repositories, SAST/SCA/IAC Projects, Source Code, Application Projects, Libraries, Frameworks |
| Website        | Web-based applications or services accessible via the internet.              | Web Applications, Internet-facing Services, Main Domains, Base URLs, Subdomains, API Endpoints |
| Image          | Container images, running containers, and registries.                       | Docker Images, OCI Images, Virtual Machine Images, Base Images, Application Images, Containers, Registries |
| Cloud Resource | Cloud provider resources and services.                                      | See provider-specific breakdowns below                                              |

## Cloud Resource: Provider-Specific Permitted Values

### AWS
- S3 Bucket
- EC2 Instance
- Lambda Function
- RDS Instance
- DynamoDB Table
- IAM User
- IAM Role
- IAM Policy
- KMS Key
- VPC
- Subnet
- Security Group
- Route Table
- Internet Gateway
- NAT Gateway
- Elastic Load Balancer
- CloudFront Distribution
- SNS Topic
- SQS Queue
- CloudWatch Alarm
- CloudTrail Trail
- ECR Repository
- ECS Cluster
- EKS Cluster
- Elasticache Cluster
- Redshift Cluster
- Secrets Manager Secret
- Parameter Store Parameter
- GuardDuty Detector
- Security Hub
- Step Function
- Glue Job
- Athena Workgroup
- CodeBuild Project
- CodePipeline Pipeline
- API Gateway
- Lightsail Instance
- Elastic File System
- Backup Vault
- Organization
- Account
- Region
- Other

### Azure
- Storage Account
- Blob Storage
- File Storage
- Virtual Machine
- VM Scale Set
- App Service
- Function App
- SQL Database
- Cosmos DB
- PostgreSQL Server
- MySQL Server
- MariaDB Server
- Virtual Network
- Subnet
- Public IP Address
- Network Security Group
- Application Gateway
- Load Balancer
- Route Table
- Firewall
- Key Vault
- Event Hub
- Service Bus
- Automation Account
- API Management
- Synapse Workspace
- Machine Learning Workspace
- Databricks Workspace
- CDN Profile
- DNS Zone
- Resource Group
- Subscription
- Managed Identity
- Policy Assignment
- Role Assignment
- Log Analytics Workspace
- Alert Rule
- Kubernetes Service (AKS)
- Container Registry
- Backup Vault
- App Configuration
- Logic App
- Search Service
- Stream Analytics Job
- Bastion Host
- Other

### GCP
- Cloud Storage Bucket
- Compute Engine VM
- Cloud Function
- BigQuery Dataset
- Cloud SQL Instance
- Spanner Instance
- Pub/Sub Topic
- Pub/Sub Subscription
- VPC Network
- Subnet
- Firewall Rule
- Load Balancer
- Cloud DNS Zone
- Cloud Run Service
- GKE Cluster
- GKE Node Pool
- Service Account
- IAM Policy
- KMS KeyRing
- KMS CryptoKey
- Secret Manager Secret
- App Engine App
- Dataflow Job
- Dataproc Cluster
- Cloud Scheduler Job
- Cloud Tasks Queue
- Cloud Endpoints Service
- Project
- Organization
- Folder
- Region
- Other

## Example Schema (YAML)

```yaml
- type: Host
  permitted_values:
    - Server
    - Workstation
    - NAS Device
    - Printer
    - Scanner
    - IoT Device
    - Network Device
    - Virtual Machine
    - Physical Machine
    - Laptop
    - Desktop
    - Firewall
    - Router
    - Switch
    - Load Balancer
    - Storage Device
    - Mobile Device
    - Appliance
- type: Code Project
  permitted_values:
    - Repository
    - SAST Project
    - SCA Project
    - IAC Project
    - GitHub Repository
    - GitLab Repository
    - Bitbucket Repository
    - Source Code
    - Application Project
    - Library
    - Framework
- type: Website
  permitted_values:
    - Web Application
    - Internet Service
    - Main Domain
    - Base URL
    - Subdomain
    - API Endpoint
- type: Image
  permitted_values:
    - Container Image
    - Container
    - Registry
    - Docker Image
    - OCI Image
    - Virtual Machine Image
    - Base Image
    - Application Image
- type: Cloud Resource
  providers:
    - provider: AWS
      permitted_values:
        - S3 Bucket
        - EC2 Instance
        - Lambda Function
        - RDS Instance
        - DynamoDB Table
        - IAM User
        - IAM Role
        - IAM Policy
        - KMS Key
        - VPC
        - Subnet
        - Security Group
        - Route Table
        - Internet Gateway
        - NAT Gateway
        - Elastic Load Balancer
        - CloudFront Distribution
        - SNS Topic
        - SQS Queue
        - CloudWatch Alarm
        - CloudTrail Trail
        - ECR Repository
        - ECS Cluster
        - EKS Cluster
        - Elasticache Cluster
        - Redshift Cluster
        - Secrets Manager Secret
        - Parameter Store Parameter
        - GuardDuty Detector
        - Security Hub
        - Step Function
        - Glue Job
        - Athena Workgroup
        - CodeBuild Project
        - CodePipeline Pipeline
        - API Gateway
        - Lightsail Instance
        - Elastic File System
        - Backup Vault
        - Organization
        - Account
        - Region
        - Other
    - provider: Azure
      permitted_values:
        - Storage Account
        - Blob Storage
        - File Storage
        - Virtual Machine
        - VM Scale Set
        - App Service
        - Function App
        - SQL Database
        - Cosmos DB
        - PostgreSQL Server
        - MySQL Server
        - MariaDB Server
        - Virtual Network
        - Subnet
        - Public IP Address
        - Network Security Group
        - Application Gateway
        - Load Balancer
        - Route Table
        - Firewall
        - Key Vault
        - Event Hub
        - Service Bus
        - Automation Account
        - API Management
        - Synapse Workspace
        - Machine Learning Workspace
        - Databricks Workspace
        - CDN Profile
        - DNS Zone
        - Resource Group
        - Subscription
        - Managed Identity
        - Policy Assignment
        - Role Assignment
        - Log Analytics Workspace
        - Alert Rule
        - Kubernetes Service (AKS)
        - Container Registry
        - Backup Vault
        - App Configuration
        - Logic App
        - Search Service
        - Stream Analytics Job
        - Bastion Host
        - Other
    - provider: GCP
      permitted_values:
        - Cloud Storage Bucket
        - Compute Engine VM
        - Cloud Function
        - BigQuery Dataset
        - Cloud SQL Instance
        - Spanner Instance
        - Pub/Sub Topic
        - Pub/Sub Subscription
        - VPC Network
        - Subnet
        - Firewall Rule
        - Load Balancer
        - Cloud DNS Zone
        - Cloud Run Service
        - GKE Cluster
        - GKE Node Pool
        - Service Account
        - IAM Policy
        - KMS KeyRing
        - KMS CryptoKey
        - Secret Manager Secret
        - App Engine App
        - Dataflow Job
        - Dataproc Cluster
        - Cloud Scheduler Job
        - Cloud Tasks Queue
        - Cloud Endpoints Service
        - Project
        - Organization
        - Folder
        - Region
        - Other
```

## Notes
- Each asset type may have additional metadata or unique identifiers depending on the connector or platform.
- For a full list of supported connectors and their unique identifiers, refer to the documentation or the extracted PDF.

# Asset Type Validation

To ensure that asset types, providers, and subtypes are valid and consistent with the permitted values, we provide a script to validate asset definitions against `asset_types.yaml`.

## How it Works
- The script `validate_asset_type.py` loads the allowed types and values from `asset_types.yaml`.
- It checks that the asset's `type` is valid.
- For `Cloud Resource` types, it also checks the `provider` and `subtype`.
- For other types, it checks the `subtype` if present.

## Example Asset File
```json
{
  "type": "Cloud Resource",
  "provider": "AWS",
  "subtype": "EC2 Instance"
}
```

## Usage
1. Ensure you have `pyyaml` installed:
   ```sh
   pip install pyyaml
   ```
2. Run the validation script:
   ```sh
   python validate_asset_type.py asset.json asset_types.yaml
   ```

- If the asset is valid, you will see:
  ```
  ✅ Valid asset
  ```
- If the asset is invalid, you will see an error message describing the issue.

This approach ensures that all asset data used in the system is standardised and validated against a single source of truth.

## Project Structure

To simplify development and maintenance, the project uses the following structure:

```
nessus-reporting-metrics-demo/
│
├── etl/                        # All ETL scripts and modules
│   ├── __init__.py
│   ├── extractors/             # Data extraction modules
│   │   ├── __init__.py
│   │   └── nessus_extractor.py
│   ├── transformers/           # Data transformation modules
│   │   ├── __init__.py
│   │   └── nessus_transformer.py
│   ├── loaders/                # Data loading modules
│   │   ├── __init__.py
│   │   ├── database_loader.py
│   │   ├── supabase_timeseries_loader.py  # Includes metrics generation
│   │   └── business_context_manager.py
│   ├── metrics/                # Metrics generation modules
│   │   ├── __init__.py
│   │   ├── mttr_calculator.py
│   │   ├── metrics_generator.py
│   │   └── reporting_tables.py
│   └── pipeline/               # Pipeline orchestration
│       ├── __init__.py
│       └── nessus_etl_pipeline.py
│
├── schemas/                    # Database and validation schemas
│   ├── supabase_timeseries_schema.sql
│   ├── business_context_schema.sql
│   └── ...                     # Other schema files
│
├── assets/                     # Asset definitions and validation
│   ├── asset_types.yaml
│   └── validate_asset_type.py
│
├── config/                     # Configuration files
│   └── business_rules.yaml     # Business groups and tag rules
│
├── tests/                      # All test cases and test scripts
│   ├── test_business_context.py # Business Context unit tests
│   ├── test_business_context_integration.py # Integration test
│   ├── test_etl_pipeline.py    # ETL pipeline tests
│   ├── test_metrics_generation.py # Metrics generation tests
│   ├── query_business_context.py # Query helper script
│   └── README.md               # Test documentation
│
├── test_timeseries_etl.py      # Main ETL pipeline runner with metrics
│
├── docs/                       # Documentation
│   ├── ETL_GUIDE.md            # ETL pipeline guide
│   ├── ASSET_TYPES.md          # Asset types reference
│   └── BUSINESS_CONTEXT_GUIDE.md # Business groups and tags guide
│
├── data/                       # Sample data files
│   └── nessus_reports/
│       └── sample_files/
│           └── nessus/
│               └── *.nessus
│
├── logs/                       # Log files directory
│
├── venv/                       # Python virtual environment (in .gitignore)
│
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── .env                        # Environment variables (in .gitignore)
├── .gitignore
└── ...                         # Other project files
```

### Naming Conventions
- Python files: `snake_case.py` (e.g., `extract.py`)
- Folders: all lowercase, plural where appropriate (e.g., `schemas/`, `assets/`)
- Test files: prefix with `test_` for pytest
- Schema files: `.schema.json` suffix
- Sample data: in `data/` with descriptive names

This structure supports clear separation of concerns, scalability, and maintainability for all ETL and validation workflows.

## Documentation

### Core Documentation
- **[README.md](README.md)** - This file, main project overview and quick start
- **[ETL Pipeline Guide](docs/ETL_GUIDE.md)** - Detailed technical implementation guide
- **[Asset Types Reference](docs/ASSET_TYPES.md)** - Complete asset type definitions and validation
- **[Business Context Guide](docs/BUSINESS_CONTEXT_GUIDE.md)** - Business Groups and Asset Tags implementation

### Schema Documentation
- **[Time Series Schema](schemas/supabase_timeseries_schema.sql)** - Complete database schema with time series support
- **[Business Context Schema](schemas/business_context_schema.sql)** - Business Groups and Asset Tags schema

### Configuration
- **[Business Rules](config/business_rules.yaml)** - Sample business group and tag configuration

### API Documentation
- **[API Specification](docs/api-specification.yaml)** - OpenAPI 3.0/Swagger specification for the REST API
- **[API Quick Start](docs/API_QUICKSTART.md)** - Quick start guide for frontend developers
- **[API Documentation](docs/API.md)** - API implementation guide *(coming soon)*

### Additional Resources
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions *(coming soon)*

### Development
- **[Contributing Guidelines](CONTRIBUTING.md)** - How to contribute to the project *(coming soon)*
- **[Tests README](tests/README.md)** - Overview of all tests and how to run them

## Frontend Development

### API Specification
The project includes a comprehensive OpenAPI 3.0 specification for frontend development teams:

- **Location**: [`docs/api-specification.yaml`](docs/api-specification.yaml)
- **Format**: OpenAPI 3.0 (Swagger)
- **Viewer**: Can be viewed using [Swagger Editor](https://editor.swagger.io/) or [Swagger UI](https://swagger.io/tools/swagger-ui/)

### Key API Features
- **Authentication**: JWT-based authentication with refresh tokens
- **RESTful Design**: Standard REST patterns for all resources
- **Pagination**: Consistent pagination across all list endpoints
- **Filtering**: Advanced filtering for assets and vulnerabilities
- **Business Context**: Full support for Business Groups and Asset Tags
- **Real-time Updates**: WebSocket support for live updates (specification coming soon)

### Frontend Stack Recommendations
Based on the API design and Vulcan Cyber's UI patterns, we recommend:
- **Framework**: React/Next.js or Vue.js
- **UI Library**: Material-UI, Ant Design, or Tailwind UI
- **State Management**: Redux Toolkit or Zustand
- **API Client**: Axios with interceptors for auth
- **Charts**: Recharts or Chart.js for visualisations
- **Tables**: AG-Grid or TanStack Table for data grids

## Testing

The project includes comprehensive tests for all components:

### Running Tests

```bash
# Run the complete ETL pipeline with metrics generation
python test_timeseries_etl.py

# Run all unit tests
pytest tests/ -v

# Run specific test files
pytest tests/test_business_context.py -v
pytest tests/test_metrics_generation.py -v

# Run integration test (requires Supabase)
python tests/test_business_context_integration.py

# Query existing data and metrics
python tests/query_business_context.py
```

### Test Coverage
- **Pipeline Tests**: Complete ETL workflow with metrics generation
- **Unit Tests**: Business Context Manager, ETL Pipeline components, Metrics Generation
- **Integration Tests**: End-to-end workflow with real Supabase connection
- **Validation Tests**: Asset type schema validation
- **Metrics Tests**: MTTR calculation, remediation capacity, and reporting tables

See [tests/README.md](tests/README.md) for detailed test documentation.

## Requirements

### Python Dependencies
Core dependencies are listed in `requirements.txt`:
- `psycopg2-binary` - PostgreSQL adapter
- `supabase` - Supabase client
- `lxml` - XML parsing for Nessus files
- `python-dateutil` - Date/time handling
- `python-dotenv` - Environment variable management
- `pytest` - Testing framework
- `PyYAML` - YAML configuration parsing
- `jsonschema` - JSON schema validation

### System Requirements
- Python 3.8 or higher
- PostgreSQL 12+ or Supabase account
- 4GB RAM minimum
- 1GB free disk space

## Getting Help

- **Issues**: Report bugs or request features via [GitHub Issues](../../issues)
- **Discussions**: Ask questions or discuss ideas via [GitHub Discussions](../../discussions)
- **Documentation**: Check the `docs/` directory for detailed guides
- **Tests**: Run the test suite to verify your setup

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Metrics Pipeline Order

> **Note:** The remediation status resolver step (`etl/metrics/remediation_status_resolver.py`) must run first in the metrics pipeline before MTTR and other metrics are calculated. See `etl/metrics/README.md` for details.

1. Remediation Status Resolver (must run first)
2. MTTR Calculator
3. Metrics Generator
4. Reporting Tables Manager
