# Asset Types Reference

This document provides a comprehensive reference for asset types, validation, and categorisation used in the Nessus Reporting Metrics system.

## Table of Contents
- [Overview](#overview)
- [Asset Type Categories](#asset-type-categories)
- [Cloud Provider Resources](#cloud-provider-resources)
- [Validation System](#validation-system)
- [Usage Examples](#usage-examples)
- [Schema Definition](#schema-definition)

## Overview

This project uses a standardised schema for categorising assets, based on Vulcan Cyber ExposureOS™ documentation. The asset type system ensures consistent classification across different data sources and provides a foundation for vulnerability management and risk assessment.

## Asset Type Categories

### 1. Host
Physical or virtual machines, network devices, IoT, and related endpoints.

**Permitted Values:**
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

**Examples:**
```json
{
  "type": "Host",
  "subtype": "Server",
  "name": "web-server-01",
  "ip": "192.168.1.100"
}
```

### 2. Code Project
Software codebases, repositories, and related development projects.

**Permitted Values:**
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

**Examples:**
```json
{
  "type": "Code Project",
  "subtype": "GitHub Repository",
  "name": "my-web-app",
  "url": "https://github.com/org/my-web-app"
}
```

### 3. Website
Web-based applications or services accessible via the internet.

**Permitted Values:**
- Web Application
- Internet Service
- Main Domain
- Base URL
- Subdomain
- API Endpoint

**Examples:**
```json
{
  "type": "Website",
  "subtype": "Web Application",
  "name": "company-portal",
  "url": "https://portal.company.com"
}
```

### 4. Image
Container images, running containers, and registries.

**Permitted Values:**
- Container Image
- Container
- Registry
- Docker Image
- OCI Image
- Virtual Machine Image
- Base Image
- Application Image

**Examples:**
```json
{
  "type": "Image",
  "subtype": "Docker Image",
  "name": "nginx:latest",
  "registry": "docker.io"
}
```

### 5. Cloud Resource
Cloud provider resources and services (see detailed breakdown below).

## Cloud Provider Resources

### AWS Resources

**Compute & Storage:**
- EC2 Instance
- Lambda Function
- S3 Bucket
- Elastic File System
- Lightsail Instance

**Database:**
- RDS Instance
- DynamoDB Table
- Elasticache Cluster
- Redshift Cluster

**Networking:**
- VPC
- Subnet
- Security Group
- Route Table
- Internet Gateway
- NAT Gateway
- Elastic Load Balancer

**Security & Identity:**
- IAM User
- IAM Role
- IAM Policy
- KMS Key
- Secrets Manager Secret
- Parameter Store Parameter
- GuardDuty Detector
- Security Hub

**Application Services:**
- CloudFront Distribution
- SNS Topic
- SQS Queue
- API Gateway
- Step Function

**Analytics & ML:**
- Glue Job
- Athena Workgroup

**DevOps:**
- CodeBuild Project
- CodePipeline Pipeline
- ECR Repository

**Container Services:**
- ECS Cluster
- EKS Cluster

**Monitoring:**
- CloudWatch Alarm
- CloudTrail Trail

**Backup & Archive:**
- Backup Vault

**Management:**
- Organization
- Account
- Region

**Other:**
- Other (for resources not explicitly listed)

### Azure Resources

**Compute:**
- Virtual Machine
- VM Scale Set
- App Service
- Function App

**Storage:**
- Storage Account
- Blob Storage
- File Storage

**Database:**
- SQL Database
- Cosmos DB
- PostgreSQL Server
- MySQL Server
- MariaDB Server

**Networking:**
- Virtual Network
- Subnet
- Public IP Address
- Network Security Group
- Application Gateway
- Load Balancer
- Route Table
- Firewall
- Bastion Host

**Security & Identity:**
- Key Vault
- Managed Identity
- Policy Assignment
- Role Assignment

**Integration:**
- Event Hub
- Service Bus
- Logic App

**Analytics & AI:**
- Synapse Workspace
- Machine Learning Workspace
- Databricks Workspace
- Stream Analytics Job

**DevOps:**
- Automation Account
- Container Registry

**Web & Mobile:**
- API Management
- CDN Profile
- Search Service

**Management:**
- Resource Group
- Subscription
- Log Analytics Workspace
- Alert Rule
- App Configuration

**Container Services:**
- Kubernetes Service (AKS)

**Backup:**
- Backup Vault

**DNS:**
- DNS Zone

**Other:**
- Other (for resources not explicitly listed)

### GCP Resources

**Compute:**
- Compute Engine VM
- Cloud Function
- Cloud Run Service
- App Engine App

**Storage:**
- Cloud Storage Bucket

**Database:**
- Cloud SQL Instance
- Spanner Instance
- BigQuery Dataset

**Messaging:**
- Pub/Sub Topic
- Pub/Sub Subscription

**Networking:**
- VPC Network
- Subnet
- Firewall Rule
- Load Balancer
- Cloud DNS Zone

**Container Services:**
- GKE Cluster
- GKE Node Pool

**Security & Identity:**
- Service Account
- IAM Policy
- KMS KeyRing
- KMS CryptoKey
- Secret Manager Secret

**Analytics & ML:**
- Dataflow Job
- Dataproc Cluster

**DevOps:**
- Cloud Scheduler Job
- Cloud Tasks Queue
- Cloud Endpoints Service

**Management:**
- Project
- Organization
- Folder
- Region

**Other:**
- Other (for resources not explicitly listed)

## Validation System

### Validation Script

The system includes a validation script (`assets/validate_asset_type.py`) to ensure asset definitions comply with the permitted values.

#### Installation
```bash
pip install pyyaml
```

#### Usage
```bash
python assets/validate_asset_type.py asset.json assets/asset_types.yaml
```

### Validation Rules

1. **Type Validation**: Asset `type` must be one of the five permitted categories
2. **Subtype Validation**: Asset `subtype` must be from the permitted values for that type
3. **Provider Validation**: For Cloud Resources, `provider` must be AWS, Azure, or GCP
4. **Cloud Resource Validation**: Cloud resource `subtype` must be valid for the specified provider

### Example Validation

**Valid Asset:**
```json
{
  "type": "Cloud Resource",
  "provider": "AWS",
  "subtype": "EC2 Instance",
  "name": "web-server-prod",
  "region": "us-east-1"
}
```

**Invalid Asset (will fail validation):**
```json
{
  "type": "Cloud Resource",
  "provider": "AWS",
  "subtype": "Invalid Resource Type"
}
```

## Usage Examples

### Basic Asset Definition
```json
{
  "type": "Host",
  "subtype": "Server",
  "name": "database-server-01",
  "ip": "10.0.1.50",
  "os": "Ubuntu 20.04",
  "environment": "production"
}
```

### Cloud Resource with Metadata
```json
{
  "type": "Cloud Resource",
  "provider": "AWS",
  "subtype": "RDS Instance",
  "name": "prod-database",
  "region": "us-west-2",
  "instance_id": "db-abc123def456",
  "tags": {
    "Environment": "Production",
    "Team": "Backend",
    "CostCenter": "Engineering"
  }
}
```

### Container Image Asset
```json
{
  "type": "Image",
  "subtype": "Docker Image",
  "name": "my-app:v1.2.3",
  "registry": "registry.company.com",
  "base_image": "node:16-alpine",
  "scan_date": "2024-01-15T10:30:00Z"
}
```

### Code Repository Asset
```json
{
  "type": "Code Project",
  "subtype": "GitHub Repository",
  "name": "payment-service",
  "url": "https://github.com/company/payment-service",
  "language": "Python",
  "team": "Payments"
}
```

## Schema Definition

The complete schema is defined in `assets/asset_types.yaml`:

```yaml
- type: Host
  permitted_values:
    - Server
    - Workstation
    - NAS Device
    # ... (full list)

- type: Code Project
  permitted_values:
    - Repository
    - SAST Project
    # ... (full list)

- type: Website
  permitted_values:
    - Web Application
    - Internet Service
    # ... (full list)

- type: Image
  permitted_values:
    - Container Image
    - Container
    # ... (full list)

- type: Cloud Resource
  providers:
    - provider: AWS
      permitted_values:
        - S3 Bucket
        - EC2 Instance
        # ... (full AWS list)
    - provider: Azure
      permitted_values:
        - Storage Account
        - Virtual Machine
        # ... (full Azure list)
    - provider: GCP
      permitted_values:
        - Cloud Storage Bucket
        - Compute Engine VM
        # ... (full GCP list)
```

## Best Practices

### Asset Naming
- Use descriptive, consistent naming conventions
- Include environment indicators (prod, staging, dev)
- Use kebab-case for multi-word names

### Metadata
- Include relevant tags for categorisation
- Add ownership and team information
- Include cost center or business unit data

### Validation
- Always validate assets before importing
- Use the validation script in CI/CD pipelines
- Regularly review and update asset definitions

### Documentation
- Document custom asset properties
- Maintain asset inventory documentation
- Keep asset type definitions up to date

## Integration with ETL Pipeline

The asset type system integrates with the ETL pipeline to:

1. **Classify Assets**: Automatically categorise assets from Nessus scans
2. **Validate Data**: Ensure imported assets conform to the schema
3. **Enrich Metadata**: Add standardised asset type information
4. **Enable Reporting**: Support asset-based vulnerability reporting

For more information on ETL integration, see the [ETL Pipeline Guide](ETL_GUIDE.md).

## Contributing

To add new asset types or modify existing ones:

1. Update `assets/asset_types.yaml`
2. Update this documentation
3. Test with the validation script
4. Update any dependent code or schemas
5. Submit a pull request with the changes

## Support

For questions about asset types or validation:
- Check the [main README](../README.md)
- Review the [ETL Pipeline Guide](ETL_GUIDE.md)
- Open an issue in the project repository 