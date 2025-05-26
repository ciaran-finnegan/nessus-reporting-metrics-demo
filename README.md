# nessus-reporting-metrics-demo
Generate vulnerability metrics from Nessus data

# High Level System Design

A simple proof of concept which implements a series of python scripts to peform extract, transform and load services.

- Extract data from a source, in this case a Nessus file
- Transform data by mapping fields to the field names in the proposed schema
- Load transformed data into time series tables in a database (e.g. SQLite, or PostGres)
- Generate additional table data such as metrics
- Implement a simple API that enables a Web Application to consume the metric data for visualisation on dashboards

## System Components

## Sequence Diagram

# Data Model

## Vulnerabilty Schema
to be completed

## Asset Schema
to be completed

## Asset Category Schema
to be completed

## Organisational Groups Schema
to be completed

## Business Application Groups Schema
to be completed

## Relationships
to be completed

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
