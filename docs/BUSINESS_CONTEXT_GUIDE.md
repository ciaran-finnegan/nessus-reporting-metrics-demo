# Business Groups and Asset Tags Guide

This guide explains how to use Business Groups and Asset Tags to organise your assets and prioritise vulnerability remediation based on business context, following Vulcan Cyber's proven approach.

## Table of Contents
- [Overview](#overview)
- [Business Groups](#business-groups)
- [Asset Tags](#asset-tags)
- [Implementation](#implementation)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)

## Overview

Business Groups and Asset Tags bring your organisation's business context into the vulnerability management platform, enabling:

- **Contextual Prioritisation**: Focus on vulnerabilities that matter most to your business
- **Organisational Alignment**: Mirror your company structure for better reporting
- **Dynamic Classification**: Automatically categorise assets based on rules
- **Risk-Based Remediation**: Prioritise fixes based on asset criticality and business impact

### Key Differences

| Feature | Asset Tags | Business Groups |
|---------|------------|-----------------|
| Purpose | Label and filter assets | Organise assets into business units |
| Structure | Flat (no hierarchy) | Hierarchical (parent/child) |
| Assignment | Many tags per asset | Many groups per asset |
| Rules | Dynamic or static | Static assignment |
| Impact | Filtering and criticality | Reporting and prioritisation |

## Business Groups

Business Groups represent collections of assets organised by business context, such as departments, geographic regions, or environments.

### Creating Business Groups

```python
from etl.loaders import BusinessContextManager

# Initialize the manager
context_manager = BusinessContextManager(supabase_client)

# Create a root business group
geographic_id = context_manager.create_business_group(
    name="Geographic Regions",
    description="Assets organised by location"
)

# Create child groups
emea_id = context_manager.create_business_group(
    name="EMEA",
    parent_id=geographic_id,
    description="Europe, Middle East, and Africa",
    color="#0066CC"
)
```

### Hierarchical Structure Example

```
Geographic Regions/
├── EMEA/
│   ├── UK/
│   ├── Germany/
│   └── France/
├── APAC/
│   ├── Australia/
│   ├── Japan/
│   └── Singapore/
└── Americas/
    ├── USA/
    ├── Canada/
    └── Brazil/

Departments/
├── Finance/
├── HR/
├── IT/
│   ├── Infrastructure/
│   ├── Security/
│   └── Applications/
└── R&D/

Environments/
├── Production/
├── Staging/
├── Development/
└── Test/
```

### Assigning Assets to Business Groups

```python
# Get asset IDs (example)
asset_ids = ["asset-uuid-1", "asset-uuid-2", "asset-uuid-3"]

# Assign to business group
context_manager.assign_assets_to_business_group(
    asset_ids=asset_ids,
    business_group_id=emea_id,
    assigned_by="admin@company.com"
)
```

## Asset Tags

Asset Tags are labels that help categorise and filter assets. They can be:
- **Static**: Manually applied tags
- **Imported**: Tags from external scanners
- **Dynamic**: Automatically applied based on rules

### Creating Tags

#### Static Tags
```python
# Create a manual tag
tag_id = context_manager.create_tag(
    name="#critical-infrastructure",
    tag_type="manual",
    description="Critical business infrastructure",
    criticality_score=5,
    color="#FF0000",
    is_favorite=True
)
```

#### Dynamic Tags
```python
# Create a dynamic tag for external-facing assets
external_tag_id = context_manager.create_tag(
    name="#external-facing",
    tag_type="dynamic",
    description="Internet-exposed assets",
    criticality_score=5,
    color="#FF0000",
    rule_definition={
        "type": "external_facing"
    }
)

# Create a tag for assets with critical vulnerabilities
critical_vuln_tag_id = context_manager.create_tag(
    name="#critical-vulnerabilities",
    tag_type="dynamic",
    description="Assets with critical vulnerabilities",
    criticality_score=4,
    rule_definition={
        "type": "vulnerability_exists",
        "severity": ["Critical"]
    }
)
```

### Dynamic Tag Rule Types

| Rule Type | Description | Example Configuration |
|-----------|-------------|----------------------|
| `ip_range` | Match assets in IP ranges | `{"type": "ip_range", "ranges": ["10.0.0.0/8"]}` |
| `asset_name_contains` | Match asset names by pattern | `{"type": "asset_name_contains", "patterns": ["prod-*", "*-db"]}` |
| `external_facing` | Match external assets | `{"type": "external_facing"}` |
| `vulnerability_exists` | Match assets with specific vulns | `{"type": "vulnerability_exists", "severity": ["Critical", "High"]}` |
| `operating_system` | Match by OS pattern | `{"type": "operating_system", "os_patterns": ["*Windows*"]}` |
| `asset_type` | Match by asset type | `{"type": "asset_type", "asset_class": "Host", "asset_types": ["Server"]}` |
| `cloud_provider` | Match cloud assets | `{"type": "cloud_provider", "providers": ["AWS", "Azure"]}` |

## Implementation

### Database Schema

The implementation includes four new tables:
- `business_groups`: Hierarchical business group structure
- `asset_tags`: Tag definitions and rules
- `asset_business_groups`: Asset to business group mappings
- `asset_tag_assignments`: Asset to tag mappings

### Loading Data with Business Context

```python
from etl.loaders import SupabaseTimeSeriesLoader
import yaml

# Load configuration
with open('config/business_rules.yaml', 'r') as f:
    business_rules = yaml.safe_load(f)

# Initialize loader
loader = SupabaseTimeSeriesLoader()

# Load with business context
result = loader.load_with_business_context(
    assets=assets,
    vulnerabilities=vulnerabilities,
    business_rules=business_rules,
    apply_dynamic_tags=True
)
```

## Configuration

### Business Rules Configuration (YAML)

Create a `config/business_rules.yaml` file:

```yaml
business_groups:
  - name: "Production"
    parent: "Environments"
    rules:
      - type: "tag_match"
        tags: ["production", "prod"]
      - type: "hostname_pattern"
        patterns: ["prod-*", "*-prod"]

dynamic_tags:
  - name: "#external-facing"
    type: "external_facing"
    criticality_score: 5
    color: "#FF0000"
    
  - name: "#databases"
    type: "asset_name_contains"
    criticality_score: 4
    rule:
      patterns: ["*-db-*", "*-sql-*"]
```

## Usage Examples

### Querying Assets by Business Group

```sql
-- Get vulnerability summary by business group
SELECT * FROM vulnerability_summary_by_business_group
WHERE business_group_name = 'Production'
ORDER BY risk_score DESC;

-- Get assets with their business context
SELECT 
    asset_fingerprint,
    current_hostname,
    business_groups,
    tags,
    effective_criticality
FROM assets_with_context
WHERE 'Production' = ANY(business_groups)
AND 'external-facing' = ANY(tags);
```

### Creating Default Structure

```python
# Create default business groups and tags
context_manager = BusinessContextManager(supabase_client)
context_manager.create_default_business_groups()
context_manager.create_default_dynamic_tags()
```

### Applying Dynamic Tags After Scan

```python
# After loading new scan data
context_manager.apply_dynamic_tags(scan_session_id)
```

## Best Practices

### Business Group Structure
1. **Mirror Your Organisation**: Create groups that reflect your actual structure
2. **Keep It Simple**: Start with major divisions, add detail as needed
3. **Use Meaningful Names**: Make groups self-explanatory
4. **Leverage Hierarchy**: Use parent/child relationships for drill-down reporting

### Asset Tags
1. **Naming Convention**: Use # prefix for tags (e.g., #production)
2. **Criticality Scores**: Assign scores 1-5 based on business impact
3. **Favorite Tags**: Mark frequently used tags as favorites
4. **Dynamic Rules**: Prefer dynamic tags over manual for consistency

### Performance
1. **Batch Operations**: Assign multiple assets at once
2. **Index Usage**: The schema includes optimised indexes
3. **Rule Efficiency**: Keep dynamic rules simple and specific
4. **Regular Review**: Periodically review and update rules

### Integration
1. **Import Tags**: Leverage tags from scanners
2. **API Usage**: Use views for reporting queries
3. **Automation**: Set up automatic assignment rules
4. **Monitoring**: Track tag and group coverage

## Example: Complete Setup

```python
import yaml
from etl.loaders import SupabaseTimeSeriesLoader, BusinessContextManager

# 1. Initialize
loader = SupabaseTimeSeriesLoader()
context_manager = BusinessContextManager(loader.client)

# 2. Create structure
context_manager.create_default_business_groups()
context_manager.create_default_dynamic_tags()

# 3. Load business rules
with open('config/business_rules.yaml', 'r') as f:
    business_rules = yaml.safe_load(f)

# 4. Process scan with context
scan_session_id = loader.create_scan_session(
    scan_name="Weekly Vulnerability Scan",
    scan_file_path="scan.nessus"
)

# Extract and transform data
assets = extractor.extract_assets()
vulnerabilities = extractor.extract_vulnerabilities()

# Load with business context
result = loader.load_with_business_context(
    assets=assets,
    vulnerabilities=vulnerabilities,
    business_rules=business_rules
)

# 5. Query results
stats = loader.client.table('vulnerability_summary_by_business_group').select('*').execute()
for group in stats.data:
    print(f"{group['business_group_name']}: {group['critical_vulns']} critical vulnerabilities")
```

This implementation provides enterprise-grade asset organisation and vulnerability prioritisation capabilities, enabling effective risk-based remediation strategies aligned with your business needs. 