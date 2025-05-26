# Migration Guide: Time Series Schema

This guide explains how to migrate from the simple asset/vulnerability tables to the new time series schema with proper relationships and asset identity management.

## Overview

The new schema provides:
- **Proper asset identity management** with fingerprinting
- **True time series data** for vulnerability tracking
- **Scan session tracking** for audit trails
- **Asset change history** for compliance
- **Robust foreign key relationships** between entities
- **Performance optimised** with proper indexes and views

## Schema Changes

### Old Schema (Simple)
```sql
assets (id, asset_name, asset_ip, type, ...)
vulnerabilities (id, asset_name, vulnerability_name, ...)
```

### New Schema (Time Series)
```sql
scan_sessions (id, scan_name, scan_date, ...)
assets (id, current_hostname, current_ip_address, asset_fingerprint, ...)
asset_history (id, asset_id, scan_session_id, change_type, ...)
vulnerability_definitions (id, plugin_id, vulnerability_name, ...)
vulnerability_scans (id, asset_id, vulnerability_id, scan_session_id, ...)
```

## Migration Steps

### Step 1: Backup Current Data

Before migrating, export your current data:

```python
from supabase import create_client
import json

# Export current assets
assets = supabase.table('assets').select('*').execute()
with open('backup_assets.json', 'w') as f:
    json.dump(assets.data, f, indent=2)

# Export current vulnerabilities
vulns = supabase.table('vulnerabilities').select('*').execute()
with open('backup_vulnerabilities.json', 'w') as f:
    json.dump(vulns.data, f, indent=2)
```

### Step 2: Apply New Schema

Run the new schema in your Supabase SQL editor:

```sql
-- Copy and paste the contents of schemas/supabase_timeseries_schema.sql
```

**Note:** The new schema includes commented DROP statements. Uncomment these if you want to completely replace the old tables:

```sql
DROP TABLE IF EXISTS vulnerability_scans CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS scan_sessions CASCADE;
```

### Step 3: Migrate Existing Data

Use the migration script to transfer your old data:

```python
#!/usr/bin/env python3
"""
Migration script to transfer data from old schema to new time series schema
"""

import json
from datetime import datetime, timezone
from etl.loaders.supabase_timeseries_loader import SupabaseTimeSeriesLoader

def migrate_data():
    loader = SupabaseTimeSeriesLoader()
    
    # Create a migration scan session
    scan_session_id = loader.create_scan_session(
        scan_name="Data Migration",
        metadata={"migration": True, "source": "old_schema"}
    )
    
    # Load backed up assets
    with open('backup_assets.json', 'r') as f:
        old_assets = json.load(f)
    
    asset_mapping = {}  # Map old asset names to new asset IDs
    
    for old_asset in old_assets:
        # Convert old asset format to new format
        new_asset = {
            'Asset_Name': old_asset.get('asset_name', ''),
            'Asset_IP': old_asset.get('asset_ip', ''),
            'Type': old_asset.get('type', 'unknown'),
            'Operating_System': old_asset.get('operating_system'),
            # Add other fields as needed
        }
        
        # Upsert asset using new loader
        asset_id = loader.upsert_asset(new_asset)
        asset_mapping[old_asset['asset_name']] = asset_id
    
    # Load backed up vulnerabilities
    with open('backup_vulnerabilities.json', 'r') as f:
        old_vulns = json.load(f)
    
    for old_vuln in old_vulns:
        # Create vulnerability definition
        vuln_def_id = loader.upsert_vulnerability_definition({
            'Plugin_ID': old_vuln.get('plugin_id', 'unknown'),
            'Vulnerability_Name': old_vuln.get('vulnerability_name', ''),
            'CVSS_Score': old_vuln.get('cvss_score'),
            'Risk': old_vuln.get('risk'),
            # Add other fields as needed
        })
        
        # Find corresponding asset
        asset_name = old_vuln.get('asset_name', '')
        if asset_name in asset_mapping:
            asset_id = asset_mapping[asset_name]
            
            # Create vulnerability scan record
            loader.insert_vulnerability_scan(asset_id, vuln_def_id, {
                'Status': old_vuln.get('status', 'open'),
                'Severity': old_vuln.get('severity', 'Unknown'),
                'Port': old_vuln.get('port'),
                # Add other fields as needed
            })

if __name__ == "__main__":
    migrate_data()
```

### Step 4: Update ETL Pipeline

Replace your old loader with the new time series loader:

```python
# Old way
from etl.loaders.supabase_loader import SupabaseLoader
loader = SupabaseLoader()

# New way
from etl.loaders.supabase_timeseries_loader import SupabaseTimeSeriesLoader
loader = SupabaseTimeSeriesLoader()

# Create scan session before loading
scan_session_id = loader.create_scan_session(
    scan_name="Daily Nessus Scan",
    scan_file_path="/path/to/scan.nessus"
)

# Load data as before
loader.load_assets(assets)
loader.load_vulnerabilities(vulnerabilities)

# Update scan session with stats
loader.update_scan_session_stats(
    total_hosts=len(assets),
    total_vulnerabilities=len(vulnerabilities)
)
```

## Key Benefits

### 1. Asset Identity Persistence

Assets maintain their identity across scans even if hostname or IP changes:

```python
# First scan: hostname = "server01", IP = "192.168.1.100"
# Second scan: hostname = "server01-new", IP = "192.168.1.100"
# Result: Same asset ID, change recorded in asset_history
```

### 2. True Time Series Data

Each vulnerability finding is linked to a specific scan session:

```sql
-- Find all vulnerability scans for an asset over time
SELECT vs.scan_date, vs.severity, vs.status, ss.scan_name
FROM vulnerability_scans vs
JOIN scan_sessions ss ON vs.scan_session_id = ss.id
WHERE vs.asset_id = 'asset-uuid'
ORDER BY vs.scan_date;
```

### 3. Vulnerability Lifecycle Tracking

Track how vulnerabilities change over time:

```sql
-- Track vulnerability status changes
SELECT 
    vd.vulnerability_name,
    vs.scan_date,
    vs.status,
    vs.remediation_status
FROM vulnerability_scans vs
JOIN vulnerability_definitions vd ON vs.vulnerability_id = vd.id
WHERE vs.asset_id = 'asset-uuid'
  AND vd.plugin_id = '12345'
ORDER BY vs.scan_date;
```

### 4. Asset Change Tracking

Monitor asset changes for compliance:

```sql
-- View asset changes over time
SELECT 
    ah.change_type,
    ah.observed_at,
    ah.previous_values,
    ah.new_values,
    ss.scan_name
FROM asset_history ah
JOIN scan_sessions ss ON ah.scan_session_id = ss.id
WHERE ah.asset_id = 'asset-uuid'
ORDER BY ah.observed_at;
```

## Performance Considerations

The new schema includes comprehensive indexing:

- **Asset lookups** by hostname, IP, fingerprint
- **Vulnerability queries** by severity, status, dates
- **Time series queries** optimised for date ranges
- **Composite indexes** for common query patterns

## Views and Analytics

Use the built-in views for common queries:

```sql
-- Current vulnerability state
SELECT * FROM current_vulnerabilities 
WHERE severity IN ('Critical', 'High');

-- Asset summary with vulnerability counts
SELECT * FROM asset_summary 
ORDER BY critical_vulns DESC;

-- Vulnerability trends across the environment
SELECT * FROM vulnerability_trends 
WHERE affected_assets > 5;
```

## Rollback Plan

If you need to rollback:

1. Keep the old tables during migration (don't drop them)
2. Use the backup JSON files to restore data
3. Switch back to the old loader in your ETL pipeline

## Testing

After migration, run the comprehensive test:

```bash
python test_timeseries_etl.py
```

This will verify:
- ✅ ETL pipeline functionality
- ✅ Asset identity persistence
- ✅ Time series queries
- ✅ Data integrity

## Support

If you encounter issues during migration:

1. Check the logs for specific error messages
2. Verify your Supabase permissions include function execution
3. Ensure all required extensions are enabled
4. Test with a small dataset first

The new schema provides a robust foundation for vulnerability management with proper time series tracking and asset identity management. 