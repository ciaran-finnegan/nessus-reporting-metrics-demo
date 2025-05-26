-- Data Cleanup Utility
-- Use this to completely clear all data while preserving schema

-- Clear all scan data (preserves schema)
DELETE FROM vulnerability_scans;
DELETE FROM scan_sessions;
DELETE FROM asset_history;
DELETE FROM metrics_snapshots;
DELETE FROM metric_values;
DELETE FROM mttr_history;
DELETE FROM remediation_trends;

-- Reset assets to clean state
UPDATE assets SET 
    is_active = false, 
    last_seen = '1970-01-01'::timestamp;

-- Clear business context (optional)
-- DELETE FROM asset_business_groups;
-- DELETE FROM asset_tag_assignments;

-- Reset sequences (if needed)
-- SELECT setval(pg_get_serial_sequence('table_name', 'id'), 1, false);

-- 