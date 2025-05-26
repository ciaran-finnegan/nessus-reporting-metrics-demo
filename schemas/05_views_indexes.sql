-- Views and Indexes for Performance and Convenience

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scan_sessions_date ON scan_sessions(scan_date);
CREATE INDEX IF NOT EXISTS idx_assets_fingerprint ON assets(asset_fingerprint);
CREATE INDEX IF NOT EXISTS idx_assets_active ON assets(is_active);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(current_hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(current_ip_address);
CREATE INDEX IF NOT EXISTS idx_vuln_scans_asset ON vulnerability_scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_vuln_scans_status ON vulnerability_scans(status);
CREATE INDEX IF NOT EXISTS idx_vuln_scans_severity ON vulnerability_scans(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_scans_scan_date ON vulnerability_scans(scan_date);
CREATE INDEX IF NOT EXISTS idx_metrics_snapshots_created ON metrics_snapshots(created_at);
CREATE INDEX IF NOT EXISTS idx_metric_values_snapshot ON metric_values(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_mttr_history_calculation_date ON mttr_history(calculation_date);

-- Current vulnerability state view
CREATE OR REPLACE VIEW current_vulnerabilities AS
WITH latest_scans AS (
    SELECT 
        asset_id,
        vulnerability_id,
        MAX(scan_date) as latest_scan_date
    FROM vulnerability_scans
    GROUP BY asset_id, vulnerability_id
)
SELECT 
    vs.*,
    a.asset_class,
    a.current_hostname,
    a.current_ip_address,
    a.asset_type,
    a.criticality as asset_criticality,
    vd.vulnerability_name,
    vd.cvss_base_score,
    vd.risk_factor,
    vd.family as vulnerability_family
FROM vulnerability_scans vs
JOIN latest_scans ls ON vs.asset_id = ls.asset_id 
    AND vs.vulnerability_id = ls.vulnerability_id 
    AND vs.scan_date = ls.latest_scan_date
JOIN assets a ON vs.asset_id = a.id
JOIN vulnerability_definitions vd ON vs.vulnerability_id = vd.id
WHERE a.is_active = true;

-- Asset summary view
CREATE OR REPLACE VIEW asset_summary AS
SELECT 
    a.id,
    a.asset_class,
    a.current_hostname,
    a.current_ip_address,
    a.asset_type,
    a.criticality,
    a.last_seen,
    COUNT(cv.id) as total_vulnerabilities,
    COUNT(CASE WHEN cv.severity = 'Critical' THEN 1 END) as critical_vulns,
    COUNT(CASE WHEN cv.severity = 'High' THEN 1 END) as high_vulns,
    COUNT(CASE WHEN cv.severity = 'Medium' THEN 1 END) as medium_vulns,
    COUNT(CASE WHEN cv.severity = 'Low' THEN 1 END) as low_vulns,
    COUNT(CASE WHEN cv.remediation_status = 'open' THEN 1 END) as open_vulns
FROM assets a
LEFT JOIN current_vulnerabilities cv ON a.id = cv.asset_id
WHERE a.is_active = true
GROUP BY a.id, a.asset_class, a.current_hostname, a.current_ip_address, a.asset_type, a.criticality, a.last_seen;

-- Vulnerability trends view
CREATE OR REPLACE VIEW vulnerability_trends AS
SELECT 
    vd.vulnerability_name,
    vd.plugin_id,
    vd.risk_factor,
    vd.cvss_base_score,
    COUNT(DISTINCT vs.asset_id) as affected_assets,
    MIN(vs.first_seen) as first_discovered,
    MAX(vs.last_seen) as last_observed,
    COUNT(CASE WHEN vs.remediation_status = 'open' THEN 1 END) as currently_open,
    COUNT(CASE WHEN vs.remediation_status = 'fixed' THEN 1 END) as fixed_instances
FROM vulnerability_definitions vd
JOIN vulnerability_scans vs ON vd.id = vs.vulnerability_id
JOIN assets a ON vs.asset_id = a.id
WHERE a.is_active = true
GROUP BY vd.id, vd.vulnerability_name, vd.plugin_id, vd.risk_factor, vd.cvss_base_score;

-- Latest metrics view
CREATE OR REPLACE VIEW latest_metrics AS
SELECT 
    ms.created_at as snapshot_date,
    ms.metrics_data->>'timestamp' as calculation_timestamp,
    (ms.metrics_data->'remediation_capacity'->>'total_vulnerabilities')::INTEGER as total_vulnerabilities,
    (ms.metrics_data->'remediation_capacity'->>'open_vulnerabilities')::INTEGER as open_vulnerabilities,
    (ms.metrics_data->'remediation_capacity'->>'remediation_rate_percentage')::DECIMAL as remediation_rate,
    (ms.metrics_data->'daily_remediation'->>'average_daily_remediation')::DECIMAL as daily_remediation_rate,
    (ms.metrics_data->'campaign_coverage'->>'coverage_percentage')::DECIMAL as campaign_coverage,
    (ms.metrics_data->'asset_coverage'->>'coverage_percentage')::DECIMAL as asset_coverage
FROM metrics_snapshots ms
WHERE ms.id = (
    SELECT id FROM metrics_snapshots 
    ORDER BY created_at DESC 
    LIMIT 1
); 