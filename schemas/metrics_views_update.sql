-- Create or update views after tables are properly set up

-- Update the existing latest_metrics view to be compatible
DROP VIEW IF EXISTS latest_metrics;
CREATE OR REPLACE VIEW latest_metrics_summary AS
SELECT 
    ms.created_at as snapshot_date,
    ms.metrics_data->>'timestamp' as calculation_timestamp,
    (ms.metrics_data->'remediation_capacity'->>'total_vulnerabilities')::INTEGER as total_vulnerabilities,
    (ms.metrics_data->'remediation_capacity'->>'open_vulnerabilities')::INTEGER as open_vulnerabilities,
    (ms.metrics_data->'remediation_capacity'->>'remediation_rate_percentage')::DECIMAL as remediation_rate,
    (ms.metrics_data->'daily_remediation'->>'average_daily_remediation')::DECIMAL as daily_remediation_rate,
    (ms.metrics_data->'campaign_coverage'->>'coverage_percentage')::DECIMAL as campaign_coverage,
    (ms.metrics_data->'asset_coverage'->>'coverage_percentage')::DECIMAL as asset_coverage,
    ms.metrics_data->'vulnerability_trends'->'top_vulnerabilities' as top_vulnerabilities
FROM metrics_snapshots ms
WHERE ms.id = (
    SELECT id FROM metrics_snapshots 
    ORDER BY created_at DESC 
    LIMIT 1
);

-- Create MTTR Trends View compatible with existing structure
CREATE OR REPLACE VIEW mttr_trends AS
SELECT 
    mh.calculation_date::DATE as date,
    mh.overall_mttr_days,
    (mh.mttr_by_risk_level->>'Critical')::DECIMAL as critical_mttr,
    (mh.mttr_by_risk_level->>'High')::DECIMAL as high_mttr,
    (mh.mttr_by_risk_level->>'Medium')::DECIMAL as medium_mttr,
    (mh.mttr_by_risk_level->>'Low')::DECIMAL as low_mttr,
    mh.remediated_vulnerabilities_count,
    mh.total_vulnerabilities_count
FROM mttr_history mh
WHERE mh.calculation_date IS NOT NULL
ORDER BY mh.calculation_date;

-- Create Remediation Performance View
CREATE OR REPLACE VIEW remediation_performance AS
SELECT 
    rt.trend_date,
    rt.new_vulnerabilities,
    rt.remediated_vulnerabilities,
    rt.total_open_vulnerabilities,
    rt.remediation_rate_percentage,
    rt.mttr_days,
    rt.assets_scanned,
    rt.active_assets,
    LAG(rt.total_open_vulnerabilities) OVER (ORDER BY rt.trend_date) as previous_open,
    rt.total_open_vulnerabilities - LAG(rt.total_open_vulnerabilities) OVER (ORDER BY rt.trend_date) as net_change
FROM remediation_trends rt
ORDER BY rt.trend_date; 