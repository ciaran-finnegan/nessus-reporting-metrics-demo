-- Update existing metrics tables to match the Python code expectations
-- This adds missing columns and ensures compatibility

-- Add missing columns to metrics_snapshots table
ALTER TABLE metrics_snapshots 
ADD COLUMN IF NOT EXISTS metrics_data JSONB DEFAULT '{}';

-- Add missing columns to mttr_history table  
ALTER TABLE mttr_history
ADD COLUMN IF NOT EXISTS calculation_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
ADD COLUMN IF NOT EXISTS overall_mttr_days NUMERIC(10,2),
ADD COLUMN IF NOT EXISTS mttr_by_risk_level JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS mttr_by_business_group JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS mttr_by_asset_type JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS remediated_vulnerabilities_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_vulnerabilities_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS calculation_method VARCHAR(100) DEFAULT 'database_rpc';

-- Create remediation_trends table if it doesn't exist
CREATE TABLE IF NOT EXISTS remediation_trends (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trend_date DATE NOT NULL,
    new_vulnerabilities INTEGER DEFAULT 0,
    remediated_vulnerabilities INTEGER DEFAULT 0,
    total_open_vulnerabilities INTEGER DEFAULT 0,
    critical_open INTEGER DEFAULT 0,
    high_open INTEGER DEFAULT 0,
    medium_open INTEGER DEFAULT 0,
    low_open INTEGER DEFAULT 0,
    remediation_rate_percentage DECIMAL(5,2) DEFAULT 0.0,
    mttr_days DECIMAL(10,2),
    assets_scanned INTEGER DEFAULT 0,
    active_assets INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_trend_date UNIQUE (trend_date)
);

-- Add missing indexes
CREATE INDEX IF NOT EXISTS idx_metrics_snapshots_data ON metrics_snapshots USING GIN(metrics_data);
CREATE INDEX IF NOT EXISTS idx_mttr_history_calculation_date ON mttr_history(calculation_date);
CREATE INDEX IF NOT EXISTS idx_mttr_history_overall ON mttr_history(overall_mttr_days);
CREATE INDEX IF NOT EXISTS idx_remediation_trends_date ON remediation_trends(trend_date);
CREATE INDEX IF NOT EXISTS idx_remediation_trends_rate ON remediation_trends(remediation_rate_percentage);

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

-- Grant permissions
GRANT ALL ON remediation_trends TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role; 