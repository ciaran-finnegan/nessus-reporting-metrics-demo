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

-- Drop the remediation_trends table if it exists and recreate it properly
DROP TABLE IF EXISTS remediation_trends CASCADE;

-- Create remediation_trends table
CREATE TABLE remediation_trends (
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

-- Grant permissions on the new table
GRANT ALL ON remediation_trends TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role; 