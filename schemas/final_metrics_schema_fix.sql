-- Add missing columns to metrics_snapshots
ALTER TABLE metrics_snapshots 
ADD COLUMN IF NOT EXISTS snapshot_type VARCHAR(50) DEFAULT 'comprehensive',
ADD COLUMN IF NOT EXISTS snapshot_date TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Fix mttr_history table completely
ALTER TABLE mttr_history 
ALTER COLUMN value DROP NOT NULL,
ALTER COLUMN metric_type DROP NOT NULL;

-- Add the missing columns that the Python code expects
ALTER TABLE mttr_history 
ADD COLUMN IF NOT EXISTS overall_mttr NUMERIC(10,4),
ADD COLUMN IF NOT EXISTS by_risk_level JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS by_business_group JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS by_asset_type JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS remediated_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS introduced_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS calculation_method VARCHAR(50) DEFAULT 'database_rpc'; 