-- Fix metrics_snapshots table to match Python code expectations
ALTER TABLE metrics_snapshots 
ADD COLUMN IF NOT EXISTS snapshot_date TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Update the metrics_snapshots table structure to match Python expectations
ALTER TABLE metrics_snapshots 
ALTER COLUMN id TYPE UUID USING gen_random_uuid(),
ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Fix mttr_history table structure
ALTER TABLE mttr_history 
ALTER COLUMN metric_type DROP NOT NULL,
ADD COLUMN IF NOT EXISTS overall_mttr NUMERIC(10,4),
ADD COLUMN IF NOT EXISTS by_risk_level JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS by_business_group JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS by_asset_type JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS remediated_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS introduced_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS calculation_method VARCHAR(50) DEFAULT 'database_rpc'; 