-- First, drop the dependent view temporarily
DROP VIEW IF EXISTS latest_metrics_summary;

-- Add missing columns without changing existing ones
ALTER TABLE metrics_snapshots 
ADD COLUMN IF NOT EXISTS snapshot_date TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Fix mttr_history table structure (make metric_type nullable and add missing columns)
ALTER TABLE mttr_history 
ALTER COLUMN metric_type DROP NOT NULL;

ALTER TABLE mttr_history 
ADD COLUMN IF NOT EXISTS overall_mttr NUMERIC(10,4),
ADD COLUMN IF NOT EXISTS by_risk_level JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS by_business_group JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS by_asset_type JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS remediated_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS introduced_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS calculation_method VARCHAR(50) DEFAULT 'database_rpc';

-- Recreate the view if it existed (you may need to adjust this based on your actual view definition)
CREATE OR REPLACE VIEW latest_metrics_summary AS
SELECT 
  ms.id as snapshot_id,
  ms.created_at as snapshot_time,
  ms.snapshot_date,
  mv.metric_name,
  mv.value,
  mv.unit,
  mv.breakdown,
  mv.metadata
FROM metrics_snapshots ms
JOIN metric_values mv ON ms.id::text = mv.snapshot_id::text
WHERE ms.id::text = (
  SELECT ms2.id::text 
  FROM metrics_snapshots ms2 
  ORDER BY ms2.created_at DESC 
  LIMIT 1
); 