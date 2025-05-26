-- Fix the metrics_snapshots id column to auto-generate UUIDs
ALTER TABLE metrics_snapshots 
ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Make sure the column allows UUID generation
UPDATE metrics_snapshots SET id = gen_random_uuid() WHERE id IS NULL; 