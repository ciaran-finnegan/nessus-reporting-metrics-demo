-- Update MTTR functions to ensure they work with existing schema
-- These functions provide database-level MTTR calculations

-- Function: Calculate overall MTTR across all remediated vulnerabilities
CREATE OR REPLACE FUNCTION calculate_mttr_overall()
RETURNS TABLE (mttr_days NUMERIC) AS $$
BEGIN
    RETURN QUERY
    SELECT COALESCE(
        AVG(EXTRACT(EPOCH FROM (vs.remediation_date - vs.first_seen)) / 86400)::NUMERIC, 
        30.0
    ) as mttr_days
    FROM vulnerability_scans vs
    WHERE vs.remediation_status = 'fixed' 
      AND vs.remediation_date IS NOT NULL 
      AND vs.first_seen IS NOT NULL;
END;
$$ LANGUAGE plpgsql;

-- Function: Calculate MTTR by risk level (severity)
CREATE OR REPLACE FUNCTION calculate_ 