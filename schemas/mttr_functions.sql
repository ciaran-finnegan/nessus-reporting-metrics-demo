-- MTTR (Mean Time To Remediate) Calculation Functions
-- These functions provide database-level MTTR calculations for vulnerability management

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
CREATE OR REPLACE FUNCTION calculate_mttr_by_risk_level()
RETURNS TABLE (risk_level VARCHAR(50), mttr_days NUMERIC) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        vs.severity as risk_level,
        COALESCE(
            AVG(EXTRACT(EPOCH FROM (vs.remediation_date - vs.first_seen)) / 86400)::NUMERIC,
            CASE vs.severity
                WHEN 'Critical' THEN 7.0
                WHEN 'High' THEN 15.0
                WHEN 'Medium' THEN 30.0
                WHEN 'Low' THEN 90.0
                ELSE 30.0
            END
        ) as mttr_days
    FROM vulnerability_scans vs
    WHERE vs.remediation_status = 'fixed' 
      AND vs.remediation_date IS NOT NULL 
      AND vs.first_seen IS NOT NULL
    GROUP BY vs.severity
    
    UNION ALL
    
    -- Include risk levels with no remediated vulnerabilities (fallback values)
    SELECT 
        unnest(ARRAY['Critical', 'High', 'Medium', 'Low']) as risk_level,
        unnest(ARRAY[7.0, 15.0, 30.0, 90.0]) as mttr_days
    WHERE NOT EXISTS (
        SELECT 1 FROM vulnerability_scans 
        WHERE remediation_status = 'fixed' 
          AND remediation_date IS NOT NULL
    );
END;
$$ LANGUAGE plpgsql;

-- Function: Calculate MTTR by business group
CREATE OR REPLACE FUNCTION calculate_mttr_by_business_group()
RETURNS TABLE (business_group VARCHAR(255), mttr_days NUMERIC) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COALESCE(bg_name.name, 'Unassigned') as business_group,
        COALESCE(
            AVG(EXTRACT(EPOCH FROM (vs.remediation_date - vs.first_seen)) / 86400)::NUMERIC,
            30.0
        ) as mttr_days
    FROM vulnerability_scans vs
    JOIN assets a ON vs.asset_id = a.id
    LEFT JOIN (
        SELECT 
            a.id as asset_id,
            unnest(a.business_groups) as name
        FROM assets a
        WHERE array_length(a.business_groups, 1) > 0
    ) bg_name ON a.id = bg_name.asset_id
    WHERE vs.remediation_status = 'fixed' 
      AND vs.remediation_date IS NOT NULL 
      AND vs.first_seen IS NOT NULL
    GROUP BY bg_name.name
    
    UNION ALL
    
    -- Fallback for when no remediated vulnerabilities exist
    SELECT 
        'Default Group'::VARCHAR(255) as business_group,
        30.0::NUMERIC as mttr_days
    WHERE NOT EXISTS (
        SELECT 1 FROM vulnerability_scans 
        WHERE remediation_status = 'fixed' 
          AND remediation_date IS NOT NULL
    );
END;
$$ LANGUAGE plpgsql;

-- Function: Calculate MTTR by asset type
CREATE OR REPLACE FUNCTION calculate_mttr_by_asset_type()
RETURNS TABLE (asset_type VARCHAR(100), mttr_days NUMERIC) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.asset_type,
        COALESCE(
            AVG(EXTRACT(EPOCH FROM (vs.remediation_date - vs.first_seen)) / 86400)::NUMERIC,
            CASE 
                WHEN a.asset_type IN ('server', 'host') THEN 21.0
                WHEN a.asset_type IN ('workstation', 'laptop', 'desktop') THEN 14.0
                ELSE 30.0
            END
        ) as mttr_days
    FROM vulnerability_scans vs
    JOIN assets a ON vs.asset_id = a.id
    WHERE vs.remediation_status = 'fixed' 
      AND vs.remediation_date IS NOT NULL 
      AND vs.first_seen IS NOT NULL
    GROUP BY a.asset_type
    
    UNION ALL
    
    -- Include asset types with no remediated vulnerabilities (fallback values)
    SELECT DISTINCT
        a.asset_type,
        CASE 
            WHEN a.asset_type IN ('server', 'host') THEN 21.0
            WHEN a.asset_type IN ('workstation', 'laptop', 'desktop') THEN 14.0
            ELSE 30.0
        END::NUMERIC as mttr_days
    FROM assets a
    WHERE a.is_active = true
      AND a.asset_type NOT IN (
          SELECT DISTINCT a2.asset_type
          FROM vulnerability_scans vs2
          JOIN assets a2 ON vs2.asset_id = a2.id
          WHERE vs2.remediation_status = 'fixed' 
            AND vs2.remediation_date IS NOT NULL
      );
END;
$$ LANGUAGE plpgsql;

-- Grant permissions to service role and authenticated users
GRANT EXECUTE ON FUNCTION calculate_mttr_overall() TO service_role;
GRANT EXECUTE ON FUNCTION calculate_mttr_by_risk_level() TO service_role;
GRANT EXECUTE ON FUNCTION calculate_mttr_by_business_group() TO service_role;
GRANT EXECUTE ON FUNCTION calculate_mttr_by_asset_type() TO service_role;

GRANT EXECUTE ON FUNCTION calculate_mttr_overall() TO authenticated;
GRANT EXECUTE ON FUNCTION calculate_mttr_by_risk_level() TO authenticated;
GRANT EXECUTE ON FUNCTION calculate_mttr_by_business_group() TO authenticated;
GRANT EXECUTE ON FUNCTION calculate_mttr_by_asset_type() TO authenticated; 