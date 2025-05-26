-- Business Context Schema for Business Groups and Asset Tags
-- Based on Vulcan Cyber's proven approach to asset organization

-- Business Groups table with hierarchical structure
CREATE TABLE business_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES business_groups(id) ON DELETE CASCADE,
    path TEXT, -- Materialized path for efficient hierarchy queries (e.g., "/root/emea/uk/")
    depth INTEGER DEFAULT 0,
    color VARCHAR(7), -- Hex color for UI display
    icon VARCHAR(50), -- Icon identifier
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255),
    
    CONSTRAINT business_groups_name_unique UNIQUE (name, parent_id)
);

-- Asset Tags table
CREATE TABLE asset_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    tag_type VARCHAR(50) NOT NULL DEFAULT 'manual', -- manual, imported, dynamic
    color VARCHAR(7), -- Hex color for UI display
    is_favorite BOOLEAN DEFAULT FALSE,
    
    -- Dynamic tag rules (stored as JSONB for flexibility)
    rule_definition JSONB, -- Contains rule type and criteria
    evaluate_on_creation BOOLEAN DEFAULT TRUE,
    last_evaluated TIMESTAMP WITH TIME ZONE,
    
    -- Source information for imported tags
    source_connector VARCHAR(100), -- e.g., 'nessus', 'qualys', 'aws'
    source_id VARCHAR(255), -- Original ID from source system
    
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Many-to-many relationship: Assets to Business Groups
CREATE TABLE asset_business_groups (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    business_group_id UUID NOT NULL REFERENCES business_groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by VARCHAR(255),
    
    PRIMARY KEY (asset_id, business_group_id)
);

-- Many-to-many relationship: Assets to Tags
CREATE TABLE asset_tag_assignments (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES asset_tags(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by VARCHAR(255),
    auto_applied BOOLEAN DEFAULT FALSE, -- True if applied by dynamic rule
    
    PRIMARY KEY (asset_id, tag_id)
);

-- Update assets table to include criticality score
ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality_score INTEGER DEFAULT 2 CHECK (criticality_score >= 1 AND criticality_score <= 5);

-- Indexes for performance
CREATE INDEX idx_business_groups_parent ON business_groups(parent_id);
CREATE INDEX idx_business_groups_path ON business_groups(path);
CREATE INDEX idx_asset_tags_type ON asset_tags(tag_type);
CREATE INDEX idx_asset_tags_favorite ON asset_tags(is_favorite);
CREATE INDEX idx_asset_bg_asset ON asset_business_groups(asset_id);
CREATE INDEX idx_asset_bg_group ON asset_business_groups(business_group_id);
CREATE INDEX idx_asset_tag_asset ON asset_tag_assignments(asset_id);
CREATE INDEX idx_asset_tag_tag ON asset_tag_assignments(tag_id);

-- View: Assets with Business Context
CREATE VIEW assets_with_context AS
SELECT 
    a.*,
    COALESCE(
        MAX(at_crit.criticality_score),
        a.criticality_score
    ) as effective_criticality, -- Max criticality from tags or asset
    array_agg(DISTINCT bg.name) FILTER (WHERE bg.name IS NOT NULL) as assigned_business_groups,
    array_agg(DISTINCT at.name) FILTER (WHERE at.name IS NOT NULL) as assigned_tags,
    jsonb_object_agg(
        bg.name, 
        jsonb_build_object('id', bg.id, 'path', bg.path)
    ) FILTER (WHERE bg.name IS NOT NULL) as business_group_details
FROM assets a
LEFT JOIN asset_business_groups abg ON a.id = abg.asset_id
LEFT JOIN business_groups bg ON abg.business_group_id = bg.id
LEFT JOIN asset_tag_assignments ata ON a.id = ata.asset_id
LEFT JOIN asset_tags at ON ata.tag_id = at.id
LEFT JOIN (
    -- Get max criticality score from tags
    SELECT 
        ata.asset_id,
        MAX(CAST(at.metadata->>'criticality_score' AS INTEGER)) as criticality_score
    FROM asset_tag_assignments ata
    JOIN asset_tags at ON ata.tag_id = at.id
    WHERE at.metadata->>'criticality_score' IS NOT NULL
    GROUP BY ata.asset_id
) at_crit ON a.id = at_crit.asset_id
GROUP BY a.id;

-- View: Vulnerability Summary by Business Group
CREATE VIEW vulnerability_summary_by_business_group AS
SELECT 
    bg.id as business_group_id,
    bg.name as business_group_name,
    bg.path as business_group_path,
    COUNT(DISTINCT awc.id) as total_assets,
    COUNT(DISTINCT vs.id) as total_vulnerabilities,
    COUNT(DISTINCT CASE WHEN vs.severity = 'Critical' THEN vs.id END) as critical_vulns,
    COUNT(DISTINCT CASE WHEN vs.severity = 'High' THEN vs.id END) as high_vulns,
    COUNT(DISTINCT CASE WHEN vs.severity = 'Medium' THEN vs.id END) as medium_vulns,
    COUNT(DISTINCT CASE WHEN vs.severity = 'Low' THEN vs.id END) as low_vulns,
    AVG(awc.effective_criticality) as avg_asset_criticality,
    SUM(
        CASE 
            WHEN vs.severity = 'Critical' THEN 4 * awc.effective_criticality
            WHEN vs.severity = 'High' THEN 3 * awc.effective_criticality
            WHEN vs.severity = 'Medium' THEN 2 * awc.effective_criticality
            WHEN vs.severity = 'Low' THEN 1 * awc.effective_criticality
            ELSE 0
        END
    ) as risk_score
FROM business_groups bg
LEFT JOIN asset_business_groups abg ON bg.id = abg.business_group_id
LEFT JOIN assets_with_context awc ON abg.asset_id = awc.id
LEFT JOIN current_vulnerabilities vs ON awc.id = vs.asset_id
WHERE awc.is_active = true OR awc.is_active IS NULL
GROUP BY bg.id, bg.name, bg.path;

-- Function to get vulnerability metrics by business group hierarchy
CREATE OR REPLACE FUNCTION get_business_group_metrics(
    p_parent_id UUID DEFAULT NULL,
    p_depth INTEGER DEFAULT NULL
) RETURNS TABLE (
    business_group_id UUID,
    business_group_name VARCHAR,
    path TEXT,
    depth INTEGER,
    direct_assets INTEGER,
    total_assets INTEGER,
    critical_vulns INTEGER,
    high_vulns INTEGER,
    risk_score NUMERIC,
    avg_criticality NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE bg_hierarchy AS (
        -- Base case: start with parent or root
        SELECT 
            bg.id,
            bg.name,
            bg.path,
            bg.depth,
            bg.parent_id
        FROM business_groups bg
        WHERE (p_parent_id IS NULL AND bg.parent_id IS NULL) 
           OR (p_parent_id IS NOT NULL AND bg.parent_id = p_parent_id)
        
        UNION ALL
        
        -- Recursive case: get all descendants
        SELECT 
            bg.id,
            bg.name,
            bg.path,
            bg.depth,
            bg.parent_id
        FROM business_groups bg
        JOIN bg_hierarchy h ON bg.parent_id = h.id
        WHERE p_depth IS NULL OR bg.depth <= p_depth
    )
    SELECT 
        h.id,
        h.name,
        h.path,
        h.depth,
        COUNT(DISTINCT CASE WHEN abg.business_group_id = h.id THEN awc.id END) as direct_assets,
        COUNT(DISTINCT awc.id) as total_assets,
        COUNT(DISTINCT CASE WHEN cv.severity = 'Critical' THEN cv.id END) as critical_vulns,
        COUNT(DISTINCT CASE WHEN cv.severity = 'High' THEN cv.id END) as high_vulns,
        COALESCE(SUM(
            CASE 
                WHEN cv.severity = 'Critical' THEN 4 * awc.effective_criticality
                WHEN cv.severity = 'High' THEN 3 * awc.effective_criticality
                WHEN cv.severity = 'Medium' THEN 2 * awc.effective_criticality
                WHEN cv.severity = 'Low' THEN 1 * awc.effective_criticality
                ELSE 0
            END
        ), 0) as risk_score,
        AVG(awc.effective_criticality) as avg_criticality
    FROM bg_hierarchy h
    LEFT JOIN asset_business_groups abg ON abg.business_group_id = h.id
    LEFT JOIN assets_with_context awc ON abg.asset_id = awc.id
    LEFT JOIN current_vulnerabilities cv ON awc.id = cv.asset_id
    WHERE awc.is_active = true OR awc.is_active IS NULL
    GROUP BY h.id, h.name, h.path, h.depth;
END;
$$ LANGUAGE plpgsql;

-- Row Level Security
ALTER TABLE business_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_business_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_tag_assignments ENABLE ROW LEVEL SECURITY;

-- Basic RLS policies
CREATE POLICY "Allow all operations for authenticated users" ON business_groups FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow all operations for authenticated users" ON asset_tags FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow all operations for authenticated users" ON asset_business_groups FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow all operations for authenticated users" ON asset_tag_assignments FOR ALL USING (auth.role() = 'authenticated');

-- Grant permissions
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO service_role; 