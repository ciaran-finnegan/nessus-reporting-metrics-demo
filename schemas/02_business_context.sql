-- Business Groups and Asset Tags Schema

-- Business Groups table with hierarchical structure
CREATE TABLE IF NOT EXISTS business_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES business_groups(id) ON DELETE CASCADE,
    path TEXT,
    depth INTEGER DEFAULT 0,
    color VARCHAR(7),
    icon VARCHAR(50),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255),
    
    CONSTRAINT business_groups_name_unique UNIQUE (name, parent_id)
);

-- Asset Tags table
CREATE TABLE IF NOT EXISTS asset_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    tag_type VARCHAR(50) NOT NULL DEFAULT 'manual',
    color VARCHAR(7),
    is_favorite BOOLEAN DEFAULT FALSE,
    
    -- Dynamic tag rules
    rule_definition JSONB,
    evaluate_on_creation BOOLEAN DEFAULT TRUE,
    last_evaluated TIMESTAMP WITH TIME ZONE,
    
    -- Source information for imported tags
    source_connector VARCHAR(100),
    source_id VARCHAR(255),
    
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Many-to-many relationship: Assets to Business Groups
CREATE TABLE IF NOT EXISTS asset_business_groups (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    business_group_id UUID NOT NULL REFERENCES business_groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by VARCHAR(255),
    
    PRIMARY KEY (asset_id, business_group_id)
);

-- Many-to-many relationship: Assets to Tags
CREATE TABLE IF NOT EXISTS asset_tag_assignments (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES asset_tags(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by VARCHAR(255),
    auto_applied BOOLEAN DEFAULT FALSE,
    
    PRIMARY KEY (asset_id, tag_id)
); 