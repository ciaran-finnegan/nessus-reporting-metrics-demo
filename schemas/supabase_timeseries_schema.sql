-- Time Series Vulnerability Management Schema for Supabase
-- This schema handles asset and vulnerability tracking over time with proper relationships

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Drop existing tables if they exist (for migration)
-- DROP TABLE IF EXISTS vulnerability_scans CASCADE;
-- DROP TABLE IF EXISTS vulnerabilities CASCADE;
-- DROP TABLE IF EXISTS assets CASCADE;
-- DROP TABLE IF EXISTS scan_sessions CASCADE;

-- Scan Sessions table - tracks individual scan runs
CREATE TABLE scan_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_name VARCHAR(255) NOT NULL,
    scan_date TIMESTAMP WITH TIME ZONE NOT NULL,
    scanner_type VARCHAR(100) NOT NULL DEFAULT 'nessus',
    scanner_version VARCHAR(100),
    scan_policy VARCHAR(255),
    scan_targets TEXT[], -- Array of IP ranges/hostnames scanned
    scan_duration_minutes INTEGER,
    total_hosts_scanned INTEGER,
    total_vulnerabilities_found INTEGER,
    scan_file_name VARCHAR(255),
    scan_file_hash VARCHAR(64), -- SHA256 hash of scan file for deduplication
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Assets table - maintains unique asset identity over time for all asset types
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Asset classification (based on asset_types.yaml)
    asset_class VARCHAR(50) NOT NULL DEFAULT 'Host', -- Host, Code Project, Website, Image, Cloud Resource
    asset_type VARCHAR(100) DEFAULT 'unknown', -- Specific type within class
    asset_subtype VARCHAR(100), -- Specific subtype from asset_types.yaml
    
    -- Universal asset fingerprinting for identity persistence
    asset_fingerprint VARCHAR(500) UNIQUE NOT NULL, -- Unique fingerprint based on asset class
    
    -- Host-specific fields (for asset_class = 'Host')
    current_hostname VARCHAR(255),
    current_ip_address INET,
    mac_address VARCHAR(17), -- MAC address for physical identity
    operating_system VARCHAR(255),
    os_version VARCHAR(255),
    fqdn VARCHAR(255), -- Fully qualified domain name
    cloud_instance_id VARCHAR(255), -- Cloud instance identifier
    is_external BOOLEAN DEFAULT FALSE, -- For external-facing assets
    
    -- Code Project fields (for asset_class = 'Code Project')
    repository_name VARCHAR(255),
    repository_url VARCHAR(500),
    
    -- Website fields (for asset_class = 'Website')
    url VARCHAR(500),
    
    -- Image fields (for asset_class = 'Image')
    image_digest VARCHAR(255),
    image_repository VARCHAR(255),
    image_tag VARCHAR(255),
    
    -- Cloud Resource fields (for asset_class = 'Cloud Resource')
    cloud_provider VARCHAR(50), -- AWS, Azure, GCP
    cloud_resource_id VARCHAR(255), -- Native cloud resource ID
    cloud_region VARCHAR(100), -- Cloud region
    
    -- Business context
    business_unit VARCHAR(255),
    environment VARCHAR(100), -- prod, staging, dev, test
    criticality VARCHAR(50) DEFAULT 'medium', -- critical, high, medium, low
    
    -- Ownership and tagging
    owners TEXT[] DEFAULT '{}',
    tags JSONB DEFAULT '{}',
    business_groups TEXT[] DEFAULT '{}',
    
    -- Lifecycle tracking
    first_discovered TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Asset History table - tracks changes to asset attributes over time
CREATE TABLE asset_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_session_id UUID NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    
    -- Historical values
    hostname VARCHAR(255),
    ip_address INET,
    operating_system VARCHAR(255),
    os_version VARCHAR(255),
    
    -- Change tracking
    change_type VARCHAR(50) NOT NULL, -- discovered, ip_changed, hostname_changed, os_updated, etc.
    previous_values JSONB DEFAULT '{}',
    new_values JSONB DEFAULT '{}',
    
    -- Timestamps
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vulnerabilities table - master list of vulnerability definitions
CREATE TABLE vulnerability_definitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Vulnerability identification
    plugin_id VARCHAR(50) NOT NULL, -- Nessus plugin ID
    cve_ids TEXT[] DEFAULT '{}', -- Associated CVE IDs
    vulnerability_name VARCHAR(500) NOT NULL,
    
    -- Classification
    family VARCHAR(255),
    category VARCHAR(255),
    
    -- Scoring
    cvss_base_score DECIMAL(3,1),
    cvss_temporal_score DECIMAL(3,1),
    cvss_environmental_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    risk_factor VARCHAR(50), -- Critical, High, Medium, Low, None
    
    -- Vulnerability details
    description TEXT,
    solution TEXT,
    synopsis TEXT,
    
    -- References
    vuln_references JSONB DEFAULT '{}', -- URLs, advisories, etc.
    
    -- Metadata
    plugin_publication_date DATE,
    plugin_modification_date DATE,
    vuln_publication_date DATE,
    patch_publication_date DATE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT vuln_def_plugin_unique UNIQUE (plugin_id)
);

-- Vulnerability Scans table - time series of vulnerability findings
CREATE TABLE vulnerability_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Relationships
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerability_definitions(id) ON DELETE CASCADE,
    scan_session_id UUID NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    
    -- Scan-specific details
    port INTEGER,
    protocol VARCHAR(10), -- tcp, udp
    service VARCHAR(100),
    
    -- Finding details
    status VARCHAR(50) NOT NULL, -- open, fixed, reopen, new
    severity VARCHAR(50) NOT NULL, -- Critical, High, Medium, Low, Info
    
    -- Temporal tracking
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    scan_date TIMESTAMP WITH TIME ZONE NOT NULL, -- Date of this specific scan
    
    -- Evidence and context
    plugin_output TEXT,
    proof TEXT,
    
    -- Remediation tracking
    remediation_status VARCHAR(50) DEFAULT 'open', -- open, in_progress, fixed, accepted_risk, false_positive
    remediation_date TIMESTAMP WITH TIME ZONE,
    remediation_notes TEXT,
    assigned_to VARCHAR(255),
    
    -- Business impact
    business_impact VARCHAR(50) DEFAULT 'unknown', -- critical, high, medium, low, none
    exploitability VARCHAR(50) DEFAULT 'unknown', -- functional, poc, unproven, unlikely
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints for time series integrity
    CONSTRAINT vuln_scans_unique_finding UNIQUE (asset_id, vulnerability_id, scan_session_id)
);

-- Indexes for performance
CREATE INDEX idx_scan_sessions_date ON scan_sessions(scan_date);
CREATE INDEX idx_scan_sessions_scanner ON scan_sessions(scanner_type);
CREATE INDEX idx_scan_sessions_hash ON scan_sessions(scan_file_hash);

-- Indexes for all asset types
CREATE INDEX idx_assets_class ON assets(asset_class);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_subtype ON assets(asset_subtype);
CREATE INDEX idx_assets_fingerprint ON assets(asset_fingerprint);
CREATE INDEX idx_assets_active ON assets(is_active);
CREATE INDEX idx_assets_last_seen ON assets(last_seen);
CREATE INDEX idx_assets_criticality ON assets(criticality);

-- Host-specific indexes
CREATE INDEX idx_assets_hostname ON assets(current_hostname) WHERE asset_class = 'Host';
CREATE INDEX idx_assets_ip ON assets(current_ip_address) WHERE asset_class = 'Host';
CREATE INDEX idx_assets_cloud_instance ON assets(cloud_instance_id) WHERE cloud_instance_id IS NOT NULL;
CREATE INDEX idx_assets_fqdn ON assets(fqdn) WHERE fqdn IS NOT NULL;

-- Code Project indexes
CREATE INDEX idx_assets_repository ON assets(repository_name) WHERE asset_class = 'Code Project';
CREATE INDEX idx_assets_repo_url ON assets(repository_url) WHERE asset_class = 'Code Project';

-- Website indexes
CREATE INDEX idx_assets_url ON assets(url) WHERE asset_class = 'Website';

-- Image indexes
CREATE INDEX idx_assets_image_digest ON assets(image_digest) WHERE asset_class = 'Image';
CREATE INDEX idx_assets_image_repo ON assets(image_repository) WHERE asset_class = 'Image';

-- Cloud Resource indexes
CREATE INDEX idx_assets_cloud_provider ON assets(cloud_provider) WHERE asset_class = 'Cloud Resource';
CREATE INDEX idx_assets_cloud_resource ON assets(cloud_resource_id) WHERE asset_class = 'Cloud Resource';
CREATE INDEX idx_assets_cloud_region ON assets(cloud_region) WHERE asset_class = 'Cloud Resource';

-- Partial unique index for MAC addresses (only when not null and not virtual)
CREATE UNIQUE INDEX idx_assets_mac_unique ON assets(mac_address) 
WHERE mac_address IS NOT NULL 
AND mac_address !~ '^(00:00:00|ff:ff:ff|02:00:00|00:50:56|00:0c:29|00:05:69|00:1c:42|08:00:27)';

CREATE INDEX idx_asset_history_asset ON asset_history(asset_id);
CREATE INDEX idx_asset_history_scan ON asset_history(scan_session_id);
CREATE INDEX idx_asset_history_observed ON asset_history(observed_at);

CREATE INDEX idx_vuln_def_plugin ON vulnerability_definitions(plugin_id);
CREATE INDEX idx_vuln_def_cve ON vulnerability_definitions USING GIN(cve_ids);
CREATE INDEX idx_vuln_def_risk ON vulnerability_definitions(risk_factor);
CREATE INDEX idx_vuln_def_cvss ON vulnerability_definitions(cvss_base_score);

CREATE INDEX idx_vuln_scans_asset ON vulnerability_scans(asset_id);
CREATE INDEX idx_vuln_scans_vuln ON vulnerability_scans(vulnerability_id);
CREATE INDEX idx_vuln_scans_session ON vulnerability_scans(scan_session_id);
CREATE INDEX idx_vuln_scans_status ON vulnerability_scans(status);
CREATE INDEX idx_vuln_scans_severity ON vulnerability_scans(severity);
CREATE INDEX idx_vuln_scans_scan_date ON vulnerability_scans(scan_date);
CREATE INDEX idx_vuln_scans_remediation ON vulnerability_scans(remediation_status);
CREATE INDEX idx_vuln_scans_first_seen ON vulnerability_scans(first_seen);
CREATE INDEX idx_vuln_scans_last_seen ON vulnerability_scans(last_seen);

-- Composite indexes for common queries
CREATE INDEX idx_vuln_scans_asset_status ON vulnerability_scans(asset_id, status);
CREATE INDEX idx_vuln_scans_severity_status ON vulnerability_scans(severity, remediation_status);
CREATE INDEX idx_assets_class_active ON assets(asset_class, is_active);
CREATE INDEX idx_assets_type_active ON assets(asset_type, is_active);
CREATE INDEX idx_assets_class_criticality ON assets(asset_class, criticality);

-- Views for common queries

-- Current vulnerability state (latest scan results)
CREATE VIEW current_vulnerabilities AS
WITH latest_scans AS (
    SELECT 
        asset_id,
        vulnerability_id,
        MAX(scan_date) as latest_scan_date
    FROM vulnerability_scans
    GROUP BY asset_id, vulnerability_id
)
SELECT 
    vs.*,
    a.asset_class,
    a.current_hostname,
    a.current_ip_address,
    a.asset_type,
    a.asset_subtype,
    a.criticality as asset_criticality,
    vd.vulnerability_name,
    vd.cvss_base_score,
    vd.risk_factor,
    vd.family as vulnerability_family
FROM vulnerability_scans vs
JOIN latest_scans ls ON vs.asset_id = ls.asset_id 
    AND vs.vulnerability_id = ls.vulnerability_id 
    AND vs.scan_date = ls.latest_scan_date
JOIN assets a ON vs.asset_id = a.id
JOIN vulnerability_definitions vd ON vs.vulnerability_id = vd.id
WHERE a.is_active = true;

-- Asset summary with current vulnerability counts
CREATE VIEW asset_summary AS
SELECT 
    a.id,
    a.asset_class,
    a.current_hostname,
    a.current_ip_address,
    a.asset_type,
    a.asset_subtype,
    a.criticality,
    a.last_seen,
    COUNT(cv.id) as total_vulnerabilities,
    COUNT(CASE WHEN cv.severity = 'Critical' THEN 1 END) as critical_vulns,
    COUNT(CASE WHEN cv.severity = 'High' THEN 1 END) as high_vulns,
    COUNT(CASE WHEN cv.severity = 'Medium' THEN 1 END) as medium_vulns,
    COUNT(CASE WHEN cv.severity = 'Low' THEN 1 END) as low_vulns,
    COUNT(CASE WHEN cv.remediation_status = 'open' THEN 1 END) as open_vulns,
    MAX(cv.cvss_base_score) as highest_cvss_score
FROM assets a
LEFT JOIN current_vulnerabilities cv ON a.id = cv.asset_id
WHERE a.is_active = true
GROUP BY a.id, a.asset_class, a.current_hostname, a.current_ip_address, a.asset_type, a.asset_subtype, a.criticality, a.last_seen;

-- Vulnerability trend analysis
CREATE VIEW vulnerability_trends AS
SELECT 
    vd.vulnerability_name,
    vd.plugin_id,
    vd.risk_factor,
    vd.cvss_base_score,
    COUNT(DISTINCT vs.asset_id) as affected_assets,
    MIN(vs.first_seen) as first_discovered,
    MAX(vs.last_seen) as last_observed,
    COUNT(CASE WHEN vs.remediation_status = 'open' THEN 1 END) as currently_open,
    COUNT(CASE WHEN vs.remediation_status = 'fixed' THEN 1 END) as fixed_instances
FROM vulnerability_definitions vd
JOIN vulnerability_scans vs ON vd.id = vs.vulnerability_id
JOIN assets a ON vs.asset_id = a.id
WHERE a.is_active = true
GROUP BY vd.id, vd.vulnerability_name, vd.plugin_id, vd.risk_factor, vd.cvss_base_score;

-- Functions for comprehensive asset fingerprinting (all asset types)
CREATE OR REPLACE FUNCTION generate_asset_fingerprint(
    p_asset_class VARCHAR(50),
    p_data JSONB
) RETURNS VARCHAR(500) AS $$
DECLARE
    v_fingerprint VARCHAR(500);
BEGIN
    -- Different fingerprinting logic based on asset class (following Vulcan Cyber approach)
    CASE p_asset_class
        
        -- Host fingerprinting (based on Vulcan Cyber's proven approach)
        WHEN 'Host' THEN
            -- Priority: Cloud Instance ID > MAC > IP+Hostname+FQDN > IP+Hostname > Hostname
            IF p_data->>'cloud_instance_id' IS NOT NULL THEN
                v_fingerprint := 'host:cloud:' || LOWER(p_data->>'cloud_instance_id');
            ELSIF p_data->>'mac_address' IS NOT NULL AND 
                  p_data->>'mac_address' !~ '^(00:00:00|ff:ff:ff|02:00:00|00:50:56|00:0c:29|00:05:69|00:1c:42|08:00:27)' THEN
                v_fingerprint := 'host:mac:' || LOWER(p_data->>'mac_address');
            ELSIF p_data->>'ip_address' IS NOT NULL AND p_data->>'hostname' IS NOT NULL AND p_data->>'fqdn' IS NOT NULL THEN
                v_fingerprint := 'host:full:' || (p_data->>'ip_address') || ':' || LOWER(p_data->>'hostname') || ':' || LOWER(p_data->>'fqdn');
            ELSIF p_data->>'ip_address' IS NOT NULL AND p_data->>'hostname' IS NOT NULL THEN
                v_fingerprint := 'host:ip_host:' || (p_data->>'ip_address') || ':' || LOWER(p_data->>'hostname');
            ELSIF p_data->>'hostname' IS NOT NULL AND p_data->>'fqdn' IS NOT NULL THEN
                v_fingerprint := 'host:host_fqdn:' || LOWER(p_data->>'hostname') || ':' || LOWER(p_data->>'fqdn');
            ELSIF p_data->>'hostname' IS NOT NULL THEN
                v_fingerprint := 'host:hostname:' || LOWER(p_data->>'hostname');
            ELSE
                v_fingerprint := 'host:ip:' || (p_data->>'ip_address');
            END IF;
            
        -- Code Project fingerprinting
        WHEN 'Code Project' THEN
            -- Priority: Repository URL > Repository Name + Provider
            IF p_data->>'repository_url' IS NOT NULL THEN
                v_fingerprint := 'code:url:' || LOWER(p_data->>'repository_url');
            ELSIF p_data->>'repository_name' IS NOT NULL AND p_data->>'provider' IS NOT NULL THEN
                v_fingerprint := 'code:name_provider:' || LOWER(p_data->>'repository_name') || ':' || LOWER(p_data->>'provider');
            ELSE
                v_fingerprint := 'code:name:' || LOWER(p_data->>'repository_name');
            END IF;
            
        -- Website fingerprinting
        WHEN 'Website' THEN
            -- Use URL as unique identifier
            v_fingerprint := 'web:url:' || LOWER(REGEXP_REPLACE(p_data->>'url', '^https?://', ''));
            
        -- Image fingerprinting
        WHEN 'Image' THEN
            -- Priority: Digest > Repository+Tag
            IF p_data->>'image_digest' IS NOT NULL THEN
                v_fingerprint := 'image:digest:' || LOWER(p_data->>'image_digest');
            ELSE
                v_fingerprint := 'image:repo_tag:' || LOWER(p_data->>'image_repository') || ':' || LOWER(COALESCE(p_data->>'image_tag', 'latest'));
            END IF;
            
        -- Cloud Resource fingerprinting
        WHEN 'Cloud Resource' THEN
            -- Use Native ID (cloud provider's unique identifier)
            IF p_data->>'cloud_resource_id' IS NOT NULL THEN
                v_fingerprint := 'cloud:' || LOWER(p_data->>'cloud_provider') || ':' || LOWER(p_data->>'cloud_resource_id');
            ELSIF p_data->>'cloud_provider' = 'AWS' AND p_data->>'arn' IS NOT NULL THEN
                v_fingerprint := 'cloud:aws:arn:' || LOWER(p_data->>'arn');
            ELSIF p_data->>'name' IS NOT NULL AND p_data->>'cloud_region' IS NOT NULL THEN
                v_fingerprint := 'cloud:' || LOWER(p_data->>'cloud_provider') || ':' || LOWER(p_data->>'cloud_region') || ':' || LOWER(p_data->>'name');
            ELSE
                v_fingerprint := 'cloud:' || LOWER(p_data->>'cloud_provider') || ':' || LOWER(p_data->>'name');
            END IF;
            
        ELSE
            -- Fallback for unknown asset types
            v_fingerprint := LOWER(p_asset_class) || ':unknown:' || MD5(p_data::text);
    END CASE;
    
    RETURN v_fingerprint;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to upsert assets with proper identity management for all asset types
CREATE OR REPLACE FUNCTION upsert_asset(
    p_asset_class VARCHAR(50),
    p_asset_data JSONB,
    p_scan_session_id UUID DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_asset_id UUID;
    v_fingerprint VARCHAR(500);
    v_existing_asset RECORD;
    v_changes_detected BOOLEAN := FALSE;
    v_asset_type VARCHAR(100);
    v_asset_subtype VARCHAR(100);
BEGIN
    -- Generate fingerprint based on asset class
    v_fingerprint := generate_asset_fingerprint(p_asset_class, p_asset_data);
    
    -- Extract asset type and subtype from data
    v_asset_type := COALESCE(p_asset_data->>'asset_type', 'unknown');
    v_asset_subtype := p_asset_data->>'asset_subtype';
    
    -- Try to find existing asset by fingerprint
    SELECT * INTO v_existing_asset FROM assets WHERE asset_fingerprint = v_fingerprint;
    
    IF v_existing_asset.id IS NOT NULL THEN
        -- Asset exists, check for changes and update
        v_asset_id := v_existing_asset.id;
        
        -- Update asset with current information based on asset class
        CASE p_asset_class
            WHEN 'Host' THEN
                UPDATE assets SET
                    current_hostname = COALESCE(p_asset_data->>'hostname', current_hostname),
                    current_ip_address = COALESCE((p_asset_data->>'ip_address')::INET, current_ip_address),
                    mac_address = COALESCE(p_asset_data->>'mac_address', mac_address),
                    operating_system = COALESCE(p_asset_data->>'operating_system', operating_system),
                    os_version = COALESCE(p_asset_data->>'os_version', os_version),
                    fqdn = COALESCE(p_asset_data->>'fqdn', fqdn),
                    cloud_instance_id = COALESCE(p_asset_data->>'cloud_instance_id', cloud_instance_id),
                    is_external = COALESCE((p_asset_data->>'is_external')::BOOLEAN, is_external),
                    asset_type = v_asset_type,
                    asset_subtype = v_asset_subtype,
                    last_seen = NOW(),
                    is_active = true,
                    updated_at = NOW()
                WHERE id = v_asset_id;
                
            WHEN 'Code Project' THEN
                UPDATE assets SET
                    repository_name = COALESCE(p_asset_data->>'repository_name', repository_name),
                    repository_url = COALESCE(p_asset_data->>'repository_url', repository_url),
                    asset_type = v_asset_type,
                    asset_subtype = v_asset_subtype,
                    last_seen = NOW(),
                    is_active = true,
                    updated_at = NOW()
                WHERE id = v_asset_id;
                
            WHEN 'Website' THEN
                UPDATE assets SET
                    url = COALESCE(p_asset_data->>'url', url),
                    asset_type = v_asset_type,
                    asset_subtype = v_asset_subtype,
                    last_seen = NOW(),
                    is_active = true,
                    updated_at = NOW()
                WHERE id = v_asset_id;
                
            WHEN 'Image' THEN
                UPDATE assets SET
                    image_digest = COALESCE(p_asset_data->>'image_digest', image_digest),
                    image_repository = COALESCE(p_asset_data->>'image_repository', image_repository),
                    image_tag = COALESCE(p_asset_data->>'image_tag', image_tag),
                    asset_type = v_asset_type,
                    asset_subtype = v_asset_subtype,
                    last_seen = NOW(),
                    is_active = true,
                    updated_at = NOW()
                WHERE id = v_asset_id;
                
            WHEN 'Cloud Resource' THEN
                UPDATE assets SET
                    cloud_provider = COALESCE(p_asset_data->>'cloud_provider', cloud_provider),
                    cloud_resource_id = COALESCE(p_asset_data->>'cloud_resource_id', cloud_resource_id),
                    cloud_region = COALESCE(p_asset_data->>'cloud_region', cloud_region),
                    asset_type = v_asset_type,
                    asset_subtype = v_asset_subtype,
                    last_seen = NOW(),
                    is_active = true,
                    updated_at = NOW()
                WHERE id = v_asset_id;
        END CASE;
        
        -- Record any changes in asset history
        IF p_scan_session_id IS NOT NULL THEN
            INSERT INTO asset_history (asset_id, scan_session_id, change_type, new_values, observed_at)
            VALUES (v_asset_id, p_scan_session_id, 'updated', p_asset_data, NOW());
        END IF;
        
    ELSE
        -- New asset - insert based on asset class
        INSERT INTO assets (
            asset_class,
            asset_type,
            asset_subtype,
            asset_fingerprint,
            -- Host fields
            current_hostname,
            current_ip_address,
            mac_address,
            operating_system,
            os_version,
            fqdn,
            cloud_instance_id,
            is_external,
            -- Code Project fields
            repository_name,
            repository_url,
            -- Website fields
            url,
            -- Image fields
            image_digest,
            image_repository,
            image_tag,
            -- Cloud Resource fields
            cloud_provider,
            cloud_resource_id,
            cloud_region,
            -- Common fields
            business_unit,
            environment,
            criticality,
            first_discovered,
            last_seen,
            metadata
        ) VALUES (
            p_asset_class,
            v_asset_type,
            v_asset_subtype,
            v_fingerprint,
            -- Host fields
            p_asset_data->>'hostname',
            (p_asset_data->>'ip_address')::INET,
            p_asset_data->>'mac_address',
            p_asset_data->>'operating_system',
            p_asset_data->>'os_version',
            p_asset_data->>'fqdn',
            p_asset_data->>'cloud_instance_id',
            COALESCE((p_asset_data->>'is_external')::BOOLEAN, FALSE),
            -- Code Project fields
            p_asset_data->>'repository_name',
            p_asset_data->>'repository_url',
            -- Website fields
            p_asset_data->>'url',
            -- Image fields
            p_asset_data->>'image_digest',
            p_asset_data->>'image_repository',
            p_asset_data->>'image_tag',
            -- Cloud Resource fields
            p_asset_data->>'cloud_provider',
            p_asset_data->>'cloud_resource_id',
            p_asset_data->>'cloud_region',
            -- Common fields
            p_asset_data->>'business_unit',
            COALESCE(p_asset_data->>'environment', 'unknown'),
            COALESCE(p_asset_data->>'criticality', 'medium'),
            NOW(),
            NOW(),
            COALESCE(p_asset_data - 'hostname' - 'ip_address' - 'mac_address' - 'operating_system' - 'os_version' - 'fqdn' - 'cloud_instance_id' - 'is_external' - 'repository_name' - 'repository_url' - 'url' - 'image_digest' - 'image_repository' - 'image_tag' - 'cloud_provider' - 'cloud_resource_id' - 'cloud_region' - 'business_unit' - 'environment' - 'criticality' - 'asset_type' - 'asset_subtype', '{}')
        ) RETURNING id INTO v_asset_id;
        
        -- Record discovery
        IF p_scan_session_id IS NOT NULL THEN
            INSERT INTO asset_history (asset_id, scan_session_id, change_type, new_values, observed_at)
            VALUES (v_asset_id, p_scan_session_id, 'discovered', p_asset_data, NOW());
        END IF;
    END IF;
    
    RETURN v_asset_id;
END;
$$ LANGUAGE plpgsql;

-- Row Level Security (RLS) policies
ALTER TABLE scan_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_scans ENABLE ROW LEVEL SECURITY;

-- Basic RLS policies (adjust based on your authentication needs)
CREATE POLICY "Allow all operations for authenticated users" ON scan_sessions FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow all operations for authenticated users" ON assets FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow all operations for authenticated users" ON asset_history FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow all operations for authenticated users" ON vulnerability_definitions FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow all operations for authenticated users" ON vulnerability_scans FOR ALL USING (auth.role() = 'authenticated');

-- Grant permissions to service role
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO service_role; 