-- Complete Vulnerability Management Schema
-- This is the main schema file that creates all core tables

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scan Sessions table - tracks individual scan runs
CREATE TABLE IF NOT EXISTS scan_sessions (
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

-- Assets table - maintains unique asset identity over time
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Asset classification
    asset_class VARCHAR(50) NOT NULL DEFAULT 'Host',
    asset_type VARCHAR(100) DEFAULT 'unknown',
    asset_subtype VARCHAR(100),
    
    -- Universal asset fingerprinting for identity persistence
    asset_fingerprint VARCHAR(500) UNIQUE NOT NULL,
    
    -- Host-specific fields
    current_hostname VARCHAR(255),
    current_ip_address INET,
    mac_address VARCHAR(17),
    operating_system VARCHAR(255),
    os_version VARCHAR(255),
    fqdn VARCHAR(255),
    cloud_instance_id VARCHAR(255),
    is_external BOOLEAN DEFAULT FALSE,
    
    -- Code Project fields
    repository_name VARCHAR(255),
    repository_url VARCHAR(500),
    
    -- Website fields
    url VARCHAR(500),
    
    -- Image fields
    image_digest VARCHAR(255),
    image_repository VARCHAR(255),
    image_tag VARCHAR(255),
    
    -- Cloud Resource fields
    cloud_provider VARCHAR(50),
    cloud_resource_id VARCHAR(255),
    cloud_region VARCHAR(100),
    
    -- Business context
    business_unit VARCHAR(255),
    environment VARCHAR(100),
    criticality VARCHAR(50) DEFAULT 'medium',
    criticality_score INTEGER DEFAULT 2 CHECK (criticality_score >= 1 AND criticality_score <= 5),
    
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

-- Asset History table
CREATE TABLE IF NOT EXISTS asset_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_session_id UUID NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    
    -- Historical values
    hostname VARCHAR(255),
    ip_address INET,
    operating_system VARCHAR(255),
    os_version VARCHAR(255),
    
    -- Change tracking
    change_type VARCHAR(50) NOT NULL,
    previous_values JSONB DEFAULT '{}',
    new_values JSONB DEFAULT '{}',
    
    -- Timestamps
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vulnerability Definitions table
CREATE TABLE IF NOT EXISTS vulnerability_definitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Vulnerability identification
    plugin_id VARCHAR(50) NOT NULL,
    cve_ids TEXT[] DEFAULT '{}',
    vulnerability_name VARCHAR(500) NOT NULL,
    
    -- Classification
    family VARCHAR(255),
    category VARCHAR(255),
    
    -- Scoring
    cvss_base_score DECIMAL(3,1),
    cvss_temporal_score DECIMAL(3,1),
    cvss_environmental_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    risk_factor VARCHAR(50),
    
    -- Vulnerability details
    description TEXT,
    solution TEXT,
    synopsis TEXT,
    
    -- References
    vuln_references JSONB DEFAULT '{}',
    
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
CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Relationships
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerability_definitions(id) ON DELETE CASCADE,
    scan_session_id UUID NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    
    -- Scan-specific details
    port INTEGER,
    protocol VARCHAR(10),
    service VARCHAR(100),
    
    -- Finding details
    status VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    
    -- Temporal tracking
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    scan_date TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Evidence and context
    plugin_output TEXT,
    proof TEXT,
    
    -- Remediation tracking
    remediation_status VARCHAR(50) DEFAULT 'open',
    remediation_date TIMESTAMP WITH TIME ZONE,
    remediation_notes TEXT,
    assigned_to VARCHAR(255),
    
    -- Business impact
    business_impact VARCHAR(50) DEFAULT 'unknown',
    exploitability VARCHAR(50) DEFAULT 'unknown',
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints for time series integrity
    CONSTRAINT vuln_scans_unique_finding UNIQUE (asset_id, vulnerability_id, scan_session_id)
); 