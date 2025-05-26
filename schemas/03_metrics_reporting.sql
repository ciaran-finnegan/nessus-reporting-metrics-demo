-- Metrics and Reporting Tables

-- Metrics Snapshots table - stores point-in-time metrics
CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    scan_session_id UUID REFERENCES scan_sessions(id),
    metrics_count INTEGER NOT NULL DEFAULT 0,
    snapshot_type VARCHAR(50) DEFAULT 'comprehensive',
    snapshot_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metrics_data JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}'
);

-- Individual Metric Values table
CREATE TABLE IF NOT EXISTS metric_values (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID REFERENCES metrics_snapshots(id) ON DELETE CASCADE,
    metric_name VARCHAR(255) NOT NULL,
    metric_category VARCHAR(100) DEFAULT 'general',
    value NUMERIC(10,4) NOT NULL,
    unit VARCHAR(50) NOT NULL DEFAULT 'count',
    period_start TIMESTAMP WITH TIME ZONE,
    period_end TIMESTAMP WITH TIME ZONE,
    breakdown JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- MTTR History table
CREATE TABLE IF NOT EXISTS mttr_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_type VARCHAR(255),
    value NUMERIC(10,4),
    period_start TIMESTAMP WITH TIME ZONE,
    period_end TIMESTAMP WITH TIME ZONE,
    breakdown JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    calculation_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    overall_mttr NUMERIC(10,4),
    by_risk_level JSONB DEFAULT '{}',
    by_business_group JSONB DEFAULT '{}',
    by_asset_type JSONB DEFAULT '{}',
    remediated_count INTEGER DEFAULT 0,
    introduced_count INTEGER DEFAULT 0,
    calculation_method VARCHAR(50) DEFAULT 'database_rpc'
);

-- Remediation Trends table
CREATE TABLE IF NOT EXISTS remediation_trends (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trend_date DATE NOT NULL,
    new_vulnerabilities INTEGER DEFAULT 0,
    remediated_vulnerabilities INTEGER DEFAULT 0,
    total_open_vulnerabilities INTEGER DEFAULT 0,
    critical_open INTEGER DEFAULT 0,
    high_open INTEGER DEFAULT 0,
    medium_open INTEGER DEFAULT 0,
    low_open INTEGER DEFAULT 0,
    remediation_rate_percentage DECIMAL(5,2) DEFAULT 0.0,
    mttr_days DECIMAL(10,2),
    assets_scanned INTEGER DEFAULT 0,
    active_assets INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_trend_date UNIQUE (trend_date)
); 