-- Asset Management Functions

-- Function for comprehensive asset fingerprinting
CREATE OR REPLACE FUNCTION generate_asset_fingerprint(
    p_asset_class VARCHAR(50),
    p_data JSONB
) RETURNS VARCHAR(500) AS $$
DECLARE
    v_fingerprint VARCHAR(500);
BEGIN
    CASE p_asset_class
        WHEN 'Host' THEN
            IF p_data->>'cloud_instance_id' IS NOT NULL THEN
                v_fingerprint := 'host:cloud:' || LOWER(p_data->>'cloud_instance_id');
            ELSIF p_data->>'mac_address' IS NOT NULL AND 
                  p_data->>'mac_address' !~ '^( 