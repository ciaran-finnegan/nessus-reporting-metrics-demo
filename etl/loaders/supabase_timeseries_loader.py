import os
import logging
import hashlib
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from supabase import create_client, Client
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class SupabaseTimeSeriesLoader:
    """
    Time series loader for Supabase that handles:
    - Proper asset identity management with fingerprinting
    - Vulnerability definitions and scan results separation
    - Scan session tracking
    - Asset change history
    - True time series data with proper relationships
    """
    
    def __init__(self):
        self.url = os.getenv('SUPABASE_URL')
        self.key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
        
        if not self.url or not self.key:
            raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in environment")
        
        self.client: Client = create_client(self.url, self.key)
        self.current_scan_session_id: Optional[str] = None
        
    def test_connection(self) -> bool:
        """Test the Supabase connection"""
        try:
            # Try to query scan_sessions table
            result = self.client.table('scan_sessions').select('id').limit(1).execute()
            logger.info("✅ Supabase connection successful")
            return True
        except Exception as e:
            logger.error(f"❌ Supabase connection failed: {e}")
            return False
    
    def create_scan_session(self, scan_name: str, scan_file_path: str = None, 
                          scan_targets: List[str] = None, metadata: Dict = None, 
                          scan_date: datetime = None) -> str:
        """
        Create a new scan session to track this ETL run
        
        Args:
            scan_name: Name/identifier for this scan
            scan_file_path: Path to the source scan file
            scan_targets: List of IP ranges/hostnames that were scanned
            metadata: Additional metadata about the scan
            
        Returns:
            UUID of the created scan session
        """
        try:
            # Calculate file hash if file path provided
            file_hash = None
            file_name = None
            if scan_file_path and os.path.exists(scan_file_path):
                file_name = os.path.basename(scan_file_path)
                with open(scan_file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
            
            scan_data = {
                'scan_name': scan_name,
                'scan_date': (scan_date or datetime.now(timezone.utc)).isoformat(),
                'scanner_type': 'nessus',
                'scan_file_name': file_name,
                'scan_file_hash': file_hash,
                'scan_targets': scan_targets or [],
                'metadata': metadata or {}
            }
            
            result = self.client.table('scan_sessions').insert(scan_data).execute()
            
            if result.data:
                self.current_scan_session_id = result.data[0]['id']
                logger.info(f"✅ Created scan session: {self.current_scan_session_id}")
                return self.current_scan_session_id
            else:
                raise Exception("No data returned from scan session creation")
                
        except Exception as e:
            logger.error(f"❌ Failed to create scan session: {e}")
            raise
    
    def update_scan_session_stats(self, total_hosts: int, total_vulnerabilities: int, 
                                duration_minutes: int = None):
        """Update scan session with final statistics"""
        if not self.current_scan_session_id:
            logger.warning("No current scan session to update")
            return
            
        try:
            update_data = {
                'total_hosts_scanned': total_hosts,
                'total_vulnerabilities_found': total_vulnerabilities,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            if duration_minutes:
                update_data['scan_duration_minutes'] = duration_minutes
            
            result = self.client.table('scan_sessions').update(update_data).eq(
                'id', self.current_scan_session_id
            ).execute()
            
            logger.info(f"✅ Updated scan session stats: {total_hosts} hosts, {total_vulnerabilities} vulnerabilities")
            
        except Exception as e:
            logger.error(f"❌ Failed to update scan session stats: {e}")
    
    def _generate_asset_fingerprint(self, hostname: str, ip_address: str, 
                                  mac_address: str = None, os_info: str = None) -> str:
        """
        Generate a consistent fingerprint for asset identity
        Priority: MAC > IP+OS > IP+Hostname > IP only
        """
        if mac_address:
            return f"mac:{mac_address.lower()}"
        elif os_info:
            clean_os = ''.join(c for c in os_info if c.isalnum()).lower()
            return f"ip_os:{ip_address}:{clean_os}"
        elif hostname:
            return f"ip_host:{ip_address}:{hostname.lower()}"
        else:
            return f"ip:{ip_address}"
    
    def upsert_asset(self, asset_data: Dict) -> str:
        """
        Upsert an asset using the database function for proper identity management
        Now supports multi-asset-type approach
        
        Args:
            asset_data: Dictionary containing asset information
            
        Returns:
            UUID of the asset
        """
        try:
            # For Nessus data, we're dealing with hosts
            hostname = asset_data.get('Asset_Name', '')
            ip_address = asset_data.get('Asset_IP', '')
            mac_address = asset_data.get('MAC_Address')  # If available
            os_info = asset_data.get('Operating_System')
            os_version = asset_data.get('OS_Version')
            asset_type = asset_data.get('Type', 'unknown')
            
            if not ip_address:
                raise ValueError("IP address is required for asset identification")
            
            # Prepare asset data in JSONB format for the new function
            asset_jsonb = {
                'hostname': hostname or None,
                'ip_address': ip_address,
                'mac_address': mac_address,
                'operating_system': os_info,
                'os_version': os_version,
                'asset_type': asset_type,
                # Add any additional fields that might be available
                'fqdn': asset_data.get('FQDN'),
                'cloud_instance_id': asset_data.get('Cloud_Instance_ID'),
                'is_external': asset_data.get('Is_External', False)
            }
            
            # Remove None values
            asset_jsonb = {k: v for k, v in asset_jsonb.items() if v is not None}
            
            # Call the database function with the new signature
            result = self.client.rpc('upsert_asset', {
                'p_asset_class': 'Host',  # Nessus scans are for hosts
                'p_asset_data': asset_jsonb,
                'p_scan_session_id': self.current_scan_session_id
            }).execute()
            
            if result.data:
                asset_id = result.data
                logger.debug(f"✅ Upserted host asset {hostname} ({ip_address}) -> {asset_id}")
                return asset_id
            else:
                raise Exception("No asset ID returned from upsert")
                
        except Exception as e:
            logger.error(f"❌ Failed to upsert asset {asset_data.get('Asset_Name', 'unknown')}: {e}")
            raise
    
    def upsert_vulnerability_definition(self, vuln_data: Dict) -> str:
        """
        Upsert a vulnerability definition (the vulnerability itself, not a finding)
        
        Args:
            vuln_data: Dictionary containing vulnerability information
            
        Returns:
            UUID of the vulnerability definition
        """
        try:
            plugin_id = vuln_data.get('Plugin_ID', vuln_data.get('plugin_id'))
            if not plugin_id:
                raise ValueError("Plugin ID is required for vulnerability definition")
            
            # Check if vulnerability definition already exists
            existing = self.client.table('vulnerability_definitions').select('id').eq(
                'plugin_id', plugin_id
            ).execute()
            
            if existing.data:
                # Update existing definition
                vuln_def_data = {
                    'vulnerability_name': vuln_data.get('Vulnerability_Name', vuln_data.get('name', '')),
                    'family': vuln_data.get('Family', vuln_data.get('family')),
                    'cvss_base_score': self._safe_float(vuln_data.get('CVSS_Score', vuln_data.get('cvss_base_score'))),
                    'risk_factor': vuln_data.get('Risk', vuln_data.get('risk_factor')),
                    'description': vuln_data.get('Description', vuln_data.get('description')),
                    'solution': vuln_data.get('Solution', vuln_data.get('solution')),
                    'synopsis': vuln_data.get('Synopsis', vuln_data.get('synopsis')),
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
                
                # Remove None values
                vuln_def_data = {k: v for k, v in vuln_def_data.items() if v is not None}
                
                result = self.client.table('vulnerability_definitions').update(vuln_def_data).eq(
                    'id', existing.data[0]['id']
                ).execute()
                
                return existing.data[0]['id']
            else:
                # Create new definition
                vuln_def_data = {
                    'plugin_id': plugin_id,
                    'vulnerability_name': vuln_data.get('Vulnerability_Name', vuln_data.get('name', '')),
                    'family': vuln_data.get('Family', vuln_data.get('family')),
                    'cvss_base_score': self._safe_float(vuln_data.get('CVSS_Score', vuln_data.get('cvss_base_score'))),
                    'risk_factor': vuln_data.get('Risk', vuln_data.get('risk_factor')),
                    'description': vuln_data.get('Description', vuln_data.get('description')),
                    'solution': vuln_data.get('Solution', vuln_data.get('solution')),
                    'synopsis': vuln_data.get('Synopsis', vuln_data.get('synopsis'))
                }
                
                # Remove None values
                vuln_def_data = {k: v for k, v in vuln_def_data.items() if v is not None}
                
                result = self.client.table('vulnerability_definitions').insert(vuln_def_data).execute()
                
                if result.data:
                    vuln_id = result.data[0]['id']
                    logger.debug(f"✅ Created vulnerability definition {plugin_id} -> {vuln_id}")
                    return vuln_id
                else:
                    raise Exception("No vulnerability ID returned from insert")
                    
        except Exception as e:
            logger.error(f"❌ Failed to upsert vulnerability definition {plugin_id}: {e}")
            raise
    
    def insert_vulnerability_scan(self, asset_id: str, vulnerability_id: str, 
                                scan_data: Dict) -> str:
        """
        Insert a vulnerability scan finding (time series data)
        
        Args:
            asset_id: UUID of the asset
            vulnerability_id: UUID of the vulnerability definition
            scan_data: Dictionary containing scan-specific data
            
        Returns:
            UUID of the vulnerability scan record
        """
        try:
            if not self.current_scan_session_id:
                raise ValueError("No current scan session. Call create_scan_session first.")
            
            scan_date = datetime.now(timezone.utc)
            
            vuln_scan_data = {
                'asset_id': asset_id,
                'vulnerability_id': vulnerability_id,
                'scan_session_id': self.current_scan_session_id,
                'port': self._safe_int(scan_data.get('Port')),
                'protocol': scan_data.get('Protocol', 'tcp'),
                'service': scan_data.get('Service'),
                'status': scan_data.get('Status', 'open'),
                'severity': scan_data.get('Severity', scan_data.get('Risk', 'Unknown')),
                'first_seen': scan_date.isoformat(),
                'last_seen': scan_date.isoformat(),
                'scan_date': scan_date.isoformat(),
                'plugin_output': scan_data.get('Plugin_Output'),
                'proof': scan_data.get('Proof'),
                'remediation_status': 'open',
                'business_impact': 'unknown',
                'exploitability': 'unknown'
            }
            
            # Remove None values
            vuln_scan_data = {k: v for k, v in vuln_scan_data.items() if v is not None}
            
            result = self.client.table('vulnerability_scans').insert(vuln_scan_data).execute()
            
            if result.data:
                scan_id = result.data[0]['id']
                logger.debug(f"✅ Inserted vulnerability scan -> {scan_id}")
                return scan_id
            else:
                raise Exception("No scan ID returned from insert")
                
        except Exception as e:
            logger.error(f"❌ Failed to insert vulnerability scan: {e}")
            raise
    
    def load_with_business_context(self, assets: List[Dict], vulnerabilities: List[Dict],
                                  business_rules: Dict = None, apply_dynamic_tags: bool = True):
        """
        Load assets and vulnerabilities with business context support
        
        Args:
            assets: List of asset dictionaries
            vulnerabilities: List of vulnerability dictionaries
            business_rules: Optional business rules configuration
            apply_dynamic_tags: Whether to apply dynamic tags after loading
        """
        # First load assets and vulnerabilities as normal
        assets_loaded = self.load_assets(assets)
        vulns_loaded = self.load_vulnerabilities(vulnerabilities)
        
        # Initialize business context manager
        from .business_context_manager import BusinessContextManager
        context_manager = BusinessContextManager(self.client)
        
        # Apply imported tags from scanner
        for asset in assets:
            if 'tags' in asset and asset['tags']:
                # Get the asset ID we just created
                asset_result = self.client.table('assets').select('id').eq(
                    'current_ip_address', asset.get('Asset_IP')
                ).order('created_at', desc=True).limit(1).execute()
                
                if asset_result.data:
                    asset_id = asset_result.data[0]['id']
                    
                    for tag_name in asset['tags']:
                        # Create or get tag
                        try:
                            tag_id = context_manager.create_tag(
                                name=f"#{tag_name}" if not tag_name.startswith('#') else tag_name,
                                tag_type='imported',
                                source_connector='nessus',
                                description=f"Imported from Nessus scan"
                            )
                            # Assign to asset
                            context_manager.apply_tag_to_assets([asset_id], tag_id)
                        except:
                            # Tag might already exist, try to find it
                            tag_result = self.client.table('asset_tags').select('id').eq(
                                'name', f"#{tag_name}" if not tag_name.startswith('#') else tag_name
                            ).execute()
                            if tag_result.data:
                                context_manager.apply_tag_to_assets([asset_id], tag_result.data[0]['id'])
        
        # Apply dynamic tags based on rules
        if apply_dynamic_tags:
            context_manager.apply_dynamic_tags(self.current_scan_session_id)
        
        # Auto-assign to business groups based on rules
        if business_rules:
            self._apply_business_group_rules(business_rules, context_manager)
            
        logger.info(f"✅ Loaded {assets_loaded} assets and {vulns_loaded} vulnerabilities with business context")
        
        return {
            'assets_loaded': assets_loaded,
            'vulnerabilities_loaded': vulns_loaded
        }
    
    def _apply_business_group_rules(self, business_rules: Dict, context_manager):
        """Apply business group assignment rules"""
        for bg_rule in business_rules.get('business_groups', []):
            # Get or create business group
            bg_result = self.client.table('business_groups').select('id').eq(
                'name', bg_rule['name']
            ).execute()
            
            if bg_result.data:
                bg_id = bg_result.data[0]['id']
            else:
                # Create if doesn't exist
                parent_id = None
                if 'parent' in bg_rule:
                    parent_result = self.client.table('business_groups').select('id').eq(
                        'name', bg_rule['parent']
                    ).execute()
                    if parent_result.data:
                        parent_id = parent_result.data[0]['id']
                
                bg_id = context_manager.create_business_group(
                    name=bg_rule['name'],
                    parent_id=parent_id,
                    description=bg_rule.get('description')
                )
            
            # Find matching assets based on rules
            matching_assets = []
            for rule in bg_rule.get('rules', []):
                if rule['type'] == 'tag_match':
                    # Find assets with specific tags
                    for tag_name in rule['tags']:
                        tag_result = self.client.table('asset_tags').select('id').eq(
                            'name', f"#{tag_name}" if not tag_name.startswith('#') else tag_name
                        ).execute()
                        
                        if tag_result.data:
                            assignments = self.client.table('asset_tag_assignments').select(
                                'asset_id'
                            ).eq('tag_id', tag_result.data[0]['id']).execute()
                            
                            matching_assets.extend([a['asset_id'] for a in assignments.data])
                
                elif rule['type'] == 'ip_range':
                    # This would use the same logic as dynamic tags
                    pass
                    
                elif rule['type'] == 'hostname_pattern':
                    # Find assets matching hostname patterns
                    for pattern in rule['patterns']:
                        sql_pattern = pattern.replace('*', '%').replace('?', '_')
                        assets = self.client.table('assets').select('id').ilike(
                            'current_hostname', sql_pattern
                        ).eq('is_active', True).execute()
                        
                        matching_assets.extend([a['id'] for a in assets.data])
            
            # Assign matching assets to business group
            if matching_assets:
                unique_assets = list(set(matching_assets))
                context_manager.assign_assets_to_business_group(unique_assets, bg_id)
    
    def load_assets(self, assets: List[Dict]) -> int:
        """
        Load assets using the new time series approach
        
        Args:
            assets: List of asset dictionaries
            
        Returns:
            Number of assets processed
        """
        if not assets:
            return 0
        
        processed_count = 0
        
        for asset in assets:
            try:
                asset_id = self.upsert_asset(asset)
                processed_count += 1
            except Exception as e:
                logger.error(f"Failed to process asset {asset.get('Asset_Name', 'unknown')}: {e}")
                continue
        
        logger.info(f"✅ Processed {processed_count}/{len(assets)} assets")
        return processed_count
    
    def load_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        """
        Load vulnerabilities using the new time series approach
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Number of vulnerabilities processed
        """
        if not vulnerabilities:
            return 0
        
        processed_count = 0
        
        for vuln in vulnerabilities:
            try:
                # First, ensure the vulnerability definition exists
                vuln_def_id = self.upsert_vulnerability_definition(vuln)
                
                # Find the asset this vulnerability belongs to
                asset_name = vuln.get('Asset_Name', '')
                asset_ip = vuln.get('IP', vuln.get('Asset_IP', ''))
                
                if not asset_ip:
                    logger.warning(f"No IP address for vulnerability on {asset_name}, skipping")
                    continue
                
                # Find asset by IP (we could enhance this with fingerprinting later)
                asset_result = self.client.table('assets').select('id').eq(
                    'current_ip_address', asset_ip
                ).execute()
                
                if not asset_result.data:
                    logger.warning(f"Asset not found for IP {asset_ip}, skipping vulnerability")
                    continue
                
                asset_id = asset_result.data[0]['id']
                
                # Insert the vulnerability scan finding
                scan_id = self.insert_vulnerability_scan(asset_id, vuln_def_id, vuln)
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Failed to process vulnerability {vuln.get('Vulnerability_Name', 'unknown')}: {e}")
                continue
        
        logger.info(f"✅ Processed {processed_count}/{len(vulnerabilities)} vulnerabilities")
        return processed_count
    
    def get_statistics(self) -> Dict:
        """Get current database statistics"""
        try:
            stats = {}
            
            # Count scan sessions
            scan_sessions = self.client.table('scan_sessions').select('id', count='exact').execute()
            stats['scan_sessions'] = scan_sessions.count
            
            # Count assets
            assets = self.client.table('assets').select('id', count='exact').execute()
            stats['total_assets'] = assets.count
            
            # Count active assets
            active_assets = self.client.table('assets').select('id', count='exact').eq('is_active', True).execute()
            stats['active_assets'] = active_assets.count
            
            # Count vulnerability definitions
            vuln_defs = self.client.table('vulnerability_definitions').select('id', count='exact').execute()
            stats['vulnerability_definitions'] = vuln_defs.count
            
            # Count vulnerability scans
            vuln_scans = self.client.table('vulnerability_scans').select('id', count='exact').execute()
            stats['vulnerability_scans'] = vuln_scans.count
            
            # Count open vulnerabilities
            open_vulns = self.client.table('vulnerability_scans').select('id', count='exact').eq('remediation_status', 'open').execute()
            stats['open_vulnerabilities'] = open_vulns.count
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _safe_int(self, value) -> Optional[int]:
        """Safely convert value to int"""
        if value is None or value == '':
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    
    def _safe_float(self, value) -> Optional[float]:
        """Safely convert value to float"""
        if value is None or value == '':
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
    
    def query_current_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """Query current vulnerabilities using the view"""
        try:
            result = self.client.table('current_vulnerabilities').select('*').limit(limit).execute()
            return result.data
        except Exception as e:
            logger.error(f"Failed to query current vulnerabilities: {e}")
            return []
    
    def query_asset_summary(self, limit: int = 10) -> List[Dict]:
        """Query asset summary using the view"""
        try:
            result = self.client.table('asset_summary').select('*').limit(limit).execute()
            return result.data
        except Exception as e:
            logger.error(f"Failed to query asset summary: {e}")
            return []
    
    def generate_metrics(self) -> bool:
        """
        Generate comprehensive metrics and store them in reporting tables
        
        Returns:
            True if metrics generation was successful
        """
        try:
            logger.info("🔢 Generating comprehensive metrics...")
            
            # Import metrics modules (lazy import to avoid circular dependencies)
            from etl.metrics.mttr_calculator import MTTRCalculator
            from etl.metrics.metrics_generator import MetricsGenerator
            from etl.metrics.reporting_tables import ReportingTablesManager
            
            # Initialize metrics components
            mttr_calculator = MTTRCalculator(self.client)
            metrics_generator = MetricsGenerator(self.client)
            reporting_manager = ReportingTablesManager(self.client)
            
            logger.info("📊 Calculating MTTR metrics...")
            
            # Calculate MTTR metrics
            mttr_overall = mttr_calculator.calculate_overall_mttr()
            mttr_by_risk = mttr_calculator.calculate_mttr_by_risk_level()
            mttr_by_group = mttr_calculator.calculate_mttr_by_business_group()
            mttr_by_type = mttr_calculator.calculate_mttr_by_asset_type()
            
            logger.info("📈 Generating comprehensive metrics...")
            
            # Generate comprehensive metrics
            metrics = metrics_generator.generate_comprehensive_metrics()
            
            logger.info("💾 Storing metrics in reporting tables...")
            
            # Store metrics snapshot
            snapshot_id = reporting_manager.store_metrics_snapshot(metrics)
            
            # Update MTTR history
            if mttr_overall is not None:
                reporting_manager.update_mttr_history(
                    mttr_days=mttr_overall,
                    mttr_by_risk_level=mttr_by_risk,
                    mttr_by_business_group=mttr_by_group,
                    mttr_by_asset_type=mttr_by_type
                )
            
            logger.info(f"✅ Metrics generated successfully (snapshot: {snapshot_id})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to generate metrics: {e}")
            return False 