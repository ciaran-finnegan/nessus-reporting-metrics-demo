import json
import re
from typing import List, Dict, Optional, Set
from datetime import datetime, timezone
import logging
from supabase import Client
import ipaddress

logger = logging.getLogger(__name__)

class BusinessContextManager:
    """
    Manages Business Groups and Asset Tags following Vulcan Cyber's approach
    
    Features:
    - Hierarchical Business Groups with parent/child relationships
    - Dynamic and static asset tags
    - Automatic tag application based on rules
    - Asset criticality scoring
    - Business context-aware vulnerability prioritization
    """
    
    def __init__(self, supabase_client: Client):
        self.client = supabase_client
        
    def create_business_group(self, name: str, parent_id: Optional[str] = None, 
                            description: str = None, metadata: Dict = None,
                            color: str = None, icon: str = None) -> str:
        """
        Create a business group with optional parent
        
        Args:
            name: Business group name
            parent_id: UUID of parent business group (optional)
            description: Description of the business group
            metadata: Additional metadata as JSONB
            color: Hex color for UI display (e.g., '#FF5733')
            icon: Icon identifier for UI
            
        Returns:
            UUID of created business group
        """
        try:
            # Get parent path if exists
            parent_path = "/"
            depth = 0
            
            if parent_id:
                parent_result = self.client.table('business_groups').select(
                    'path, depth'
                ).eq('id', parent_id).execute()
                
                if parent_result.data:
                    parent_path = parent_result.data[0]['path']
                    depth = parent_result.data[0]['depth'] + 1
                else:
                    raise ValueError(f"Parent business group {parent_id} not found")
            
            # Create the business group
            bg_data = {
                'name': name,
                'parent_id': parent_id,
                'path': f"{parent_path}{name}/",
                'depth': depth,
                'description': description,
                'color': color,
                'icon': icon,
                'metadata': metadata or {}
            }
            
            result = self.client.table('business_groups').insert(bg_data).execute()
            
            if result.data:
                logger.info(f"✅ Created business group '{name}' with ID: {result.data[0]['id']}")
                return result.data[0]['id']
            else:
                raise Exception("Failed to create business group")
                
        except Exception as e:
            logger.error(f"❌ Failed to create business group '{name}': {e}")
            raise
    
    def create_tag(self, name: str, tag_type: str = 'manual', 
                  rule_definition: Dict = None, **kwargs) -> str:
        """
        Create an asset tag
        
        Args:
            name: Tag name (e.g., '#production', '#external-facing')
            tag_type: 'manual', 'imported', or 'dynamic'
            rule_definition: Rule definition for dynamic tags
            **kwargs: Additional fields (description, color, is_favorite, criticality_score, etc.)
            
        Returns:
            UUID of created tag
        """
        try:
            tag_data = {
                'name': name,
                'tag_type': tag_type,
                'description': kwargs.get('description'),
                'color': kwargs.get('color'),
                'is_favorite': kwargs.get('is_favorite', False),
                'rule_definition': rule_definition,
                'evaluate_on_creation': kwargs.get('evaluate_on_creation', True),
                'source_connector': kwargs.get('source_connector'),
                'source_id': kwargs.get('source_id'),
                'metadata': kwargs.get('metadata', {})
            }
            
            # Add criticality score to metadata if provided
            if 'criticality_score' in kwargs:
                tag_data['metadata']['criticality_score'] = kwargs['criticality_score']
            
            # Remove None values
            tag_data = {k: v for k, v in tag_data.items() if v is not None}
            
            result = self.client.table('asset_tags').insert(tag_data).execute()
            
            if result.data:
                logger.info(f"✅ Created tag '{name}' with ID: {result.data[0]['id']}")
                return result.data[0]['id']
            else:
                raise Exception("Failed to create tag")
                
        except Exception as e:
            logger.error(f"❌ Failed to create tag '{name}': {e}")
            raise
    
    def assign_assets_to_business_group(self, asset_ids: List[str], 
                                      business_group_id: str,
                                      assigned_by: str = None) -> int:
        """
        Assign multiple assets to a business group
        
        Args:
            asset_ids: List of asset UUIDs
            business_group_id: Business group UUID
            assigned_by: User who made the assignment
            
        Returns:
            Number of assets assigned
        """
        try:
            assignments = [
                {
                    'asset_id': asset_id,
                    'business_group_id': business_group_id,
                    'assigned_at': datetime.now(timezone.utc).isoformat(),
                    'assigned_by': assigned_by
                }
                for asset_id in asset_ids
            ]
            
            result = self.client.table('asset_business_groups').upsert(
                assignments,
                on_conflict='asset_id,business_group_id'
            ).execute()
            
            count = len(result.data) if result.data else 0
            logger.info(f"✅ Assigned {count} assets to business group {business_group_id}")
            return count
            
        except Exception as e:
            logger.error(f"❌ Failed to assign assets to business group: {e}")
            raise
    
    def apply_tag_to_assets(self, asset_ids: List[str], tag_id: str,
                          auto_applied: bool = False, assigned_by: str = None) -> int:
        """
        Apply a tag to multiple assets
        
        Args:
            asset_ids: List of asset UUIDs
            tag_id: Tag UUID
            auto_applied: Whether tag was applied by dynamic rule
            assigned_by: User who made the assignment
            
        Returns:
            Number of assets tagged
        """
        try:
            assignments = [
                {
                    'asset_id': asset_id,
                    'tag_id': tag_id,
                    'assigned_at': datetime.now(timezone.utc).isoformat(),
                    'assigned_by': assigned_by,
                    'auto_applied': auto_applied
                }
                for asset_id in asset_ids
            ]
            
            result = self.client.table('asset_tag_assignments').upsert(
                assignments,
                on_conflict='asset_id,tag_id'
            ).execute()
            
            count = len(result.data) if result.data else 0
            logger.info(f"✅ Applied tag {tag_id} to {count} assets")
            return count
            
        except Exception as e:
            logger.error(f"❌ Failed to apply tag to assets: {e}")
            raise
    
    def apply_dynamic_tags(self, scan_session_id: str = None):
        """
        Evaluate and apply all dynamic tag rules
        
        Args:
            scan_session_id: Optional scan session to limit evaluation scope
        """
        try:
            # Get all dynamic tags that should be evaluated
            dynamic_tags = self.client.table('asset_tags').select('*').eq(
                'tag_type', 'dynamic'
            ).eq('evaluate_on_creation', True).execute()
            
            logger.info(f"🔍 Evaluating {len(dynamic_tags.data)} dynamic tags")
            
            for tag in dynamic_tags.data:
                if tag.get('rule_definition'):
                    self._evaluate_tag_rule(tag, scan_session_id)
                    
        except Exception as e:
            logger.error(f"❌ Failed to apply dynamic tags: {e}")
            raise
    
    def _evaluate_tag_rule(self, tag: Dict, scan_session_id: str = None):
        """
        Evaluate a single dynamic tag rule and apply to matching assets
        
        Args:
            tag: Tag dictionary with rule_definition
            scan_session_id: Optional scan session to limit scope
        """
        try:
            rule_def = tag['rule_definition']
            rule_type = rule_def.get('type')
            matching_assets = []
            
            logger.debug(f"Evaluating rule type '{rule_type}' for tag '{tag['name']}'")
            
            if rule_type == 'ip_range':
                # Apply tag to assets in IP range
                matching_assets = self._find_assets_by_ip_range(rule_def.get('ranges', []))
                
            elif rule_type == 'asset_name_contains':
                # Apply tag when asset name contains substring
                matching_assets = self._find_assets_by_name_pattern(rule_def.get('patterns', []))
                
            elif rule_type == 'external_facing':
                # Apply tag to external-facing assets
                matching_assets = self._find_external_assets()
                
            elif rule_type == 'vulnerability_exists':
                # Apply tag to assets with specific vulnerabilities
                matching_assets = self._find_assets_with_vulnerabilities(
                    rule_def.get('plugin_ids', []),
                    rule_def.get('severity', []),
                    scan_session_id
                )
                
            elif rule_type == 'operating_system':
                # Apply tag based on OS
                matching_assets = self._find_assets_by_os(rule_def.get('os_patterns', []))
                
            elif rule_type == 'asset_type':
                # Apply tag based on asset type
                matching_assets = self._find_assets_by_type(
                    rule_def.get('asset_class'),
                    rule_def.get('asset_types', [])
                )
                
            elif rule_type == 'cloud_provider':
                # Apply tag based on cloud provider
                matching_assets = self._find_cloud_assets(rule_def.get('providers', []))
            
            # Apply tags to matching assets
            if matching_assets:
                self.apply_tag_to_assets(matching_assets, tag['id'], auto_applied=True)
                
            # Update last evaluated timestamp
            self.client.table('asset_tags').update({
                'last_evaluated': datetime.now(timezone.utc).isoformat()
            }).eq('id', tag['id']).execute()
            
            logger.info(f"✅ Applied tag '{tag['name']}' to {len(matching_assets)} assets")
            
        except Exception as e:
            logger.error(f"❌ Failed to evaluate tag rule '{tag['name']}': {e}")
    
    def _find_assets_by_ip_range(self, ip_ranges: List[str]) -> List[str]:
        """Find assets within specified IP ranges"""
        matching_assets = []
        
        for ip_range in ip_ranges:
            try:
                # Parse the IP range
                network = ipaddress.ip_network(ip_range, strict=False)
                
                # Query assets and check if IP is in range
                # Note: This is simplified - in production you'd want to do this more efficiently
                assets = self.client.table('assets').select(
                    'id, current_ip_address'
                ).eq('asset_class', 'Host').eq('is_active', True).execute()
                
                for asset in assets.data:
                    if asset.get('current_ip_address'):
                        try:
                            ip = ipaddress.ip_address(asset['current_ip_address'])
                            if ip in network:
                                matching_assets.append(asset['id'])
                        except:
                            continue
                            
            except Exception as e:
                logger.warning(f"Invalid IP range '{ip_range}': {e}")
                
        return list(set(matching_assets))
    
    def _find_assets_by_name_pattern(self, patterns: List[str]) -> List[str]:
        """Find assets with names matching patterns"""
        matching_assets = []
        
        for pattern in patterns:
            # Convert wildcard pattern to SQL LIKE pattern
            sql_pattern = pattern.replace('*', '%').replace('?', '_')
            
            assets = self.client.table('assets').select('id').ilike(
                'current_hostname', sql_pattern
            ).eq('is_active', True).execute()
            
            matching_assets.extend([a['id'] for a in assets.data])
            
        return list(set(matching_assets))
    
    def _find_external_assets(self) -> List[str]:
        """Find external-facing assets"""
        assets = self.client.table('assets').select('id').eq(
            'is_external', True
        ).eq('is_active', True).execute()
        
        return [a['id'] for a in assets.data]
    
    def _find_assets_with_vulnerabilities(self, plugin_ids: List[str], 
                                        severities: List[str],
                                        scan_session_id: str = None) -> List[str]:
        """Find assets with specific vulnerabilities"""
        query = self.client.table('vulnerability_scans').select('asset_id')
        
        if plugin_ids:
            # First get vulnerability definition IDs for these plugin IDs
            vuln_defs = self.client.table('vulnerability_definitions').select(
                'id'
            ).in_('plugin_id', plugin_ids).execute()
            
            vuln_ids = [v['id'] for v in vuln_defs.data]
            if vuln_ids:
                query = query.in_('vulnerability_id', vuln_ids)
        
        if severities:
            query = query.in_('severity', severities)
            
        if scan_session_id:
            query = query.eq('scan_session_id', scan_session_id)
            
        query = query.eq('remediation_status', 'open')
        
        result = query.execute()
        return list(set([r['asset_id'] for r in result.data]))
    
    def _find_assets_by_os(self, os_patterns: List[str]) -> List[str]:
        """Find assets by operating system patterns"""
        matching_assets = []
        
        for pattern in os_patterns:
            sql_pattern = pattern.replace('*', '%').replace('?', '_')
            
            assets = self.client.table('assets').select('id').ilike(
                'operating_system', sql_pattern
            ).eq('is_active', True).execute()
            
            matching_assets.extend([a['id'] for a in assets.data])
            
        return list(set(matching_assets))
    
    def _find_assets_by_type(self, asset_class: str = None, 
                           asset_types: List[str] = None) -> List[str]:
        """Find assets by asset class and/or type"""
        query = self.client.table('assets').select('id').eq('is_active', True)
        
        if asset_class:
            query = query.eq('asset_class', asset_class)
            
        if asset_types:
            query = query.in_('asset_type', asset_types)
            
        result = query.execute()
        return [a['id'] for a in result.data]
    
    def _find_cloud_assets(self, providers: List[str]) -> List[str]:
        """Find cloud assets by provider"""
        assets = self.client.table('assets').select('id').eq(
            'asset_class', 'Cloud Resource'
        ).in_('cloud_provider', providers).eq('is_active', True).execute()
        
        return [a['id'] for a in assets.data]
    
    def create_default_business_groups(self):
        """
        Create a default business group structure as an example
        Following Vulcan Cyber's best practices
        """
        try:
            # Create root groups
            geographic_id = self.create_business_group(
                "Geographic Regions",
                description="Assets organized by geographic location"
            )
            
            departments_id = self.create_business_group(
                "Departments",
                description="Assets organized by department"
            )
            
            environments_id = self.create_business_group(
                "Environments",
                description="Assets organized by environment type"
            )
            
            # Create geographic sub-groups
            emea_id = self.create_business_group("EMEA", geographic_id)
            apac_id = self.create_business_group("APAC", geographic_id)
            americas_id = self.create_business_group("Americas", geographic_id)
            
            # Create department sub-groups
            self.create_business_group("Finance", departments_id)
            self.create_business_group("HR", departments_id)
            self.create_business_group("IT", departments_id)
            self.create_business_group("R&D", departments_id)
            
            # Create environment sub-groups
            self.create_business_group("Production", environments_id)
            self.create_business_group("Staging", environments_id)
            self.create_business_group("Development", environments_id)
            self.create_business_group("Test", environments_id)
            
            logger.info("✅ Created default business group structure")
            
        except Exception as e:
            logger.error(f"❌ Failed to create default business groups: {e}")
    
    def create_default_dynamic_tags(self):
        """
        Create default dynamic tags following Vulcan Cyber's approach
        """
        try:
            # External-facing assets tag
            self.create_tag(
                name="#external-facing",
                tag_type="dynamic",
                description="Assets exposed to the internet",
                criticality_score=5,
                color="#FF0000",
                is_favorite=True,
                rule_definition={
                    "type": "external_facing"
                }
            )
            
            # Critical vulnerabilities tag
            self.create_tag(
                name="#critical-vulnerabilities",
                tag_type="dynamic",
                description="Assets with critical severity vulnerabilities",
                criticality_score=4,
                color="#FF4500",
                is_favorite=True,
                rule_definition={
                    "type": "vulnerability_exists",
                    "severity": ["Critical"]
                }
            )
            
            # Windows servers tag
            self.create_tag(
                name="#windows-servers",
                tag_type="dynamic",
                description="Windows Server operating systems",
                rule_definition={
                    "type": "operating_system",
                    "os_patterns": ["*Windows Server*"]
                }
            )
            
            # Production environment tag
            self.create_tag(
                name="#production",
                tag_type="dynamic",
                description="Production environment assets",
                criticality_score=4,
                color="#00FF00",
                rule_definition={
                    "type": "asset_name_contains",
                    "patterns": ["prod-*", "*-prod", "*-prd"]
                }
            )
            
            logger.info("✅ Created default dynamic tags")
            
        except Exception as e:
            logger.error(f"❌ Failed to create default dynamic tags: {e}") 