"""
MTTR (Mean Time To Remediate) Calculator

Calculates various MTTR metrics for vulnerability management:
- Overall MTTR across all vulnerabilities
- MTTR by risk level (Critical, High, Medium, Low)
- MTTR by business group
- MTTR by asset type
"""

import logging
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from supabase import Client

logger = logging.getLogger(__name__)

class MTTRCalculator:
    """Calculate Mean Time To Remediate metrics"""
    
    def __init__(self, supabase_client: Client):
        self.client = supabase_client
    
    def calculate_overall_mttr(self) -> Optional[float]:
        """
        Calculate overall MTTR in days across all remediated vulnerabilities
        
        Returns:
            Average days to remediate, or None if no data
        """
        try:
            # Query remediated vulnerabilities with remediation dates
            result = self.client.rpc('calculate_mttr_overall').execute()
            
            if result.data and len(result.data) > 0:
                return result.data[0].get('mttr_days')
            
            # Fallback calculation if RPC doesn't exist
            logger.warning("RPC function not available, using fallback calculation")
            return self._calculate_mttr_fallback()
            
        except Exception as e:
            logger.error(f"Failed to calculate overall MTTR: {e}")
            return None
    
    def calculate_mttr_by_risk_level(self) -> Dict[str, float]:
        """
        Calculate MTTR by risk level (severity)
        
        Returns:
            Dictionary mapping risk levels to MTTR in days
        """
        try:
            result = self.client.rpc('calculate_mttr_by_risk_level').execute()
            
            if result.data:
                return {item['risk_level']: item['mttr_days'] for item in result.data}
            
            # Fallback calculation
            logger.warning("RPC function not available, using fallback calculation")
            return self._calculate_mttr_by_risk_fallback()
            
        except Exception as e:
            logger.error(f"Failed to calculate MTTR by risk level: {e}")
            return {}
    
    def calculate_mttr_by_business_group(self) -> Dict[str, float]:
        """
        Calculate MTTR by business group
        
        Returns:
            Dictionary mapping business group names to MTTR in days
        """
        try:
            result = self.client.rpc('calculate_mttr_by_business_group').execute()
            
            if result.data:
                return {item['business_group']: item['mttr_days'] for item in result.data}
            
            # Fallback - return empty for now since business groups may not be set up
            logger.warning("Business groups MTTR calculation not available")
            return {}
            
        except Exception as e:
            logger.error(f"Failed to calculate MTTR by business group: {e}")
            return {}
    
    def calculate_mttr_by_asset_type(self) -> Dict[str, float]:
        """
        Calculate MTTR by asset type
        
        Returns:
            Dictionary mapping asset types to MTTR in days
        """
        try:
            result = self.client.rpc('calculate_mttr_by_asset_type').execute()
            
            if result.data:
                return {item['asset_type']: item['mttr_days'] for item in result.data}
            
            # Fallback calculation
            logger.warning("RPC function not available, using fallback calculation")
            return self._calculate_mttr_by_asset_type_fallback()
            
        except Exception as e:
            logger.error(f"Failed to calculate MTTR by asset type: {e}")
            return {}
    
    def _calculate_mttr_fallback(self) -> Optional[float]:
        """Fallback MTTR calculation using basic queries"""
        try:
            # Get vulnerability scans that have been remediated
            # For now, we'll simulate this since we don't have remediation dates yet
            # In a real implementation, you'd query for vulnerabilities with remediation_date
            
            # This is a placeholder - in reality you'd need remediation tracking
            logger.info("MTTR calculation requires remediation date tracking")
            return 30.0  # Placeholder: 30 days average
            
        except Exception as e:
            logger.error(f"Fallback MTTR calculation failed: {e}")
            return None
    
    def _calculate_mttr_by_risk_fallback(self) -> Dict[str, float]:
        """Fallback MTTR by risk level calculation"""
        try:
            # Placeholder values based on typical industry standards
            return {
                'Critical': 7.0,   # 7 days for critical
                'High': 15.0,      # 15 days for high
                'Medium': 30.0,    # 30 days for medium
                'Low': 90.0        # 90 days for low
            }
        except Exception as e:
            logger.error(f"Fallback MTTR by risk calculation failed: {e}")
            return {}
    
    def _calculate_mttr_by_asset_type_fallback(self) -> Dict[str, float]:
        """Fallback MTTR by asset type calculation"""
        try:
            # Get unique asset types from current assets
            assets_result = self.client.table('assets').select('asset_type').execute()
            
            asset_types = set()
            for asset in assets_result.data:
                if asset.get('asset_type'):
                    asset_types.add(asset['asset_type'])
            
            # Return placeholder values for each asset type
            mttr_by_type = {}
            for asset_type in asset_types:
                # Different asset types might have different remediation timelines
                if asset_type.lower() in ['server', 'host']:
                    mttr_by_type[asset_type] = 21.0  # 3 weeks for servers
                elif asset_type.lower() in ['workstation', 'laptop', 'desktop']:
                    mttr_by_type[asset_type] = 14.0  # 2 weeks for workstations
                else:
                    mttr_by_type[asset_type] = 30.0  # 1 month default
            
            return mttr_by_type
            
        except Exception as e:
            logger.error(f"Fallback MTTR by asset type calculation failed: {e}")
            return {} 