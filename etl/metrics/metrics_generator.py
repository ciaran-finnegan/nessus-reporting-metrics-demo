"""
Comprehensive Metrics Generator

Generates various vulnerability management metrics including:
- Remediation capacity metrics
- Daily remediation rates
- Campaign coverage
- Business group performance
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from supabase import Client

logger = logging.getLogger(__name__)

class MetricsGenerator:
    """Generate comprehensive vulnerability management metrics"""
    
    def __init__(self, supabase_client: Client):
        self.client = supabase_client
    
    def generate_comprehensive_metrics(self) -> Dict:
        """
        Generate all metrics in one comprehensive report
        
        Returns:
            Dictionary containing all calculated metrics
        """
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'remediation_capacity': self.calculate_remediation_capacity(),
                'daily_remediation': self.calculate_average_daily_remediation(),
                'campaign_coverage': self.calculate_campaign_coverage(),
                'remediation_by_business_group': self.calculate_remediation_by_business_group(),
                'remediation_capacity_by_risk': self.calculate_remediation_capacity_by_risk_level(),
                'vulnerability_trends': self.get_vulnerability_trends(),
                'asset_coverage': self.calculate_asset_coverage()
            }
            
            logger.info("✅ Generated comprehensive metrics")
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to generate comprehensive metrics: {e}")
            return {}
    
    def calculate_remediation_capacity(self) -> Dict:
        """
        Calculate remediation capacity metrics
        
        Returns:
            Dictionary with remediation vs introduction rates
        """
        try:
            # Get vulnerability counts over time
            # This is a simplified calculation - in reality you'd track remediation events
            
            # Get total vulnerabilities
            total_vulns = self.client.table('vulnerability_scans').select('id', count='exact').execute()
            total_count = total_vulns.count or 0
            
            # Get open vulnerabilities
            open_vulns = self.client.table('vulnerability_scans').select('id', count='exact').eq('remediation_status', 'open').execute()
            open_count = open_vulns.count or 0
            
            # Calculate basic capacity metrics
            remediated_count = total_count - open_count
            remediation_rate = (remediated_count / total_count * 100) if total_count > 0 else 0
            
            return {
                'total_vulnerabilities': total_count,
                'open_vulnerabilities': open_count,
                'remediated_vulnerabilities': remediated_count,
                'remediation_rate_percentage': round(remediation_rate, 2),
                'capacity_utilization': 'medium'  # Placeholder
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate remediation capacity: {e}")
            return {}
    
    def calculate_average_daily_remediation(self) -> Dict:
        """
        Calculate average daily remediation rate
        
        Returns:
            Dictionary with daily remediation statistics
        """
        try:
            # This would typically track remediation events over time
            # For now, we'll provide estimated values based on current data
            
            # Get scan sessions to estimate timeline
            sessions = self.client.table('scan_sessions').select('scan_date').order('scan_date').execute()
            
            if len(sessions.data) < 2:
                return {
                    'average_daily_remediation': 0,
                    'trend': 'insufficient_data',
                    'period_days': 0
                }
            
            # Calculate time period
            first_scan = datetime.fromisoformat(sessions.data[0]['scan_date'].replace('Z', '+00:00'))
            last_scan = datetime.fromisoformat(sessions.data[-1]['scan_date'].replace('Z', '+00:00'))
            period_days = (last_scan - first_scan).days or 1
            
            # Estimate daily remediation (placeholder calculation)
            total_vulns = self.client.table('vulnerability_scans').select('id', count='exact').execute()
            estimated_daily = (total_vulns.count or 0) / period_days if period_days > 0 else 0
            
            return {
                'average_daily_remediation': round(estimated_daily, 2),
                'trend': 'stable',
                'period_days': period_days,
                'total_period_vulnerabilities': total_vulns.count or 0
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate daily remediation: {e}")
            return {}
    
    def calculate_campaign_coverage(self) -> Dict:
        """
        Calculate campaign coverage metrics
        
        Returns:
            Dictionary with campaign effectiveness data
        """
        try:
            # Get scan sessions as proxy for campaigns
            campaigns = self.client.table('scan_sessions').select('*').execute()
            
            # Get unique assets covered
            assets = self.client.table('assets').select('id', count='exact').eq('is_active', True).execute()
            
            return {
                'total_campaigns': len(campaigns.data),
                'assets_covered': assets.count or 0,
                'campaign_effectiveness': 'high',  # Placeholder
                'coverage_percentage': 100.0  # Assuming full coverage for now
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate campaign coverage: {e}")
            return {}
    
    def calculate_remediation_by_business_group(self) -> Dict:
        """
        Calculate remediation metrics by business group
        
        Returns:
            Dictionary mapping business groups to remediation metrics
        """
        try:
            # This would require business group assignments
            # For now, return placeholder data
            
            business_groups = self.client.table('business_groups').select('*').execute()
            
            if not business_groups.data:
                return {
                    'message': 'No business groups configured',
                    'groups': {}
                }
            
            group_metrics = {}
            for group in business_groups.data:
                group_name = group['name']
                group_metrics[group_name] = {
                    'total_vulnerabilities': 0,
                    'remediated_vulnerabilities': 0,
                    'remediation_rate': 0.0,
                    'average_mttr_days': 30.0
                }
            
            return group_metrics
            
        except Exception as e:
            logger.error(f"Failed to calculate remediation by business group: {e}")
            return {}
    
    def calculate_remediation_capacity_by_risk_level(self) -> Dict:
        """
        Calculate remediation capacity broken down by risk level
        
        Returns:
            Dictionary mapping risk levels to capacity metrics
        """
        try:
            # Get vulnerability counts by severity
            risk_levels = ['Critical', 'High', 'Medium', 'Low']
            capacity_by_risk = {}
            
            for risk_level in risk_levels:
                # Get vulnerabilities for this risk level
                vulns = self.client.table('vulnerability_scans').select('id', count='exact').eq('severity', risk_level).execute()
                total = vulns.count or 0
                
                # Get open vulnerabilities for this risk level
                open_vulns = self.client.table('vulnerability_scans').select('id', count='exact').eq('severity', risk_level).eq('remediation_status', 'open').execute()
                open_count = open_vulns.count or 0
                
                remediated = total - open_count
                rate = (remediated / total * 100) if total > 0 else 0
                
                capacity_by_risk[risk_level] = {
                    'total_vulnerabilities': total,
                    'open_vulnerabilities': open_count,
                    'remediated_vulnerabilities': remediated,
                    'remediation_rate_percentage': round(rate, 2)
                }
            
            return capacity_by_risk
            
        except Exception as e:
            logger.error(f"Failed to calculate remediation capacity by risk level: {e}")
            return {}
    
    def get_vulnerability_trends(self) -> Dict:
        """
        Get vulnerability trend data
        
        Returns:
            Dictionary with trend information
        """
        try:
            # Get top vulnerabilities by count
            trends = self.client.table('vulnerability_trends').select('*').order('affected_assets', desc=True).limit(10).execute()
            
            trend_data = []
            for trend in trends.data:
                trend_data.append({
                    'vulnerability_name': trend['vulnerability_name'],
                    'affected_assets': trend['affected_assets'],
                    'currently_open': trend['currently_open'],
                    'trend': 'stable'  # Placeholder
                })
            
            return {
                'top_vulnerabilities': trend_data,
                'total_unique_vulnerabilities': len(trends.data)
            }
            
        except Exception as e:
            logger.error(f"Failed to get vulnerability trends: {e}")
            return {}
    
    def calculate_asset_coverage(self) -> Dict:
        """
        Calculate asset coverage metrics
        
        Returns:
            Dictionary with asset coverage data
        """
        try:
            # Get total assets
            total_assets = self.client.table('assets').select('id', count='exact').execute()
            
            # Get active assets
            active_assets = self.client.table('assets').select('id', count='exact').eq('is_active', True).execute()
            
            # Get assets with vulnerabilities
            assets_with_vulns = self.client.table('current_vulnerabilities').select('asset_id').execute()
            unique_vulnerable_assets = len(set(item['asset_id'] for item in assets_with_vulns.data))
            
            total_count = total_assets.count or 0
            active_count = active_assets.count or 0
            coverage_percentage = (unique_vulnerable_assets / active_count * 100) if active_count > 0 else 0
            
            return {
                'total_assets': total_count,
                'active_assets': active_count,
                'assets_with_vulnerabilities': unique_vulnerable_assets,
                'coverage_percentage': round(coverage_percentage, 2)
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate asset coverage: {e}")
            return {} 