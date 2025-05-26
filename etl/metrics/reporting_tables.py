"""
Reporting Tables Manager

Manages storage and retrieval of metrics data in reporting tables:
- Metrics snapshots for historical tracking
- MTTR history
- Trend analysis data
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from supabase import Client
import json

logger = logging.getLogger(__name__)

class ReportingTablesManager:
    """Manage metrics storage in reporting tables"""
    
    def __init__(self, supabase_client: Client):
        self.client = supabase_client
    
    def store_metrics_snapshot(self, metrics: Dict) -> Optional[str]:
        """
        Store a point-in-time metrics snapshot
        
        Args:
            metrics: Dictionary containing all calculated metrics
            
        Returns:
            UUID of the created snapshot, or None if failed
        """
        try:
            # Prepare snapshot data
            snapshot_data = {
                'snapshot_date': datetime.now().isoformat(),
                'metrics_data': metrics,
                'snapshot_type': 'comprehensive',
                'created_at': datetime.now().isoformat()
            }
            
            # Try to insert into metrics_snapshots table
            result = self.client.table('metrics_snapshots').insert(snapshot_data).execute()
            
            if result.data:
                snapshot_id = result.data[0]['id']
                logger.info(f"✅ Stored metrics snapshot: {snapshot_id}")
                
                # Also store individual metric values for easier querying
                self._store_individual_metrics(snapshot_id, metrics)
                
                return snapshot_id
            else:
                raise Exception("No snapshot ID returned from insert")
                
        except Exception as e:
            logger.error(f"Failed to store metrics snapshot: {e}")
            # If the table doesn't exist, log the metrics for now
            logger.info(f"Metrics data: {json.dumps(metrics, indent=2)}")
            return None
    
    def _store_individual_metrics(self, snapshot_id: str, metrics: Dict):
        """Store individual metric values for easier querying"""
        try:
            metric_values = []
            
            # Extract individual metrics from the comprehensive metrics dict
            for category, data in metrics.items():
                if category == 'timestamp':
                    continue
                    
                if isinstance(data, dict):
                    for metric_name, value in data.items():
                        if isinstance(value, (int, float)):
                            metric_values.append({
                                'snapshot_id': snapshot_id,
                                'metric_category': category,
                                'metric_name': metric_name,
                                'metric_value': float(value),
                                'created_at': datetime.now().isoformat()
                            })
            
            # Insert metric values if we have any
            if metric_values:
                self.client.table('metric_values').insert(metric_values).execute()
                logger.info(f"✅ Stored {len(metric_values)} individual metric values")
                
        except Exception as e:
            logger.error(f"Failed to store individual metrics: {e}")
    
    def update_mttr_history(self, mttr_days: float, mttr_by_risk_level: Dict = None,
                           mttr_by_business_group: Dict = None, mttr_by_asset_type: Dict = None):
        """
        Update MTTR history with new calculations
        
        Args:
            mttr_days: Overall MTTR in days
            mttr_by_risk_level: MTTR breakdown by risk level
            mttr_by_business_group: MTTR breakdown by business group
            mttr_by_asset_type: MTTR breakdown by asset type
        """
        try:
            # Prepare MTTR history record
            mttr_record = {
                'calculation_date': datetime.now().isoformat(),
                'overall_mttr_days': mttr_days,
                'mttr_by_risk_level': mttr_by_risk_level or {},
                'mttr_by_business_group': mttr_by_business_group or {},
                'mttr_by_asset_type': mttr_by_asset_type or {},
                'created_at': datetime.now().isoformat()
            }
            
            # Insert MTTR history record
            result = self.client.table('mttr_history').insert(mttr_record).execute()
            
            if result.data:
                logger.info(f"✅ Updated MTTR history: {mttr_days} days overall")
            else:
                raise Exception("No MTTR history ID returned from insert")
                
        except Exception as e:
            logger.error(f"Failed to update MTTR history: {e}")
            # Log the MTTR data for reference
            logger.info(f"MTTR data - Overall: {mttr_days} days")
            if mttr_by_risk_level:
                logger.info(f"MTTR by risk: {mttr_by_risk_level}")
    
    def get_latest_metrics(self) -> Optional[Dict]:
        """
        Get the latest metrics snapshot
        
        Returns:
            Latest metrics data or None if not found
        """
        try:
            result = self.client.table('metrics_snapshots').select('*').order(
                'snapshot_date', desc=True
            ).limit(1).execute()
            
            if result.data:
                return result.data[0]['metrics_data']
            else:
                logger.warning("No metrics snapshots found")
                return None
                
        except Exception as e:
            logger.error(f"Failed to get latest metrics: {e}")
            return None
    
    def get_mttr_trend(self, days: int = 30) -> List[Dict]:
        """
        Get MTTR trend data for the specified number of days
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of MTTR history records
        """
        try:
            # Calculate date threshold
            threshold_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            result = self.client.table('mttr_history').select('*').gte(
                'calculation_date', threshold_date
            ).order('calculation_date').execute()
            
            return result.data
            
        except Exception as e:
            logger.error(f"Failed to get MTTR trend: {e}")
            return []
    
    def get_metrics_trend(self, metric_category: str, metric_name: str, days: int = 30) -> List[Dict]:
        """
        Get trend data for a specific metric
        
        Args:
            metric_category: Category of the metric (e.g., 'remediation_capacity')
            metric_name: Name of the metric (e.g., 'remediation_rate_percentage')
            days: Number of days to look back
            
        Returns:
            List of metric value records
        """
        try:
            # Calculate date threshold
            threshold_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            result = self.client.table('metric_values').select('*').eq(
                'metric_category', metric_category
            ).eq(
                'metric_name', metric_name
            ).gte(
                'created_at', threshold_date
            ).order('created_at').execute()
            
            return result.data
            
        except Exception as e:
            logger.error(f"Failed to get metrics trend for {metric_category}.{metric_name}: {e}")
            return []
    
    def update_remediation_trends(self):
        """
        Update daily remediation trend aggregates
        This would typically be run daily to aggregate remediation data
        """
        try:
            # This is a placeholder for daily aggregation logic
            # In a real implementation, you'd aggregate remediation events by day
            
            today = datetime.now().date().isoformat()
            
            # Get today's vulnerability counts
            total_vulns = self.client.table('vulnerability_scans').select('id', count='exact').execute()
            open_vulns = self.client.table('vulnerability_scans').select('id', count='exact').eq('remediation_status', 'open').execute()
            
            trend_record = {
                'trend_date': today,
                'total_vulnerabilities': total_vulns.count or 0,
                'open_vulnerabilities': open_vulns.count or 0,
                'remediated_vulnerabilities': (total_vulns.count or 0) - (open_vulns.count or 0),
                'new_vulnerabilities': 0,  # Would need to track new vs existing
                'created_at': datetime.now().isoformat()
            }
            
            # Upsert the trend record (update if exists for today, insert if not)
            result = self.client.table('remediation_trends').upsert(trend_record).execute()
            
            if result.data:
                logger.info(f"✅ Updated remediation trends for {today}")
            
        except Exception as e:
            logger.error(f"Failed to update remediation trends: {e}")
    
    def get_dashboard_summary(self) -> Dict:
        """
        Get a summary of key metrics for dashboard display
        
        Returns:
            Dictionary with key dashboard metrics
        """
        try:
            # Get latest metrics
            latest_metrics = self.get_latest_metrics()
            
            if not latest_metrics:
                return {
                    'status': 'no_data',
                    'message': 'No metrics data available'
                }
            
            # Extract key metrics for dashboard
            summary = {
                'last_updated': latest_metrics.get('timestamp'),
                'total_vulnerabilities': latest_metrics.get('remediation_capacity', {}).get('total_vulnerabilities', 0),
                'open_vulnerabilities': latest_metrics.get('remediation_capacity', {}).get('open_vulnerabilities', 0),
                'remediation_rate': latest_metrics.get('remediation_capacity', {}).get('remediation_rate_percentage', 0),
                'asset_coverage': latest_metrics.get('asset_coverage', {}).get('coverage_percentage', 0),
                'daily_remediation': latest_metrics.get('daily_remediation', {}).get('average_daily_remediation', 0)
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to get dashboard summary: {e}")
            return {
                'status': 'error',
                'message': f'Failed to get dashboard summary: {e}'
            } 