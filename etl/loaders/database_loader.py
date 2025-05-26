import psycopg2
from psycopg2.extras import execute_values
from typing import List, Dict
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseLoader:
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
    
    @contextmanager
    def get_connection(self):
        conn = None
        try:
            conn = psycopg2.connect(self.connection_string)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def load_assets(self, assets: List[Dict]) -> int:
        if not assets:
            return 0
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                values = []
                for asset in assets:
                    values.append((
                        asset.get("Asset_Name", ""),
                        asset.get("Asset_IP", ""),
                        asset.get("Type", ""),
                        asset.get("Asset_First_Seen"),
                        asset.get("Asset_Last_Seen"),
                        asset.get("Asset_Tags", "[]"),
                        asset.get("Business_Groups", "[]"),
                        asset.get("Owners", "[]"),
                        asset.get("Inclusion_Date"),
                        asset.get("Asset_ID", ""),
                    ))
                
                upsert_query = """
                INSERT INTO assets (
                    Asset_Name, Asset_IP, Type, Asset_First_Seen, Asset_Last_Seen,
                    Asset_Tags, Business_Groups, Owners, Inclusion_Date, Asset_ID
                ) VALUES %s
                ON CONFLICT (Asset_Name, Asset_IP) 
                DO UPDATE SET
                    Asset_Last_Seen = EXCLUDED.Asset_Last_Seen,
                    Asset_Tags = EXCLUDED.Asset_Tags
                """
                
                execute_values(cursor, upsert_query, values)
                conn.commit()
                return len(assets)
    
    def load_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        if not vulnerabilities:
            return 0
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                values = []
                for vuln in vulnerabilities:
                    values.append((
                        vuln.get("Asset_Name", ""),
                        vuln.get("Vulnerability_Name", ""),
                        vuln.get("Status", ""),
                        vuln.get("Risk", ""),
                        vuln.get("Risk_Score"),
                        vuln.get("CVSS_Score"),
                        vuln.get("First_Seen"),
                        vuln.get("Last_Seen"),
                        vuln.get("Sources", "[]"),
                        vuln.get("Tags", "[]"),
                        vuln.get("Business_Groups", "[]"),
                        vuln.get("Owners", "[]"),
                        vuln.get("Inclusion_Date"),
                        vuln.get("Severity", ""),
                        vuln.get("Scanner", ""),
                        vuln.get("IP", ""),
                    ))
                
                upsert_query = """
                INSERT INTO vulnerabilities (
                    Asset_Name, Vulnerability_Name, Status, Risk, Risk_Score, CVSS_Score,
                    First_Seen, Last_Seen, Sources, Tags, Business_Groups, Owners,
                    Inclusion_Date, Severity, Scanner, IP
                ) VALUES %s
                ON CONFLICT (Asset_Name, Vulnerability_Name) 
                DO UPDATE SET
                    Last_Seen = EXCLUDED.Last_Seen,
                    Status = EXCLUDED.Status,
                    Risk_Score = EXCLUDED.Risk_Score
                """
                
                execute_values(cursor, upsert_query, values)
                conn.commit()
                return len(vulnerabilities)
