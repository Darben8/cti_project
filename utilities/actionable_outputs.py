"""
Actionable Outputs Module

Provides utilities for exporting threat intelligence data and generating Course-of-Action (COA)
recommendations for different indicator types.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any
import pandas as pd


# Define Course-of-Action mappings for different threat types
COURSE_OF_ACTIONS = {
    "domain": {
        "category": "network_infrastructure",
        "severity": "HIGH",
        "ttl_days": 30,
        "recommended_actions": [
            "Block domain at DNS/proxy level",
            "Add to firewall blocklist",
            "Monitor for historical connections",
            "Alert SOC on new connections"
        ]
    },
    "ip": {
        "category": "network_infrastructure",
        "severity": "HIGH",
        "ttl_days": 30,
        "recommended_actions": [
            "Block IP at firewall/edge",
            "Monitor for connections",
            "Review firewall logs for existing communications",
            "Consider GeoIP enrichment"
        ]
    },
    "ip:port": {
        "category": "network_infrastructure",
        "severity": "CRITICAL",
        "ttl_days": 7,
        "recommended_actions": [
            "Immediate firewall block",
            "Port-specific EDR/NDR rules",
            "Check for C2 communications",
            "Escalate to incident response if active"
        ]
    },
    "url": {
        "category": "web_infrastructure",
        "severity": "HIGH",
        "ttl_days": 30,
        "recommended_actions": [
            "Block URL at web proxy",
            "Add to web filtering service",
            "Notify users of phishing URLs",
            "Monitor endpoint browsers for access"
        ]
    },
    "hash": {
        "category": "malware",
        "severity": "CRITICAL",
        "ttl_days": 90,
        "recommended_actions": [
            "Add to EDR/AV blocklist",
            "Perform fleet-wide scan",
            "Quarantine detected files",
            "Investigate execution history on impacted systems"
        ]
    },
    "sha256": {
        "category": "malware",
        "severity": "CRITICAL",
        "ttl_days": 90,
        "recommended_actions": [
            "Add SHA256 to EDR blocklist",
            "Run endpoint scan",
            "Quarantine any matches",
            "Review process execution chains"
        ]
    },
    "md5": {
        "category": "malware",
        "severity": "HIGH",
        "ttl_days": 60,
        "recommended_actions": [
            "Add MD5 to AV/EDR",
            "Perform endpoint scans",
            "Quarantine detected files",
            "Consider MD5 hash collision risks"
        ]
    },
    "email": {
        "category": "phishing",
        "severity": "HIGH",
        "ttl_days": 7,
        "recommended_actions": [
            "Block sender at email gateway",
            "Quarantine similar emails",
            "Alert users to phishing",
            "Review mailbox for compromised messages"
        ]
    },
}


class CourseOfActionMapper:
    """Maps threat indicators to Course-of-Action recommendations."""
    
    def __init__(self):
        """Initialize the COA mapper with predefined mappings."""
        self.coa_mappings = COURSE_OF_ACTIONS
    
    def get_coa(self, threat_type: str, category: str = "", tags: str = "") -> Dict[str, Any]:
        """
        Get Course-of-Action recommendation for a threat indicator.
        
        Args:
            threat_type: Type of indicator (domain, ip, hash, etc.)
            category: Optional category for additional context
            tags: Optional tags for threat classification
            
        Returns:
            Dictionary containing COA recommendation with severity, TTL, and actions
        """
        # Normalize threat type
        threat_type_lower = str(threat_type).lower().strip()
        
        # Check for direct match
        if threat_type_lower in self.coa_mappings:
            return self.coa_mappings[threat_type_lower].copy()
        
        # Check for hash types
        if "hash" in threat_type_lower:
            return self.coa_mappings["hash"].copy()
        
        # Check for IP-related
        if "ip" in threat_type_lower:
            if "port" in threat_type_lower:
                return self.coa_mappings["ip:port"].copy()
            return self.coa_mappings["ip"].copy()
        
        # Check tags for phishing
        if tags and "phish" in str(tags).lower():
            return self.coa_mappings["url"].copy()
        
        # Default to HIGH severity if type not recognized
        return {
            "category": "unknown",
            "severity": "HIGH",
            "ttl_days": 30,
            "recommended_actions": [
                "Escalate to threat hunting team",
                "Request indicator clarification",
                "Monitor in SIEM for activity"
            ]
        }
    
    def get_coa_for_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply COA mapping to a DataFrame of indicators.
        
        Args:
            df: DataFrame with indicator data
            
        Returns:
            DataFrame with added COA columns
        """
        result_df = df.copy()
        
        coas = []
        for _, row in df.iterrows():
            threat_type = row.get("type", "")
            category = row.get("ioc type", row.get("category", ""))
            tags = row.get("tags", "")
            
            coa = self.get_coa(threat_type, category, tags)
            coas.append(coa)
        
        result_df["threat_category"] = [coa["category"] for coa in coas]
        result_df["severity"] = [coa["severity"] for coa in coas]
        result_df["ttl_days"] = [coa["ttl_days"] for coa in coas]
        
        return result_df


class ActionableOutputExporter:
    """Handles export of threat intelligence data in multiple formats."""
    
    @staticmethod
    def export_to_csv(df: pd.DataFrame, include_coa: bool = True) -> Tuple[pd.DataFrame, str]:
        """
        Export indicators to CSV format.
        
        Args:
            df: DataFrame of indicators (with optional COA columns)
            include_coa: Whether to include COA recommendations
            
        Returns:
            Tuple of (export_dataframe, output_path)
        """
        export_df = df.copy()
        
        if not include_coa:
            # Remove COA columns if not needed
            coa_cols = ["threat_category", "severity", "ttl_days", "recommended_actions"]
            export_df = export_df.drop(columns=[c for c in coa_cols if c in export_df.columns])
        
        # Generate output path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"cti_indicators_{timestamp}.csv"
        
        return export_df, output_path
    
    @staticmethod
    def export_to_json(
        df: pd.DataFrame,
        include_coa: bool = True,
        include_stix: bool = False
    ) -> Tuple[Dict[str, Any], str]:
        """
        Export indicators to JSON format.
        
        Args:
            df: DataFrame of indicators
            include_coa: Whether to include COA recommendations
            include_stix: Whether to include STIX metadata
            
        Returns:
            Tuple of (json_data_dict, output_path)
        """
        export_df = df.copy()
        
        if not include_coa:
            coa_cols = ["threat_category", "severity", "ttl_days", "recommended_actions"]
            export_df = export_df.drop(columns=[c for c in coa_cols if c in export_df.columns])
        
        # Convert DataFrame to records
        records = export_df.fillna("").to_dict(orient="records")
        
        # Build JSON structure
        json_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "indicator_count": len(records),
                "include_coa": include_coa,
                "include_stix": include_stix,
                "sources": list(df.get("source", []).unique()) if "source" in df.columns else []
            },
            "indicators": records
        }
        
        # Generate output path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"cti_indicators_{timestamp}.json"
        
        return json_data, output_path
    
    @staticmethod
    def export_to_stix(df: pd.DataFrame) -> Tuple[Dict[str, Any], str]:
        """
        Export indicators to STIX 2.1 format.
        
        Args:
            df: DataFrame of indicators
            
        Returns:
            Tuple of (stix_bundle, output_path)
        """
        from uuid import uuid4
        
        # STIX Bundle object list
        stix_objects = []
        
        # Add indicators as STIX objects
        for _, row in df.iterrows():
            indicator_id = f"indicator--{uuid4()}"
            threat_type = str(row.get("type", "unknown")).lower()
            value = str(row.get("indicator", row.get("value", "")))
            
            # Determine pattern based on type
            if "domain" in threat_type:
                pattern = f"[domain-name:value = '{value}']"
            elif "ip" in threat_type:
                pattern = f"[ipv4-addr:value = '{value}']"
            elif "url" in threat_type:
                pattern = f"[url:value = '{value}']"
            elif "hash" in threat_type or "sha256" in threat_type:
                pattern = f"[file:hashes.MD5 = '{value}']"
            else:
                pattern = f"[x-misp-attribute:type = '{threat_type}' AND x-misp-attribute:value = '{value}']"
            
            indicator_obj = {
                "type": "indicator",
                "id": indicator_id,
                "created": datetime.now().isoformat() + "Z",
                "modified": datetime.now().isoformat() + "Z",
                "pattern": pattern,
                "labels": [str(row.get("tags", "malicious-activity")).lower()],
                "description": f"IOC from {row.get('source', 'unknown')} - Type: {threat_type}",
            }
            
            stix_objects.append(indicator_obj)
        
        # Create STIX Bundle
        bundle_id = f"bundle--{uuid4()}"
        stix_bundle = {
            "type": "bundle",
            "id": bundle_id,
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "objects": stix_objects
        }
        
        # Generate output path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"stix_bundle_{timestamp}.json"
        
        return stix_bundle, output_path
    
    @staticmethod
    def generate_intelligence_report(df: pd.DataFrame) -> Tuple[Dict[str, Any], str]:
        """
        Generate a comprehensive intelligence report from indicators.
        
        Args:
            df: DataFrame of indicators (ideally with COA columns from CourseOfActionMapper)
            
        Returns:
            Tuple of (report_dict, output_path)
        """
        # Ensure we have COA columns, if not add them
        if "severity" not in df.columns:
            mapper = CourseOfActionMapper()
            df = mapper.get_coa_for_dataframe(df)
        
        # Report metadata
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_indicators": len(df),
                "organization": "CTI Project",
                "report_type": "Intelligence Analysis Report"
            },
            "severity_distribution": {},
            "threat_summary": {},
            "course_of_action_recommendations": {}
        }
        
        # Count severity distribution
        if "severity" in df.columns:
            severity_counts = df["severity"].value_counts().to_dict()
            report["severity_distribution"] = severity_counts
        
        # Build threat summary
        if "threat_category" in df.columns:
            threat_categories = df["threat_category"].unique()
            
            for category in threat_categories:
                category_df = df[df["threat_category"] == category]
                
                # Get severity for this category
                category_severity = category_df["severity"].iloc[0] if len(category_df) > 0 else "UNKNOWN"
                
                # Collect sample indicators
                sample_indicators = []
                for _, row in category_df.head(5).iterrows():
                    sample_indicators.append({
                        "indicator": str(row.get("indicator", row.get("value", "N/A"))),
                        "type": str(row.get("type", "unknown")),
                        "source": str(row.get("source", "unknown")),
                        "severity": str(row.get("severity", "UNKNOWN"))
                    })
                
                report["threat_summary"][category] = {
                    "category": category,
                    "count": len(category_df),
                    "severity": category_severity,
                    "indicators": sample_indicators
                }
        
        # Build COA recommendations
        mapper = CourseOfActionMapper()
        categories_seen = set()
        
        for _, row in df.iterrows():
            threat_type = row.get("type", "")
            category = row.get("threat_category", "unknown")
            tags = row.get("tags", "")
            
            # Skip if we've already added this category
            if category in categories_seen:
                continue
            
            coa = mapper.get_coa(threat_type, category, tags)
            
            report["course_of_action_recommendations"][category] = {
                "category": category,
                "severity": coa.get("severity", "UNKNOWN"),
                "ttl_days": coa.get("ttl_days", 30),
                "actions": coa.get("recommended_actions", [])
            }
            
            categories_seen.add(category)
        
        # Generate output path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"intelligence_report_{timestamp}.json"
        
        return report, output_path
