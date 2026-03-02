"""
MCP Threat Mapper
Maps threats and intelligence to MCP Threat IDs (MCP-01 to MCP-38)
Also maps to OWASP LLM Top 10 and OWASP Agentic Top 10
"""

from typing import Dict, List, Optional, Any
from core.mcp_threat_classifier import (
    MCPThreatClassifier, 
    MCP_THREAT_MAP,
    OWASP_LLM_TOP10,
    OWASP_AGENTIC_TOP10
)


# Domain to MCP Threat IDs mapping (from mcp-threat.md)
DOMAIN_TO_THREAT_IDS = {
    1: ["MCP-01", "MCP-02", "MCP-03", "MCP-28", "MCP-29", "MCP-30", "MCP-31"],  # Identity, Session & Transport Security
    2: ["MCP-04", "MCP-05", "MCP-06", "MCP-21", "MCP-22", "MCP-23", "MCP-32"],  # Access Control & Privilege Management
    3: ["MCP-07", "MCP-08", "MCP-09", "MCP-37"],  # Input Validation & Sandbox Integrity
    4: ["MCP-10", "MCP-11", "MCP-12", "MCP-15", "MCP-17", "MCP-19", "MCP-20", "MCP-35", "MCP-36"],  # Data & Control Boundary Integrity
    5: ["MCP-13", "MCP-14", "MCP-16", "MCP-18", "MCP-26", "MCP-27"],  # Supply Chain & Lifecycle Security
    6: ["MCP-24", "MCP-25"],  # Data Exfiltration & Privacy Leakage
    7: ["MCP-33", "MCP-34", "MCP-38"],  # Resource Abuse & Observability Gaps
}

# STRIDE to MCP Threat IDs mapping (from mcp-threat.md)
STRIDE_TO_THREAT_IDS = {
    "Spoofing": ["MCP-01", "MCP-02", "MCP-03", "MCP-13", "MCP-14", "MCP-18", "MCP-26", "MCP-29", "MCP-31"],
    "Tampering": ["MCP-04", "MCP-07", "MCP-09", "MCP-10", "MCP-11", "MCP-12", "MCP-15", "MCP-16", "MCP-17", "MCP-26", "MCP-27", "MCP-28", "MCP-29", "MCP-30", "MCP-35", "MCP-36"],
    "Repudiation": ["MCP-03", "MCP-16", "MCP-38"],
    "Information Disclosure": ["MCP-02", "MCP-06", "MCP-08", "MCP-09", "MCP-18", "MCP-19", "MCP-20", "MCP-24", "MCP-25", "MCP-28", "MCP-32", "MCP-34"],
    "Denial of Service": ["MCP-09", "MCP-17", "MCP-29", "MCP-33"],
    "Elevation of Privilege": ["MCP-04", "MCP-05", "MCP-06", "MCP-07", "MCP-13", "MCP-14", "MCP-21", "MCP-22", "MCP-23", "MCP-32", "MCP-37"],
}

# Risk Level to MCP Threat IDs mapping
RISK_LEVEL_TO_THREAT_IDS = {
    "Critical": ["MCP-19", "MCP-20"],
    "High": ["MCP-01", "MCP-02", "MCP-03", "MCP-04", "MCP-06", "MCP-07", "MCP-08", "MCP-10", "MCP-11", "MCP-12", "MCP-16", "MCP-17", "MCP-18", "MCP-24", "MCP-25", "MCP-26", "MCP-27", "MCP-28", "MCP-32", "MCP-37"],
    "Medium": ["MCP-05", "MCP-09", "MCP-13", "MCP-14", "MCP-15", "MCP-21", "MCP-22", "MCP-29", "MCP-30", "MCP-31", "MCP-33", "MCP-35", "MCP-36", "MCP-38"],
    "Low": ["MCP-23", "MCP-34"],
}


class MCPThreatMapper:
    """Maps threats and intelligence to MCP Threat IDs"""
    
    @staticmethod
    def map_intel_to_threat_ids(intel_item: Dict[str, Any]) -> List[str]:
        """
        Map an intelligence item to MCP Threat IDs
        
        Args:
            intel_item: Intelligence item dictionary
            
        Returns:
            List of MCP Threat IDs
        """
        # Extract text for analysis
        title = intel_item.get('title', '') or ''
        description = intel_item.get('description', '') or ''
        content = intel_item.get('content', '') or intel_item.get('ai_summary', '') or ''
        ai_threat_type = intel_item.get('ai_threat_type', '') or ''
        ai_stride_category = intel_item.get('ai_stride_category', '') or ''
        
        # Use MCPThreatClassifier to classify
        threat_ids = MCPThreatClassifier.classify_threat(
            threat_name=title,
            threat_description=f"{description} {content}",
            attack_vector=ai_threat_type,
            stride_category=ai_stride_category
        )
        
        return threat_ids
    
    @staticmethod
    def map_intel_to_all_frameworks(intel_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map an intelligence item to all three frameworks:
        - MCP Threat IDs (MCP-01 to MCP-38)
        - OWASP LLM Top 10 (LLM01 to LLM10)
        - OWASP Agentic Top 10 (ASI01 to ASI10)
        
        Args:
            intel_item: Intelligence item dictionary
            
        Returns:
            Dictionary with classifications for all three frameworks
        """
        title = intel_item.get('title', '') or ''
        description = intel_item.get('description', '') or ''
        content = intel_item.get('content', '') or intel_item.get('ai_summary', '') or ''
        ai_threat_type = intel_item.get('ai_threat_type', '') or ''
        ai_stride_category = intel_item.get('ai_stride_category', '') or ''
        
        # Use the unified classification method
        return MCPThreatClassifier.classify_to_all_frameworks(
            title=title,
            description=f"{description} {content}",
            content=content,
            attack_vector=ai_threat_type,
            stride_category=ai_stride_category
        )
    
    @staticmethod
    def map_threat_to_domain(threat_ids: List[str]) -> Dict[int, List[str]]:
        """
        Map MCP Threat IDs to domains
        
        Args:
            threat_ids: List of MCP Threat IDs
            
        Returns:
            Dictionary mapping domain number to list of threat IDs in that domain
        """
        domain_mapping = {}
        
        for threat_id in threat_ids:
            for domain, domain_threats in DOMAIN_TO_THREAT_IDS.items():
                if threat_id in domain_threats:
                    if domain not in domain_mapping:
                        domain_mapping[domain] = []
                    if threat_id not in domain_mapping[domain]:
                        domain_mapping[domain].append(threat_id)
        
        return domain_mapping
    
    @staticmethod
    def get_threat_ids_by_domain(domain: int) -> List[str]:
        """Get all MCP Threat IDs for a specific domain"""
        return DOMAIN_TO_THREAT_IDS.get(domain, [])
    
    @staticmethod
    def get_threat_ids_by_stride(stride_category: str) -> List[str]:
        """Get all MCP Threat IDs for a specific STRIDE category"""
        return STRIDE_TO_THREAT_IDS.get(stride_category, [])
    
    @staticmethod
    def get_threat_ids_by_risk_level(risk_level: str) -> List[str]:
        """Get all MCP Threat IDs for a specific risk level"""
        return RISK_LEVEL_TO_THREAT_IDS.get(risk_level, [])
    
    @staticmethod
    def get_all_threat_ids() -> List[str]:
        """Get all MCP Threat IDs (MCP-01 to MCP-38)"""
        return list(MCP_THREAT_MAP.keys())
    
    @staticmethod
    def get_threat_matrix_data() -> Dict[str, Any]:
        """
        Get threat matrix data organized by MCP Threat IDs
        
        Returns:
            Dictionary with threat matrix structure
        """
        return {
            "domains": {
                domain: {
                    "threat_ids": threat_ids,
                    "threat_names": [MCP_THREAT_MAP.get(tid, tid) for tid in threat_ids],
                    "count": len(threat_ids)
                }
                for domain, threat_ids in DOMAIN_TO_THREAT_IDS.items()
            },
            "stride": {
                stride: {
                    "threat_ids": threat_ids,
                    "threat_names": [MCP_THREAT_MAP.get(tid, tid) for tid in threat_ids],
                    "count": len(threat_ids)
                }
                for stride, threat_ids in STRIDE_TO_THREAT_IDS.items()
            },
            "risk_levels": {
                risk_level: {
                    "threat_ids": threat_ids,
                    "threat_names": [MCP_THREAT_MAP.get(tid, tid) for tid in threat_ids],
                    "count": len(threat_ids)
                }
                for risk_level, threat_ids in RISK_LEVEL_TO_THREAT_IDS.items()
            },
            "all_threats": {
                threat_id: {
                    "name": MCP_THREAT_MAP.get(threat_id, threat_id),
                    "domain": MCPThreatMapper._get_threat_domain(threat_id),
                    "stride": MCPThreatMapper._get_threat_stride(threat_id),
                    "risk_level": MCPThreatMapper._get_threat_risk_level(threat_id)
                }
                for threat_id in MCP_THREAT_MAP.keys()
            }
        }
    
    @staticmethod
    def _get_threat_domain(threat_id: str) -> Optional[int]:
        """Get domain number for a threat ID"""
        for domain, threat_ids in DOMAIN_TO_THREAT_IDS.items():
            if threat_id in threat_ids:
                return domain
        return None
    
    @staticmethod
    def _get_threat_stride(threat_id: str) -> List[str]:
        """Get STRIDE categories for a threat ID"""
        stride_categories = []
        for stride, threat_ids in STRIDE_TO_THREAT_IDS.items():
            if threat_id in threat_ids:
                stride_categories.append(stride)
        return stride_categories
    
    @staticmethod
    def _get_threat_risk_level(threat_id: str) -> str:
        """Get risk level for a threat ID"""
        for risk_level, threat_ids in RISK_LEVEL_TO_THREAT_IDS.items():
            if threat_id in threat_ids:
                return risk_level
        return "Medium"  # Default


