"""
Threat Intelligence Integrator

Enriches vulnerabilities with threat intelligence data:
- CVE information
- MITRE ATT&CK mappings
- Known exploit information
- Threat actor references
"""

import logging
from typing import List, Dict, Any, Optional
import asyncio

from .models import Vulnerability, VulnerabilityCategory

logger = logging.getLogger(__name__)


class ThreatIntelIntegrator:
    """Threat intelligence integration"""
    
    def __init__(self):
        # In a full implementation, this would connect to threat intel APIs
        # For now, we'll use pattern matching and local knowledge base
        self.mitre_mappings = self._load_mitre_mappings()
        self.cve_patterns = self._load_cve_patterns()
    
    async def enrich_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        """
        Enrich vulnerabilities with threat intelligence
        
        Args:
            vulnerabilities: List of vulnerabilities to enrich
        """
        for vuln in vulnerabilities:
            # Map to MITRE ATT&CK
            vuln.mitre_attack = self._map_to_mitre_attack(vuln)
            
            # Add CWE IDs
            vuln.cwe_id = self._map_to_cwe(vuln)
            
            # Calculate CVSS score (simplified)
            if not vuln.cvss_score:
                vuln.cvss_score = self._calculate_cvss_score(vuln)
            
            # Add threat intel references
            vuln.threat_intel_refs = self._get_threat_intel_refs(vuln)
    
    def _load_mitre_mappings(self) -> Dict[str, List[str]]:
        """Load MITRE ATT&CK mappings"""
        return {
            VulnerabilityCategory.TOOL_POISONING: ["T1059", "T1071"],
            VulnerabilityCategory.PROMPT_INJECTION: ["T1059", "T1071"],
            VulnerabilityCategory.COMMAND_INJECTION: ["T1059"],
            VulnerabilityCategory.PARAMETER_INJECTION: ["T1059", "T1071"],
            VulnerabilityCategory.DATA_EXFILTRATION: ["T1041", "T1048"],
            VulnerabilityCategory.SSRF: ["T1071", "T1190"],
            VulnerabilityCategory.PATH_TRAVERSAL: ["T1083"],
            VulnerabilityCategory.CREDENTIAL_LEAK: ["T1552"],
            VulnerabilityCategory.SUPPLY_CHAIN: ["T1195"],
        }
    
    def _load_cve_patterns(self) -> Dict[str, str]:
        """Load CVE pattern mappings"""
        # In full implementation, this would query CVE databases
        return {}
    
    def _map_to_mitre_attack(self, vuln: Vulnerability) -> List[str]:
        """Map vulnerability to MITRE ATT&CK techniques"""
        return self.mitre_mappings.get(vuln.category, [])
    
    def _map_to_cwe(self, vuln: Vulnerability) -> Optional[str]:
        """Map vulnerability to CWE ID"""
        cwe_map = {
            VulnerabilityCategory.COMMAND_INJECTION: "CWE-78",
            VulnerabilityCategory.PATH_TRAVERSAL: "CWE-22",
            VulnerabilityCategory.SSRF: "CWE-918",
            VulnerabilityCategory.CREDENTIAL_LEAK: "CWE-798",
            VulnerabilityCategory.PROMPT_INJECTION: "CWE-79",  # Similar to XSS
            VulnerabilityCategory.TOOL_POISONING: "CWE-79",
        }
        return cwe_map.get(vuln.category)
    
    def _calculate_cvss_score(self, vuln: Vulnerability) -> float:
        """Calculate simplified CVSS score"""
        # Simplified scoring based on severity
        base_scores = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0,
        }
        
        base = base_scores.get(vuln.severity.value, 5.0)
        
        # Adjust based on category
        category_multipliers = {
            VulnerabilityCategory.TOOL_POISONING: 1.1,
            VulnerabilityCategory.COMMAND_INJECTION: 1.2,
            VulnerabilityCategory.CREDENTIAL_LEAK: 1.15,
            VulnerabilityCategory.SUPPLY_CHAIN: 1.1,
        }
        
        multiplier = category_multipliers.get(vuln.category, 1.0)
        
        return min(base * multiplier, 10.0)
    
    def _get_threat_intel_refs(self, vuln: Vulnerability) -> List[str]:
        """Get threat intelligence references"""
        refs = []
        
        # Add references based on category
        if vuln.category == VulnerabilityCategory.TOOL_POISONING:
            refs.append("VulnerableMCP Database")
            refs.append("Elastic Security Labs Research")
        
        if vuln.category == VulnerabilityCategory.PARAMETER_INJECTION:
            refs.append("HiddenLayer Research")
        
        if vuln.category == VulnerabilityCategory.SUPPLY_CHAIN:
            refs.append("NPM Security Advisory")
        
        return refs

