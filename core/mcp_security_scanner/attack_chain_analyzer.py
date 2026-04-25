"""
Attack Chain Analyzer

Analyzes vulnerabilities to identify potential attack chains
and risk propagation paths.
"""

import logging
import uuid
from typing import List, Dict, Any
from collections import defaultdict

from .models import Vulnerability, VulnerabilityCategory

logger = logging.getLogger(__name__)


class AttackChainAnalyzer:
    """Attack chain and risk propagation analyzer"""
    
    def __init__(self):
        pass
    
    async def analyze(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """
        Analyze vulnerabilities to identify attack chains
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            List of attack chain descriptions
        """
        attack_chains = []
        
        # Group vulnerabilities by category
        by_category = defaultdict(list)
        for vuln in vulnerabilities:
            by_category[vuln.category].append(vuln)
        
        # Identify potential chains
        # Example: Tool Poisoning -> Command Injection -> Data Exfiltration
        chains = self._identify_chains(by_category)
        
        # Build attack chain graphs
        for chain in chains:
            chain_data = {
                'id': f"chain-{uuid.uuid4().hex[:8]}",
                'name': chain['name'],
                'description': chain['description'],
                'vulnerabilities': [v.id for v in chain['vulnerabilities']],
                'risk_score': self._calculate_chain_risk(chain['vulnerabilities']),
                'attack_steps': chain['steps'],
            }
            attack_chains.append(chain_data)
            
            # Update vulnerabilities with chain reference
            for vuln in chain['vulnerabilities']:
                vuln.attack_chain_id = chain_data['id']
                vuln.related_vulnerabilities = [
                    v.id for v in chain['vulnerabilities'] if v.id != vuln.id
                ]
        
        return attack_chains
    
    def _identify_chains(self, by_category: Dict[VulnerabilityCategory, List[Vulnerability]]) -> List[Dict[str, Any]]:
        """Identify potential attack chains"""
        chains = []
        
        # Chain 1: Tool Poisoning -> Parameter Injection -> Data Exfiltration
        if (VulnerabilityCategory.TOOL_POISONING in by_category and
            VulnerabilityCategory.PARAMETER_INJECTION in by_category):
            tool_poisoning = by_category[VulnerabilityCategory.TOOL_POISONING]
            param_injection = by_category[VulnerabilityCategory.PARAMETER_INJECTION]
            
            chain_vulns = tool_poisoning[:1] + param_injection[:1]
            chains.append({
                'name': 'Tool Poisoning to Data Exfiltration Chain',
                'description': 'Malicious tool description leads to parameter injection and data exfiltration',
                'vulnerabilities': chain_vulns,
                'steps': [
                    '1. Attacker embeds malicious instructions in tool description',
                    '2. LLM reads description and executes hidden commands',
                    '3. Parameter injection extracts sensitive data',
                    '4. Data exfiltrated to attacker-controlled server'
                ]
            })
        
        # Chain 2: Supply Chain -> Command Injection -> Privilege Escalation
        if (VulnerabilityCategory.SUPPLY_CHAIN in by_category and
            VulnerabilityCategory.COMMAND_INJECTION in by_category):
            supply_chain = by_category[VulnerabilityCategory.SUPPLY_CHAIN]
            cmd_injection = by_category[VulnerabilityCategory.COMMAND_INJECTION]
            
            chain_vulns = supply_chain[:1] + cmd_injection[:1]
            chains.append({
                'name': 'Supply Chain to RCE Chain',
                'description': 'Malicious package leads to command injection and remote code execution',
                'vulnerabilities': chain_vulns,
                'steps': [
                    '1. Malicious package installed via supply chain attack',
                    '2. Package contains vulnerable code or backdoor',
                    '3. Command injection vulnerability exploited',
                    '4. Remote code execution achieved'
                ]
            })
        
        # Chain 3: SSRF -> Path Traversal -> Credential Leak
        if (VulnerabilityCategory.SSRF in by_category and
            VulnerabilityCategory.PATH_TRAVERSAL in by_category and
            VulnerabilityCategory.CREDENTIAL_LEAK in by_category):
            ssrf = by_category[VulnerabilityCategory.SSRF]
            path_traversal = by_category[VulnerabilityCategory.PATH_TRAVERSAL]
            cred_leak = by_category[VulnerabilityCategory.CREDENTIAL_LEAK]
            
            chain_vulns = ssrf[:1] + path_traversal[:1] + cred_leak[:1]
            chains.append({
                'name': 'SSRF to Credential Theft Chain',
                'description': 'SSRF enables path traversal to access credential files',
                'vulnerabilities': chain_vulns,
                'steps': [
                    '1. SSRF vulnerability allows internal network access',
                    '2. Path traversal enables file system access',
                    '3. Credential files accessed and exfiltrated',
                    '4. Stolen credentials used for further attacks'
                ]
            })
        
        return chains
    
    def _calculate_chain_risk(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall risk score for attack chain"""
        if not vulnerabilities:
            return 0.0
        
        # Use highest severity vulnerability as base
        severity_scores = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.0,
            "info": 0.5
        }
        
        max_score = max(
            severity_scores.get(v.severity.value, 5.0)
            for v in vulnerabilities
        )
        
        # Multiply by chain length (more steps = higher risk)
        chain_multiplier = 1.0 + (len(vulnerabilities) - 1) * 0.2
        
        return min(max_score * chain_multiplier, 10.0)

