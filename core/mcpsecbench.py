"""
MCPSecBench Framework Integration

MCPSecBench defines 4 attack surfaces and 17 attack types for MCP security.
This module provides integration with the MCPSecBench framework.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class AttackSurface(Enum):
    """MCPSecBench 4 Attack Surfaces"""
    USER_INTERACTION = "User Interaction"
    MCP_CLIENT = "MCP Client"
    MCP_TRANSPORT = "MCP Transport"
    MCP_SERVER = "MCP Server"


class AttackType(Enum):
    """MCPSecBench 17 Attack Types"""
    # User Interaction Surface
    PROMPT_INJECTION = "Prompt Injection"
    INDIRECT_PROMPT_INJECTION = "Indirect Prompt Injection"
    JAILEBREAK = "Jailbreak"
    
    # MCP Client Surface
    TOOL_POISONING = "Tool Poisoning"
    TOOL_SHADOWING = "Tool Shadowing"
    TOOL_MISUSE = "Tool Misuse"
    CLIENT_CONFIGURATION_ERROR = "Client Configuration Error"
    
    # MCP Transport Surface
    TRANSPORT_HIJACKING = "Transport Hijacking"
    MAN_IN_THE_MIDDLE = "Man-in-the-Middle"
    TRANSPORT_PROTOCOL_EXPLOIT = "Transport Protocol Exploit"
    
    # MCP Server Surface
    SERVER_SIDE_INJECTION = "Server-Side Injection"
    RESOURCE_EXHAUSTION = "Resource Exhaustion"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    DATA_EXFILTRATION = "Data Exfiltration"
    SERVER_CONFIGURATION_ERROR = "Server Configuration Error"
    SUPPLY_CHAIN_ATTACK = "Supply Chain Attack"
    PRIVILEGE_ESCALATION = "Privilege Escalation"


# Attack Surface to Attack Types mapping
ATTACK_SURFACE_TO_TYPES: Dict[AttackSurface, List[AttackType]] = {
    AttackSurface.USER_INTERACTION: [
        AttackType.PROMPT_INJECTION,
        AttackType.INDIRECT_PROMPT_INJECTION,
        AttackType.JAILEBREAK
    ],
    AttackSurface.MCP_CLIENT: [
        AttackType.TOOL_POISONING,
        AttackType.TOOL_SHADOWING,
        AttackType.TOOL_MISUSE,
        AttackType.CLIENT_CONFIGURATION_ERROR
    ],
    AttackSurface.MCP_TRANSPORT: [
        AttackType.TRANSPORT_HIJACKING,
        AttackType.MAN_IN_THE_MIDDLE,
        AttackType.TRANSPORT_PROTOCOL_EXPLOIT
    ],
    AttackSurface.MCP_SERVER: [
        AttackType.SERVER_SIDE_INJECTION,
        AttackType.RESOURCE_EXHAUSTION,
        AttackType.UNAUTHORIZED_ACCESS,
        AttackType.DATA_EXFILTRATION,
        AttackType.SERVER_CONFIGURATION_ERROR,
        AttackType.SUPPLY_CHAIN_ATTACK,
        AttackType.PRIVILEGE_ESCALATION
    ]
}

# Attack Type to STRIDE mapping
ATTACK_TYPE_TO_STRIDE: Dict[AttackType, str] = {
    AttackType.PROMPT_INJECTION: "Tampering",
    AttackType.INDIRECT_PROMPT_INJECTION: "Tampering",
    AttackType.JAILEBREAK: "Elevation of Privilege",
    AttackType.TOOL_POISONING: "Tampering",
    AttackType.TOOL_SHADOWING: "Spoofing",
    AttackType.TOOL_MISUSE: "Tampering",
    AttackType.CLIENT_CONFIGURATION_ERROR: "Information Disclosure",
    AttackType.TRANSPORT_HIJACKING: "Tampering",
    AttackType.MAN_IN_THE_MIDDLE: "Tampering",
    AttackType.TRANSPORT_PROTOCOL_EXPLOIT: "Tampering",
    AttackType.SERVER_SIDE_INJECTION: "Tampering",
    AttackType.RESOURCE_EXHAUSTION: "Denial of Service",
    AttackType.UNAUTHORIZED_ACCESS: "Elevation of Privilege",
    AttackType.DATA_EXFILTRATION: "Information Disclosure",
    AttackType.SERVER_CONFIGURATION_ERROR: "Information Disclosure",
    AttackType.SUPPLY_CHAIN_ATTACK: "Tampering",
    AttackType.PRIVILEGE_ESCALATION: "Elevation of Privilege"
}


@dataclass
class MCPSecBenchThreat:
    """MCPSecBench threat definition"""
    attack_surface: AttackSurface
    attack_type: AttackType
    name: str
    description: str
    stride_category: str
    severity: str
    affected_components: List[str]
    mitigation_controls: List[str]
    examples: List[str]
    cwe_ids: List[str]
    metadata: Dict


class MCPSecBenchFramework:
    """
    MCPSecBench Framework Integration
    
    Provides:
    - Attack surface classification
    - Attack type identification
    - STRIDE mapping
    - Threat matrix generation (4 surfaces × 17 types)
    """
    
    def __init__(self):
        """Initialize MCPSecBench framework"""
        self.threats = self._load_mcpsecbench_threats()
    
    def _load_mcpsecbench_threats(self) -> List[MCPSecBenchThreat]:
        """Load MCPSecBench threat definitions"""
        threats = []
        
        # Generate threats for each attack surface and type
        for surface, attack_types in ATTACK_SURFACE_TO_TYPES.items():
            for attack_type in attack_types:
                threat = MCPSecBenchThreat(
                    attack_surface=surface,
                    attack_type=attack_type,
                    name=attack_type.value,
                    description=self._get_attack_description(attack_type),
                    stride_category=ATTACK_TYPE_TO_STRIDE.get(attack_type, "Information Disclosure"),
                    severity=self._get_attack_severity(attack_type),
                    affected_components=self._get_affected_components(surface),
                    mitigation_controls=self._get_mitigation_controls(attack_type),
                    examples=self._get_attack_examples(attack_type),
                    cwe_ids=self._get_cwe_ids(attack_type),
                    metadata={}
                )
                threats.append(threat)
        
        return threats
    
    def _get_attack_description(self, attack_type: AttackType) -> str:
        """Get description for attack type"""
        descriptions = {
            AttackType.PROMPT_INJECTION: "Direct injection of malicious prompts to manipulate LLM behavior",
            AttackType.INDIRECT_PROMPT_INJECTION: "Indirect injection through external content (web pages, documents)",
            AttackType.JAILEBREAK: "Bypassing safety mechanisms to make LLM perform restricted actions",
            AttackType.TOOL_POISONING: "Malicious tools that appear legitimate but perform harmful actions",
            AttackType.TOOL_SHADOWING: "Replacing legitimate tools with malicious versions",
            AttackType.TOOL_MISUSE: "Using legitimate tools in unintended ways to cause harm",
            AttackType.CLIENT_CONFIGURATION_ERROR: "Misconfigured MCP client exposing vulnerabilities",
            AttackType.TRANSPORT_HIJACKING: "Intercepting and modifying MCP transport layer communications",
            AttackType.MAN_IN_THE_MIDDLE: "Intercepting communications between MCP client and server",
            AttackType.TRANSPORT_PROTOCOL_EXPLOIT: "Exploiting vulnerabilities in MCP transport protocol",
            AttackType.SERVER_SIDE_INJECTION: "Injecting malicious code or commands on MCP server",
            AttackType.RESOURCE_EXHAUSTION: "Overwhelming MCP server resources to cause denial of service",
            AttackType.UNAUTHORIZED_ACCESS: "Gaining access to MCP server without proper authorization",
            AttackType.DATA_EXFILTRATION: "Unauthorized extraction of data from MCP server",
            AttackType.SERVER_CONFIGURATION_ERROR: "Misconfigured MCP server exposing vulnerabilities",
            AttackType.SUPPLY_CHAIN_ATTACK: "Compromising MCP server through supply chain vulnerabilities",
            AttackType.PRIVILEGE_ESCALATION: "Elevating privileges on MCP server beyond intended level"
        }
        return descriptions.get(attack_type, "MCP security attack")
    
    def _get_attack_severity(self, attack_type: AttackType) -> str:
        """Get severity for attack type"""
        critical = [
            AttackType.PROMPT_INJECTION,
            AttackType.TOOL_POISONING,
            AttackType.UNAUTHORIZED_ACCESS,
            AttackType.DATA_EXFILTRATION,
            AttackType.PRIVILEGE_ESCALATION
        ]
        
        high = [
            AttackType.INDIRECT_PROMPT_INJECTION,
            AttackType.TOOL_SHADOWING,
            AttackType.TRANSPORT_HIJACKING,
            AttackType.SERVER_SIDE_INJECTION,
            AttackType.SUPPLY_CHAIN_ATTACK
        ]
        
        if attack_type in critical:
            return "Critical"
        elif attack_type in high:
            return "High"
        else:
            return "Medium"
    
    def _get_affected_components(self, surface: AttackSurface) -> List[str]:
        """Get affected components for attack surface"""
        components = {
            AttackSurface.USER_INTERACTION: ["LLM", "User Interface", "Input Processing"],
            AttackSurface.MCP_CLIENT: ["MCP Client", "Tool Registry", "Client Configuration"],
            AttackSurface.MCP_TRANSPORT: ["Transport Layer", "Network", "Protocol Handler"],
            AttackSurface.MCP_SERVER: ["MCP Server", "Tool Execution", "Server Configuration"]
        }
        return components.get(surface, [])
    
    def _get_mitigation_controls(self, attack_type: AttackType) -> List[str]:
        """Get mitigation controls for attack type"""
        controls = {
            AttackType.PROMPT_INJECTION: ["Input validation", "Prompt sanitization", "Output filtering"],
            AttackType.TOOL_POISONING: ["Tool verification", "Code signing", "Sandboxing"],
            AttackType.TRANSPORT_HIJACKING: ["TLS/SSL encryption", "Certificate pinning", "Transport security"],
            AttackType.UNAUTHORIZED_ACCESS: ["Authentication", "Authorization", "Access control"],
            AttackType.DATA_EXFILTRATION: ["Data encryption", "Access logging", "Data loss prevention"]
        }
        return controls.get(attack_type, ["Security monitoring", "Access control", "Input validation"])
    
    def _get_attack_examples(self, attack_type: AttackType) -> List[str]:
        """Get examples for attack type"""
        # Return empty list for now, can be populated with real examples
        return []
    
    def _get_cwe_ids(self, attack_type: AttackType) -> List[str]:
        """Get CWE IDs for attack type"""
        cwe_mapping = {
            AttackType.PROMPT_INJECTION: ["CWE-79", "CWE-20"],
            AttackType.TOOL_POISONING: ["CWE-502", "CWE-434"],
            AttackType.UNAUTHORIZED_ACCESS: ["CWE-284", "CWE-306"],
            AttackType.DATA_EXFILTRATION: ["CWE-200", "CWE-209"]
        }
        return cwe_mapping.get(attack_type, [])
    
    def get_threat_matrix(self) -> Dict[str, Any]:
        """
        Generate MCPSecBench threat matrix (4 surfaces × 17 types).
        
        Returns:
            Dictionary with threat matrix structure
        """
        matrix = {}
        
        for surface in AttackSurface:
            matrix[surface.value] = {}
            for attack_type in ATTACK_SURFACE_TO_TYPES.get(surface, []):
                threat = next(
                    (t for t in self.threats 
                     if t.attack_surface == surface and t.attack_type == attack_type),
                    None
                )
                if threat:
                    matrix[surface.value][attack_type.value] = {
                        "name": threat.name,
                        "description": threat.description,
                        "stride_category": threat.stride_category,
                        "severity": threat.severity,
                        "affected_components": threat.affected_components,
                        "mitigation_controls": threat.mitigation_controls,
                        "cwe_ids": threat.cwe_ids
                    }
        
        return matrix
    
    def classify_threat(
        self,
        threat_name: str,
        threat_description: str
    ) -> Optional[MCPSecBenchThreat]:
        """
        Classify a threat into MCPSecBench framework.
        
        Args:
            threat_name: Name of the threat
            threat_description: Description of the threat
        
        Returns:
            MCPSecBenchThreat if classification successful, None otherwise
        """
        text = f"{threat_name} {threat_description}".lower()
        
        # Simple keyword-based classification
        for threat in self.threats:
            attack_type_name = threat.attack_type.value.lower()
            if attack_type_name in text:
                return threat
        
        return None
    
    def get_threats_by_surface(self, surface: AttackSurface) -> List[MCPSecBenchThreat]:
        """Get all threats for a specific attack surface"""
        return [t for t in self.threats if t.attack_surface == surface]
    
    def get_threats_by_type(self, attack_type: AttackType) -> List[MCPSecBenchThreat]:
        """Get all threats of a specific attack type"""
        return [t for t in self.threats if t.attack_type == attack_type]

