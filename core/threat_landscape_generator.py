"""
3D Threat Landscape Generator

Transforms MCP-38 threat data into a format suitable for 3D city visualization.
Each threat becomes a "building" with height based on severity.
"""

from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class AttackSurface(Enum):
    """Attack surface categories for color mapping"""
    SERVER_APIS = "server_apis"
    TOOL_METADATA = "tool_metadata"
    RUNTIME_FLOW = "runtime_flow"
    TRANSPORT = "transport"


# Color mapping for attack surfaces
SURFACE_COLORS = {
    AttackSurface.SERVER_APIS: "#3b82f6",      # Blue
    AttackSurface.TOOL_METADATA: "#22c55e",    # Green
    AttackSurface.RUNTIME_FLOW: "#ef4444",     # Red
    AttackSurface.TRANSPORT: "#f59e0b",        # Amber
}


# MCP-38 Threat definitions with surface mappings
MCP_38_THREATS = [
    {
        "id": "MCP-01",
        "name": "Identity Spoofing / Improper Authentication",
        "severity": 9,
        "surface": AttackSurface.SERVER_APIS,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Improper Authentication and Identity Management",
        "description": "Weak or absent authentication allows attackers to impersonate legitimate MCP clients, servers, or agents, leading to unauthorized access and corrupted audit trails.",
        "mitigation": "Enforce strong mutual authentication (mTLS, signed tokens), rotate credentials frequently, implement zero-trust verification for all MCP interactions.",
    },
    {
        "id": "MCP-02",
        "name": "Credential Theft / Token Theft",
        "severity": 9,
        "surface": AttackSurface.SERVER_APIS,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Improper Authentication and Identity Management",
        "description": "OAuth tokens, API keys, or secrets are stolen via insecure storage or transmission, enabling impersonation and privilege escalation.",
        "mitigation": "Use secure vaults for secrets, encrypt in transit and at rest, short-lived tokens with refresh mechanisms.",
    },
    {
        "id": "MCP-03",
        "name": "Replay Attacks / Session Hijacking",
        "severity": 9,
        "surface": AttackSurface.SERVER_APIS,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Session and Transport Security Failures",
        "description": "Intercepted tokens or session identifiers are reused to impersonate legitimate agents and perform unauthorized actions.",
        "mitigation": "Use nonce/timestamps, short-lived tokens, secure binding to IP/channel.",
    },
    {
        "id": "MCP-04",
        "name": "Privilege Escalation & Confused Deputy",
        "severity": 9,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "High",
        "category": "Missing or Improper Access Control",
        "description": "Misconfigured access control or delegation logic allows attackers to gain unauthorized elevated permissions.",
        "mitigation": "Least privilege, explicit delegation checks, avoid confused deputy patterns.",
    },
    {
        "id": "MCP-05",
        "name": "Excessive Permissions / Overexposure",
        "severity": 6,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "Low",
        "category": "Missing or Improper Access Control",
        "description": "MCP tools or agents are granted overly broad permissions, increasing impact if compromised.",
        "mitigation": "Principle of least privilege, scoped permissions, regular audits.",
    },
    {
        "id": "MCP-06",
        "name": "Improper Multitenancy & Isolation Failure",
        "severity": 9,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "High",
        "category": "Missing or Improper Access Control",
        "description": "Weak isolation in multi-tenant MCP deployments leads to cross-tenant data leakage or privilege escalation.",
        "mitigation": "Strong isolation (containers/VMs), separate keys/data stores.",
    },
    {
        "id": "MCP-07",
        "name": "Command Injection",
        "severity": 10,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Input Validation/Sanitization Failures",
        "description": "Unvalidated LLM-generated inputs are executed as system commands, leading to RCE.",
        "mitigation": "Strict input sanitization, avoid direct exec, use safe APIs.",
    },
    {
        "id": "MCP-08",
        "name": "File System Exposure / Path Traversal",
        "severity": 9,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Inadequate Data Protection Controls",
        "description": "Improper path validation allows unauthorized file access beyond intended directories.",
        "mitigation": "Canonical path resolution, chroot/jail, strict allowlists.",
    },
    {
        "id": "MCP-09",
        "name": "Traditional Web Vulnerabilities (SSRF, XSS)",
        "severity": 7,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "Medium",
        "category": "Input Validation/Sanitization Failures",
        "description": "MCP servers exposing HTTP interfaces inherit classic web vulnerabilities.",
        "mitigation": "Input/output encoding, CSP, URL validation for SSRF.",
    },
    {
        "id": "MCP-10",
        "name": "Tool Description Poisoning",
        "severity": 9,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "High",
        "complexity": "High",
        "category": "Data/Control Boundary Distinction Failure",
        "description": "Hidden malicious instructions in tool metadata manipulate LLM behavior.",
        "mitigation": "Validate/sign tool manifests, detect anomalous descriptions.",
    },
    {
        "id": "MCP-11",
        "name": "Full Schema Poisoning (FSP)",
        "severity": 9,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "High",
        "complexity": "High",
        "category": "Data/Control Boundary Distinction Failure",
        "description": "Structural poisoning of tool schemas affects all invocations while evading detection.",
        "mitigation": "Schema validation, integrity checks on definitions.",
    },
    {
        "id": "MCP-12",
        "name": "Resource Content Poisoning",
        "severity": 9,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Missing Integrity Controls",
        "description": "Persistent indirect prompt injection via poisoned documents, databases, or resources.",
        "mitigation": "Content validation, retrieval guards, RAG sanitization.",
    },
    {
        "id": "MCP-13",
        "name": "Tool Shadowing / Name Spoofing",
        "severity": 6,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "Medium",
        "complexity": "Low",
        "category": "Missing Integrity Controls",
        "description": "Malicious tools mimic legitimate names to trick LLM selection.",
        "mitigation": "Unique namespacing, source verification.",
    },
    {
        "id": "MCP-14",
        "name": "Cross-Server Tool Shadowing",
        "severity": 7,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "Medium",
        "complexity": "Medium",
        "category": "Missing Integrity Controls",
        "description": "Malicious server overrides or intercepts tool calls intended for another server.",
        "mitigation": "Explicit server binding, authentication per call.",
    },
    {
        "id": "MCP-15",
        "name": "Preference Manipulation Attack (PMPA)",
        "severity": 7,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "Medium",
        "complexity": "Medium",
        "category": "Trust Boundary Failures",
        "description": "Tool metadata biases LLM decision-making toward attacker-controlled tools.",
        "mitigation": "Validate preference weights, detect bias.",
    },
    {
        "id": "MCP-16",
        "name": "Rug Pull / Dynamic Behavior Change",
        "severity": 9,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "High",
        "complexity": "High",
        "category": "Supply Chain Failures",
        "description": "Initially trusted MCP servers later become malicious via updates or triggers.",
        "mitigation": "Version pinning, monitor behavior changes, rollback capabilities.",
    },
    {
        "id": "MCP-17",
        "name": "Parasitic Toolchain / Connector Chaining",
        "severity": 9,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "High",
        "category": "Data/Control Boundary Failure",
        "description": "Legitimate tools are chained to bypass controls or exfiltrate data.",
        "mitigation": "Limit chaining depth, validate chains, monitor outputs.",
    },
    {
        "id": "MCP-18",
        "name": "Shadow MCP Servers",
        "severity": 9,
        "surface": AttackSurface.SERVER_APIS,
        "risk_level": "High",
        "complexity": "High",
        "category": "Supply Chain Failures",
        "description": "Unauthorized MCP servers operate without monitoring, enabling covert abuse.",
        "mitigation": "Registry of authorized servers, mutual auth, discovery controls.",
    },
    {
        "id": "MCP-19",
        "name": "Prompt Injection (Direct)",
        "severity": 10,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Critical",
        "complexity": "Medium",
        "category": "Data/Control Boundary Failure",
        "description": "Malicious user input overrides system intent and tool constraints.",
        "mitigation": "Prompt engineering guards, input classification, privilege separation.",
    },
    {
        "id": "MCP-20",
        "name": "Prompt Injection (Indirect via Data)",
        "severity": 10,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Critical",
        "complexity": "High",
        "category": "Data/Control Boundary Failure",
        "description": "Hidden prompts in external data trigger unauthorized actions.",
        "mitigation": "Retrieval sanitization, source trust levels, context isolation.",
    },
    {
        "id": "MCP-21",
        "name": "Overreliance on LLM Safeguards",
        "severity": 6,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "Low",
        "category": "Trust Boundary Failures",
        "description": "Developers assume LLM safety filters will prevent misuse, which attackers bypass.",
        "mitigation": "External validation layers, monitoring for bypass attempts.",
    },
    {
        "id": "MCP-22",
        "name": "Insecure Human-in-the-Loop Bypass",
        "severity": 7,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "Medium",
        "category": "Improper Access Control",
        "description": "Missing or weak consent mechanisms allow unauthorized actions.",
        "mitigation": "Mandatory approval for high-risk actions, strong UI warnings.",
    },
    {
        "id": "MCP-23",
        "name": "Consent / Approval Fatigue",
        "severity": 4,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Low",
        "complexity": "Low",
        "category": "Trust Boundary Failures",
        "description": "Users habituate to frequent prompts and blindly approve risky actions.",
        "mitigation": "Batch approvals, risk-based prompting, escalation thresholds.",
    },
    {
        "id": "MCP-24",
        "name": "Data Exfiltration via Tool Output",
        "severity": 9,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Inadequate Data Protection",
        "description": "Tool outputs covertly leak sensitive data.",
        "mitigation": "DLP on outputs, redaction, monitoring for exfil patterns.",
    },
    {
        "id": "MCP-25",
        "name": "Privacy Inversion / Data Aggregation Leakage",
        "severity": 9,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "High",
        "category": "Inadequate Data Protection",
        "description": "Sensitive data aggregated across tools leaks due to weak isolation.",
        "mitigation": "Data minimization, differential privacy, aggregation controls.",
    },
    {
        "id": "MCP-26",
        "name": "Supply Chain Compromise",
        "severity": 9,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "High",
        "complexity": "High",
        "category": "Supply Chain Failures",
        "description": "Malicious code introduced into MCP packages or dependencies.",
        "mitigation": "Version pinning, signed packages, vulnerability scanning.",
    },
    {
        "id": "MCP-27",
        "name": "Missing Integrity Verification",
        "severity": 8,
        "surface": AttackSurface.TOOL_METADATA,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Missing Integrity Controls",
        "description": "No signatures, SBOMs, or attestation to verify MCP server integrity.",
        "mitigation": "Require signed manifests, remote attestation.",
    },
    {
        "id": "MCP-28",
        "name": "Man-in-the-Middle / Transport Tampering",
        "severity": 9,
        "surface": AttackSurface.TRANSPORT,
        "risk_level": "High",
        "complexity": "Medium",
        "category": "Session & Transport Failures",
        "description": "Weak TLS or auth allows interception or modification of MCP traffic.",
        "mitigation": "Enforce mTLS, pin certificates, strong ciphers.",
    },
    {
        "id": "MCP-29",
        "name": "Protocol Gaps / Weak Transport Security",
        "severity": 6,
        "surface": AttackSurface.TRANSPORT,
        "risk_level": "Medium",
        "complexity": "Low",
        "category": "Session & Transport Failures",
        "description": "Missing limits, auth, or CSRF protections enable spoofing or DoS.",
        "mitigation": "Rate limits, auth per request, anti-CSRF tokens.",
    },
    {
        "id": "MCP-30",
        "name": "Insecure stdio Descriptor Handling",
        "severity": 7,
        "surface": AttackSurface.TRANSPORT,
        "risk_level": "Medium",
        "complexity": "High",
        "category": "Session & Transport Failures",
        "description": "Improper stdio handling enables process or stream hijacking.",
        "mitigation": "Secure descriptor management, validation.",
    },
    {
        "id": "MCP-31",
        "name": "MCP Endpoint / DNS Rebinding",
        "severity": 7,
        "surface": AttackSurface.SERVER_APIS,
        "risk_level": "Medium",
        "complexity": "Medium",
        "category": "Network Isolation Failures",
        "description": "DNS rebinding tricks local MCP clients into talking to malicious servers.",
        "mitigation": "Host validation, CORS-like checks, private DNS.",
    },
    {
        "id": "MCP-32",
        "name": "Unrestricted Network Access & Lateral Movement",
        "severity": 9,
        "surface": AttackSurface.TRANSPORT,
        "risk_level": "High",
        "complexity": "High",
        "category": "Network Isolation Failures",
        "description": "Compromised MCP servers pivot to attack internal systems.",
        "mitigation": "Network segmentation, egress filtering, zero trust.",
    },
    {
        "id": "MCP-33",
        "name": "Resource Exhaustion / Denial of Wallet",
        "severity": 7,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "Medium",
        "category": "Resource Management Failures",
        "description": "Excessive LLM/tool calls cause DoS or financial loss.",
        "mitigation": "Quotas, rate limiting, cost monitoring.",
    },
    {
        "id": "MCP-34",
        "name": "Tool Manifest Reconnaissance",
        "severity": 4,
        "surface": AttackSurface.SERVER_APIS,
        "risk_level": "Low",
        "complexity": "Low",
        "category": "Insufficient Monitoring",
        "description": "Attackers enumerate tool schemas to plan attacks.",
        "mitigation": "Limit public manifest exposure, rate limit discovery.",
    },
    {
        "id": "MCP-35",
        "name": "Planning / Agent Logic Drift",
        "severity": 7,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "High",
        "category": "Data/Control Boundary Failure",
        "description": "Gradual manipulation shifts agent reasoning toward unsafe decisions.",
        "mitigation": "Alignment monitoring, goal validation.",
    },
    {
        "id": "MCP-36",
        "name": "Multi-Agent Context Hijacking",
        "severity": 7,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "High",
        "category": "Data/Control Boundary Failure",
        "description": "One compromised agent poisons shared context across agents.",
        "mitigation": "Per-agent context isolation, tamper detection.",
    },
    {
        "id": "MCP-37",
        "name": "Sandbox Escape",
        "severity": 10,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "High",
        "complexity": "High",
        "category": "Input Validation Failures",
        "description": "Code execution tools escape sandbox and access host system.",
        "mitigation": "No exec privileges, strict sandbox policies.",
    },
    {
        "id": "MCP-38",
        "name": "Invisible Agent Activity / No Observability",
        "severity": 7,
        "surface": AttackSurface.RUNTIME_FLOW,
        "risk_level": "Medium",
        "complexity": "Medium",
        "category": "Insufficient Logging & Auditability",
        "description": "Malicious activity occurs without logs or forensic traceability.",
        "mitigation": "Comprehensive logging, audit trails, observability.",
    },
]



@dataclass
class ThreatBuilding:
    """Represents a threat as a building in the 3D city"""
    id: str
    name: str
    severity: int
    surface: str
    color: str
    height: float
    width: float
    depth: float
    x: float
    z: float
    detections: int = 0
    risk_level: str = ""
    complexity: str = ""
    category: str = ""
    description: str = ""
    mitigation: str = ""


class ThreatLandscapeGenerator:
    """Generates 3D city data from MCP-38 threats"""
    
    def __init__(self):
        self.threats = MCP_38_THREATS
        self.grid_size = 8  # 8x5 grid for 38 threats
        self.spacing = 2.5
        self.base_size = 1.5
    
    def generate_landscape(self, detection_counts: Dict[str, int] = None) -> Dict[str, Any]:
        """
        Generate 3D landscape data from threats.
        
        Args:
            detection_counts: Optional dict mapping threat_id -> detection count from intel
            
        Returns:
            Dict with buildings array and metadata
        """
        if detection_counts is None:
            detection_counts = {}
        
        buildings = []
        
        for idx, threat in enumerate(self.threats):
            # Calculate grid position
            row = idx // self.grid_size
            col = idx % self.grid_size
            
            # Position with spacing
            x = (col - self.grid_size / 2) * self.spacing
            z = (row - 2) * self.spacing
            
            # Height based on severity (1-10 -> 1-10 units)
            height = threat["severity"]
            
            # Width/depth based on detection count (more detections = bigger footprint)
            detections = detection_counts.get(threat["id"], 0)
            size_multiplier = 1 + min(detections * 0.1, 1.0)  # Max 2x size
            width = self.base_size * size_multiplier
            depth = self.base_size * size_multiplier
            
            # Color from surface type
            surface = threat["surface"]
            color = SURFACE_COLORS.get(surface, "#666666")
            
            buildings.append({
                "id": threat["id"],
                "name": threat["name"],
                "severity": threat["severity"],
                "surface": surface.value,
                "color": color,
                "height": height,
                "width": width,
                "depth": depth,
                "x": x,
                "z": z,
                "detections": detections,
                "risk_level": threat.get("risk_level", "Medium"),
                "complexity": threat.get("complexity", "Medium"),
                "category": threat.get("category", ""),
                "description": threat.get("description", ""),
                "mitigation": threat.get("mitigation", "")
            })
        
        # Calculate statistics
        surfaces = {}
        for threat in self.threats:
            surface = threat["surface"].value
            surfaces[surface] = surfaces.get(surface, 0) + 1
        
        return {
            "buildings": buildings,
            "metadata": {
                "total_threats": len(buildings),
                "max_severity": max(t["severity"] for t in self.threats),
                "min_severity": min(t["severity"] for t in self.threats),
                "surfaces": surfaces,
                "grid_size": self.grid_size,
                "spacing": self.spacing
            },
            "legend": [
                {"surface": "server_apis", "color": SURFACE_COLORS[AttackSurface.SERVER_APIS], "label": "Server APIs"},
                {"surface": "tool_metadata", "color": SURFACE_COLORS[AttackSurface.TOOL_METADATA], "label": "Tool Metadata"},
                {"surface": "runtime_flow", "color": SURFACE_COLORS[AttackSurface.RUNTIME_FLOW], "label": "Runtime Flow"},
                {"surface": "transport", "color": SURFACE_COLORS[AttackSurface.TRANSPORT], "label": "Transport"},
            ]
        }
    
    def get_threat_by_id(self, threat_id: str) -> Dict[str, Any]:
        """Get detailed threat info by ID"""
        for threat in self.threats:
            if threat["id"] == threat_id:
                return {
                    "id": threat["id"],
                    "name": threat["name"],
                    "severity": threat["severity"],
                    "surface": threat["surface"].value,
                    "color": SURFACE_COLORS.get(threat["surface"], "#666666")
                }
        return None


# Singleton instance
_generator = None

def get_generator() -> ThreatLandscapeGenerator:
    """Get singleton generator instance"""
    global _generator
    if _generator is None:
        _generator = ThreatLandscapeGenerator()
    return _generator


def generate_threat_landscape(detection_counts: Dict[str, int] = None) -> Dict[str, Any]:
    """Convenience function to generate landscape"""
    return get_generator().generate_landscape(detection_counts)
