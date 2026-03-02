"""
MCP Threat Schema - Unified Data Format

All sources (GitHub, PoC, automated attack tests, intelligence gathering) are converted to this format.
Each card in the Canvas UI uses this JSON Schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
from enum import Enum
import json
import uuid


class StrideCategory(str, Enum):
    """STRIDE threat categories for MCP"""
    SPOOFING = "Spoofing"           # Spoof MCP server, forge tool responses
    TAMPERING = "Tampering"          # Modify MCP tool responses, AI context injection
    REPUDIATION = "Repudiation"      # Lack of audit trail
    INFORMATION_DISCLOSURE = "Information Disclosure"  # Private file leakage
    DENIAL_OF_SERVICE = "Denial of Service"           # Infinite polling, context flooding
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"  # LLM unauthorized tool invocation


class CardType(str, Enum):
    """Card types"""
    ASSET = "asset"              # Asset card
    THREAT = "threat"            # Threat card
    CONTROL = "control"          # Security control card
    EVIDENCE = "evidence"        # Attack evidence card
    DATA_FLOW = "data_flow"      # Data flow card


class AssetType(str, Enum):
    """Asset types"""
    MCP_SERVER = "mcp_server"
    MCP_CLIENT = "mcp_client"
    LLM_PROVIDER = "llm_provider"
    TOOL = "tool"
    FILE_SYSTEM = "filesystem"
    BROWSER = "browser"
    DATABASE = "database"
    API_KEY_STORE = "api_key_store"
    CUSTOM_DATA = "custom_data"


class ControlType(str, Enum):
    """Security control types"""
    TOOL_SANDBOX = "tool_sandbox"
    TOOL_PERMISSION = "tool_permission"
    MODEL_SAFETY_VALIDATOR = "model_safety_validator"
    TOKEN_REDACTION = "token_redaction"
    RATE_LIMIT = "rate_limit"
    PATH_WHITELIST = "path_whitelist"
    URL_WHITELIST = "url_whitelist"
    AUDIT_LOGGING = "audit_logging"
    OUTPUT_VALIDATION = "output_validation"
    INPUT_SANITIZATION = "input_sanitization"


class RiskLevel(str, Enum):
    """Risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Evidence:
    """Attack evidence"""
    source_type: str  # github, cve, paper, poc, fuzz_test, injection_test
    source_url: Optional[str] = None
    poc_summary: Optional[str] = None
    payload: Optional[str] = None
    result: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPThreat:
    """
    MCP Threat Schema - Core data structure
    
    All threats (auto-generated, manually created, intelligence imported) use this format
    """
    id: str = field(default_factory=lambda: f"MCP-T-{uuid.uuid4().hex[:8].upper()}")
    type: CardType = CardType.THREAT
    
    # Basic information
    title: str = ""
    description: str = ""
    category: StrideCategory = StrideCategory.TAMPERING
    
    # Risk assessment
    risk_score: float = 0.0  # 0-10
    risk_level: RiskLevel = RiskLevel.MEDIUM
    cvss_score: Optional[float] = None
    
    # Impact and vectors
    impact: List[str] = field(default_factory=list)  # Data Integrity, Model Safety, etc.
    attack_vector: List[str] = field(default_factory=list)  # Tool Response Injection, etc.
    affected_components: List[str] = field(default_factory=list)  # MCP Server A, Tool:read_file
    
    # Defense recommendations
    recommended_controls: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    
    # Evidence
    evidence: Optional[Evidence] = None
    
    # Source and metadata
    source: str = "manual"  # manual, ai_generated, intel_gathered, attack_test
    auto_generated: bool = False
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['type'] = self.type.value
        data['category'] = self.category.value
        data['risk_level'] = self.risk_level.value
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPThreat':
        """Create from dictionary"""
        # Ensure type is set correctly (database uses threat_type, schema uses type)
        if 'type' not in data or data.get('type') not in [e.value for e in CardType]:
            data['type'] = CardType.THREAT.value
        
        # Handle threat_type from database model
        if 'threat_type' in data and 'type' not in data:
            data['type'] = CardType.THREAT.value
        
        # Convert string enums to enum objects
        if 'type' in data and isinstance(data['type'], str):
            try:
                data['type'] = CardType(data['type'])
            except ValueError:
                data['type'] = CardType.THREAT
        
        if 'category' in data and isinstance(data['category'], str):
            try:
                data['category'] = StrideCategory(data['category'])
            except ValueError:
                data['category'] = StrideCategory.TAMPERING
        
        if 'risk_level' in data and isinstance(data['risk_level'], str):
            try:
                data['risk_level'] = RiskLevel(data['risk_level'])
            except ValueError:
                data['risk_level'] = RiskLevel.HIGH
        
        # Map database fields to schema fields
        if 'stride_category' in data and 'category' not in data:
            data['category'] = data.pop('stride_category')
        
        if 'name' in data and 'title' not in data:
            data['title'] = data.get('name', '')
        
        # Remove fields that don't exist in schema
        # MCPThreat schema fields only
        schema_fields = {
            'id', 'type', 'title', 'description', 'category', 'risk_level', 
            'risk_score', 'cvss_score', 'impact', 'attack_vector', 
            'affected_components', 'recommended_controls', 'mitigations',
            'source', 'auto_generated', 'tags', 'created_at', 'updated_at',
            'evidence', 'metadata'
        }
        # Filter to only include schema fields
        filtered_data = {k: v for k, v in data.items() if k in schema_fields}
        
        # Handle list fields that might be strings
        if 'impact' in filtered_data and isinstance(filtered_data['impact'], str):
            filtered_data['impact'] = [i.strip() for i in filtered_data['impact'].split(',') if i.strip()]
        if 'attack_vector' in filtered_data and isinstance(filtered_data['attack_vector'], str):
            filtered_data['attack_vector'] = [a.strip() for a in filtered_data['attack_vector'].split(',') if a.strip()]
        if 'recommended_controls' in filtered_data and isinstance(filtered_data['recommended_controls'], str):
            filtered_data['recommended_controls'] = [c.strip() for c in filtered_data['recommended_controls'].split(',') if c.strip()]
        
        if 'evidence' in filtered_data and isinstance(filtered_data['evidence'], dict):
            filtered_data['evidence'] = Evidence(**filtered_data['evidence'])
        
        return cls(**filtered_data)


@dataclass
class MCPAsset:
    """
    MCP Asset Schema
    
    Describes MCP Server, Client, Tools, Data Resources, etc.
    """
    id: str = field(default_factory=lambda: f"MCP-A-{uuid.uuid4().hex[:8].upper()}")
    type: CardType = CardType.ASSET
    asset_type: AssetType = AssetType.MCP_SERVER
    
    # Basic information
    name: str = ""
    description: str = ""
    version: Optional[str] = None
    
    # Connection information
    endpoint: Optional[str] = None
    transport: str = "stdio"  # stdio, http, websocket
    
    # Capabilities and permissions
    tools: List[str] = field(default_factory=list)  # Tool list
    resources: List[str] = field(default_factory=list)  # Resource list
    permissions: List[str] = field(default_factory=list)
    
    # Security settings
    security_controls: List[str] = field(default_factory=list)  # Applied controls
    vulnerabilities: List[str] = field(default_factory=list)  # Known vulnerabilities
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['type'] = self.type.value
        data['asset_type'] = self.asset_type.value
        return data


@dataclass
class MCPControl:
    """
    MCP Security Control Schema
    
    Describes security configurations (sandbox, whitelist, rate limit, etc.)
    """
    id: str = field(default_factory=lambda: f"MCP-C-{uuid.uuid4().hex[:8].upper()}")
    type: CardType = CardType.CONTROL
    control_type: ControlType = ControlType.TOOL_SANDBOX
    
    # Basic information
    name: str = ""
    description: str = ""
    
    # Configuration
    enabled: bool = True
    configuration: Dict[str, Any] = field(default_factory=dict)
    
    # Relationships
    applied_to: List[str] = field(default_factory=list)  # Asset IDs
    mitigates: List[str] = field(default_factory=list)   # Threat IDs
    
    # Effectiveness
    effectiveness: float = 0.0  # 0-100%
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['type'] = self.type.value
        data['control_type'] = self.control_type.value
        return data


@dataclass
class MCPAttackEvidence:
    """
    MCP Attack Evidence Schema
    
    Records automated attack test results
    """
    id: str = field(default_factory=lambda: f"MCP-E-{uuid.uuid4().hex[:8].upper()}")
    type: CardType = CardType.EVIDENCE
    
    # Test information
    test_type: str = ""  # fuzz_test, injection_test, tool_misuse, sandbox_bypass
    test_name: str = ""
    
    # Target
    target_asset: str = ""  # Asset ID
    target_tool: Optional[str] = None
    
    # Results
    success: bool = False
    attack_success_rate: float = 0.0  # ASR
    payload_used: Optional[str] = None
    response_received: Optional[str] = None
    
    # Analysis
    ai_analysis: Optional[str] = None
    vulnerability_confirmed: bool = False
    related_threat: Optional[str] = None  # Threat ID
    
    # Metadata
    executed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['type'] = self.type.value
        return data


@dataclass
class MCPDataFlow:
    """
    MCP Data Flow Schema
    
    Describes data flow between components
    """
    id: str = field(default_factory=lambda: f"MCP-DF-{uuid.uuid4().hex[:8].upper()}")
    type: CardType = CardType.DATA_FLOW
    
    # Connection
    source_id: str = ""      # Asset ID
    target_id: str = ""      # Asset ID
    
    # Data flow information
    data_type: str = ""      # request, response, tool_call, file_access
    protocol: str = ""       # json-rpc, http, file_io
    encrypted: bool = False
    
    # Risk
    risk_factors: List[str] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['type'] = self.type.value
        return data


# ============== Threat Templates ==============

MCP_THREAT_TEMPLATES = {
    """
    Pre-defined threat templates for fallback and demonstration purposes.
    
    NOTE: The system dynamically generates threats using AI based on the specific architecture.
    These templates are ONLY used when:
    1. AI generation fails or is unavailable
    2. Providing examples for the threat creation UI
    3. Bootstrapping the database with initial known threats
    
    The system is NOT limited to these threats. AI can generate novel threats not listed here.
    """
    "tool_response_injection": MCPThreat(
        title="MCP Tool Response Injection",
        description="Attackers can modify MCP Tool response data, causing LLM to receive tampered information",
        category=StrideCategory.TAMPERING,
        risk_score=8.2,
        risk_level=RiskLevel.HIGH,
        impact=["Data Integrity", "Model Safety", "Client Compromise"],
        attack_vector=["Tool Response Injection", "MITM on Server"],
        recommended_controls=["Validate tool output", "Enable tool sandbox", "Implement server integrity checks"]
    ),
    
    "prompt_injection_via_tool": MCPThreat(
        title="Prompt Injection via MCP Tool",
        description="Inject malicious prompts through MCP Tool output to bypass model safety restrictions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        risk_score=9.0,
        risk_level=RiskLevel.CRITICAL,
        impact=["Model Safety", "Access Control Bypass", "Data Exfiltration"],
        attack_vector=["Indirect Prompt Injection", "Tool Output Manipulation"],
        recommended_controls=["Output sanitization", "Prompt boundary enforcement", "Tool output validation"]
    ),
    
    "filesystem_path_traversal": MCPThreat(
        title="FileSystem Path Traversal via MCP Tool",
        description="Use MCP filesystem tools to perform path traversal attacks and access unauthorized files",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        risk_score=7.5,
        risk_level=RiskLevel.HIGH,
        impact=["Data Confidentiality", "Secret Exposure", "System Compromise"],
        attack_vector=["Path Traversal", "Sandbox Escape"],
        recommended_controls=["Path whitelist", "Sandbox enforcement", "Input validation"]
    ),
    
    "mcp_server_spoofing": MCPThreat(
        title="MCP Server Spoofing",
        description="Attackers spoof MCP Server to provide malicious tools or tamper with responses",
        category=StrideCategory.SPOOFING,
        risk_score=8.0,
        risk_level=RiskLevel.HIGH,
        impact=["Trust Violation", "Data Integrity", "Client Compromise"],
        attack_vector=["Server Impersonation", "DNS Spoofing", "MITM"],
        recommended_controls=["Server authentication", "TLS verification", "Certificate pinning"]
    ),
    
    "tool_privilege_escalation": MCPThreat(
        title="Tool Privilege Escalation",
        description="LLM is induced to call dangerous MCP Tools beyond expected permissions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        risk_score=8.5,
        risk_level=RiskLevel.HIGH,
        impact=["Access Control Bypass", "System Compromise", "Data Breach"],
        attack_vector=["Capability Escalation", "Permission Bypass"],
        recommended_controls=["Tool permission model", "Least privilege", "Tool allowlist"]
    ),
    
    "context_flooding_dos": MCPThreat(
        title="Context Flooding DoS",
        description="Cause service interruption through excessive MCP Tool calls or large data responses",
        category=StrideCategory.DENIAL_OF_SERVICE,
        risk_score=6.5,
        risk_level=RiskLevel.MEDIUM,
        impact=["Service Availability", "Resource Exhaustion"],
        attack_vector=["Context Window Overflow", "Infinite Loop", "Resource Exhaustion"],
        recommended_controls=["Rate limiting", "Context size limits", "Timeout enforcement"]
    ),
    
    "api_key_leakage": MCPThreat(
        title="API Key Leakage via Tool Output",
        description="MCP Tool output accidentally contains API Key or other sensitive credentials",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        risk_score=9.0,
        risk_level=RiskLevel.CRITICAL,
        impact=["Credential Exposure", "Account Compromise", "Data Breach"],
        attack_vector=["Output Data Leak", "Log Exposure"],
        recommended_controls=["Token redaction", "Output filtering", "Secret scanning"]
    ),
    
    "browser_ssrf": MCPThreat(
        title="SSRF via Browser MCP Tool",
        description="Use browser MCP tools to perform SSRF attacks and access internal services",
        category=StrideCategory.TAMPERING,
        risk_score=7.8,
        risk_level=RiskLevel.HIGH,
        impact=["Internal Service Access", "Data Exfiltration", "Network Pivoting"],
        attack_vector=["SSRF", "URL Manipulation"],
        recommended_controls=["URL whitelist", "Network isolation", "Request validation"]
    )
}


def get_threat_template(template_name: str) -> Optional[MCPThreat]:
    """Get threat template"""
    return MCP_THREAT_TEMPLATES.get(template_name)


def list_threat_templates() -> List[str]:
    """List all threat templates"""
    return list(MCP_THREAT_TEMPLATES.keys())


