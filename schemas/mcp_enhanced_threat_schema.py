"""
Enhanced MCP Threat Schema

Based on Standard Taxonomy, MCP-UPD, MPMA, and comprehensive threat modeling requirements.
Supports the full threat matrix structure as specified.
"""

from __future__ import annotations

import json
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


class MCPWorkflowPhase(Enum):
    """MCP workflow phases (Standard Taxonomy)"""
    TASK_PLANNING = "Task Planning"
    TOOL_INVOCATION = "Tool Invocation"
    RESPONSE_HANDLING = "Response Handling"
    CROSS_PHASE = "Cross-Phase"


class MSBAttackType(Enum):
    """Standard Attack Types"""
    # Task Planning Phase
    PROMPT_INJECTION = "Prompt Injection (PI)"
    PREFERENCE_MANIPULATION = "Preference Manipulation (PM)"
    NAME_COLLISION = "Name Collision (NC)"
    
    # Tool Invocation Phase
    OUT_OF_SCOPE_PARAMETER = "Out-of-Scope Parameter (OP)"
    
    # Response Handling Phase
    USER_IMPERSONATION = "User Impersonation (UI)"
    FAKE_ERROR = "Fake Error (FE)"
    RETRIEVAL_INJECTION = "Retrieval Injection (RI)"
    
    # Cross-Phase
    MIXED_ATTACK = "Mixed Attack"


class MCPUPDAttackPhase(Enum):
    """MCP-UPD Attack Phases (5-stage attack chain)"""
    TOOL_SURFACE_DISCOVERY = "Tool Surface Discovery"
    PARAMETER_INJECTION = "Parameter Injection / Constraint Evasion"
    PARASITIC_CHAINING = "Tool-to-Tool Parasitic Chaining"
    UPD_EXPLOITATION = "UPD Exploitation"
    POST_TOOL_IMPACT = "Post-Tool Impact"


class MCPUPDAttackTool(Enum):
    """MCP-UPD Attack Tool Types"""
    EXTERNAL_INGESTION_TOOL = "External Ingestion Tool (EIT)"
    PRIVACY_ACCESS_TOOL = "Privacy Access Tool (PAT)"
    NETWORK_ACCESS_TOOL = "Network Access Tool (NAT)"
    # Additional tool types for 5-stage model
    UPD_SURFACE_TOOL = "UPD Surface Tool"
    DESERIALIZATION_TOOL = "Deserialization Tool"
    INSECURE_RESOURCE_TOOL = "Insecure Resource Access Tool"
    FILE_ACCESS_TOOL = "Over-broad File Access Tool"
    AUTH_BROKEN_TOOL = "Broken AuthN/AuthZ Tool"


class MPMAAttackType(Enum):
    """MPMA Attack Types"""
    DIRECT_PREFERENCE_MANIPULATION = "Direct Preference Manipulation Attack (DPMA)"
    GENETIC_ALGORITHM_PREFERENCE = "Genetic Algorithm Preference Manipulation Attack (GAPMA)"


class GAPMAStrategy(Enum):
    """GAPMA Advertising Strategies"""
    AUTHORITATIVE = "Authoritative (Au)"
    EMOTIONAL = "Emotional"
    EXAGGERATED = "Exaggerated"
    SUBLIMINAL = "Subliminal"


class ThreatVector(Enum):
    """Threat Vector Categories"""
    PROMPT_BASED_ATTACKS = "Prompt-based Attacks / Injection"
    TOOL_PLUGIN_MISUSE = "Tool / Plugin Misuse / Abuse"
    PRIVACY_DATA_LEAKAGE = "Privacy / Data Leakage"
    RESOURCE_ABUSE_DOS = "Resource Abuse / DoS / Performance Exhaustion"
    PRIVILEGE_ESCALATION = "Privilege Escalation / Unauthorized Access"
    SUPPLY_CHAIN_RISKS = "Supply-chain / Dependency / Library Risks"
    CONFIGURATION_RISKS = "Configuration / Misconfiguration / Deployment Risks"
    LOGIC_ABUSE = "Logic / Business-Logic Abuse / Misuse"
    AGENT_MEMORY_ATTACKS = "Agent/Memory / State-based Attacks"
    AUDIT_LOGGING_FAILURES = "Audit / Logging / Non-repudiation Failures"


class RiskLevel(Enum):
    """Risk levels"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(Enum):
    """Threat remediation status"""
    UNEVALUATED = "unevaluated"
    EVALUATED = "evaluated"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    IGNORED = "ignored"
    PATCHING = "patching"
    ARCHIVED = "archived"


@dataclass
class AttackStep:
    """Attack step in exploit chain"""
    step_number: int
    action: str
    expected_result: str
    tools_needed: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class DetectionMethod:
    """Detection method for threat"""
    method_type: str  # behavioral, signature, static, dynamic, etc.
    description: str
    indicators: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    false_positive_rate: Optional[str] = None


@dataclass
class MitigationControl:
    """Mitigation control/defense"""
    control_id: str
    control_type: str  # input_validation, sandboxing, rate_limiting, etc.
    description: str
    implementation_guidance: str
    effectiveness: Optional[str] = None  # high, medium, low


@dataclass
class Reference:
    """Reference to external source"""
    source_type: str  # paper, CVE, GitHub, report, POC, etc.
    title: str
    url: Optional[str] = None
    date: Optional[str] = None
    authors: List[str] = field(default_factory=list)
    notes: Optional[str] = None


@dataclass
class EnhancedMCPThreat:
    """
    Enhanced MCP Threat with full metadata structure.
    
    Based on comprehensive threat modeling requirements including:
    - Standard Taxonomy (workflow phases, attack types)
    - MCP-UPD (parasitic tool chains)
    - MPMA (preference manipulation)
    - Traditional threat modeling (STRIDE, DREAD, etc.)
    """
    # Basic identification
    id: str = field(default_factory=lambda: f"MCP-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    title: str = ""
    description: str = ""
    
    # Classification
    threat_vector: ThreatVector = ThreatVector.PROMPT_BASED_ATTACKS
    stride_category: str = "Tampering"
    
    # Standard Taxonomy
    mcp_workflow_phase: Optional[MCPWorkflowPhase] = None
    msb_attack_type: Optional[MSBAttackType] = None
    
    # MCP-UPD classification
    mcp_upd_phase: Optional[MCPUPDAttackPhase] = None
    mcp_upd_tools: List[MCPUPDAttackTool] = field(default_factory=list)
    
    # MPMA classification
    mpma_attack_type: Optional[MPMAAttackType] = None
    gapma_strategy: Optional[GAPMAStrategy] = None
    
    # Preconditions and assumptions
    preconditions: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    
    # Assets at risk
    assets_at_risk: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    
    # Impact and damage
    impact: List[str] = field(default_factory=list)
    potential_damage: str = ""
    
    # Attack/exploit steps
    attack_steps: List[AttackStep] = field(default_factory=list)
    exploit_steps: List[str] = field(default_factory=list)
    
    # Detection
    detection_methods: List[DetectionMethod] = field(default_factory=list)
    warning_signs: List[str] = field(default_factory=list)
    
    # Mitigation
    mitigations: List[str] = field(default_factory=list)
    recommended_controls: List[MitigationControl] = field(default_factory=list)
    
    # Risk assessment
    severity: RiskLevel = RiskLevel.MEDIUM
    risk_score: float = 7.0
    cvss_score: Optional[float] = None
    likelihood: str = "medium"
    
    # NRP (Net Resilient Performance) metrics
    nrp_score: Optional[float] = None
    pua_score: Optional[float] = None  # Performance Under Attack
    asr_score: Optional[float] = None  # Attack Success Rate
    
    # Status
    status: ThreatStatus = ThreatStatus.UNEVALUATED
    is_mitigated: bool = False
    
    # Dates
    date_discovered: str = field(default_factory=lambda: datetime.now().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # References
    references: List[Reference] = field(default_factory=list)
    source: str = "manual"  # manual, ai_generated, intel_gathered, attack_test
    source_intel_ids: List[str] = field(default_factory=list)
    
    # Additional metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        
        # Convert enums to values
        if isinstance(data.get('threat_vector'), ThreatVector):
            data['threat_vector'] = data['threat_vector'].value
        if isinstance(data.get('mcp_workflow_phase'), MCPWorkflowPhase):
            data['mcp_workflow_phase'] = data['mcp_workflow_phase'].value
        if isinstance(data.get('msb_attack_type'), MSBAttackType):
            data['msb_attack_type'] = data['msb_attack_type'].value
        if isinstance(data.get('mcp_upd_phase'), MCPUPDAttackPhase):
            data['mcp_upd_phase'] = data['mcp_upd_phase'].value
        if isinstance(data.get('mpma_attack_type'), MPMAAttackType):
            data['mpma_attack_type'] = data['mpma_attack_type'].value
        if isinstance(data.get('gapma_strategy'), GAPMAStrategy):
            data['gapma_strategy'] = data['gapma_strategy'].value
        if isinstance(data.get('severity'), RiskLevel):
            data['severity'] = data['severity'].value
        if isinstance(data.get('status'), ThreatStatus):
            data['status'] = data['status'].value
        
        # Convert lists of enums
        if 'mcp_upd_tools' in data and data['mcp_upd_tools']:
            data['mcp_upd_tools'] = [t.value if isinstance(t, MCPUPDAttackTool) else t 
                                    for t in data['mcp_upd_tools']]
        
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EnhancedMCPThreat':
        """Create from dictionary"""
        # Convert enum strings back to enums
        if 'threat_vector' in data and isinstance(data['threat_vector'], str):
            try:
                data['threat_vector'] = ThreatVector(data['threat_vector'])
            except ValueError:
                data['threat_vector'] = ThreatVector.PROMPT_BASED_ATTACKS
        
        if 'mcp_workflow_phase' in data and isinstance(data['mcp_workflow_phase'], str):
            try:
                data['mcp_workflow_phase'] = MCPWorkflowPhase(data['mcp_workflow_phase'])
            except ValueError:
                data['mcp_workflow_phase'] = None
        
        if 'msb_attack_type' in data and isinstance(data['msb_attack_type'], str):
            try:
                data['msb_attack_type'] = MSBAttackType(data['msb_attack_type'])
            except ValueError:
                data['msb_attack_type'] = None
        
        if 'severity' in data and isinstance(data['severity'], str):
            try:
                data['severity'] = RiskLevel(data['severity'])
            except ValueError:
                data['severity'] = RiskLevel.MEDIUM
        
        if 'status' in data and isinstance(data['status'], str):
            try:
                data['status'] = ThreatStatus(data['status'])
            except ValueError:
                data['status'] = ThreatStatus.UNEVALUATED
        
        # MCP-UPD Phase and Tools
        if 'mcp_upd_phase' in data and isinstance(data['mcp_upd_phase'], str):
            try:
                data['mcp_upd_phase'] = MCPUPDAttackPhase(data['mcp_upd_phase'])
            except ValueError:
                data['mcp_upd_phase'] = None

        if 'mcp_upd_tools' in data and isinstance(data['mcp_upd_tools'], list):
            tools = []
            abbrev_map = {
                "EIT": MCPUPDAttackTool.EXTERNAL_INGESTION_TOOL,
                "PAT": MCPUPDAttackTool.PRIVACY_ACCESS_TOOL,
                "NAT": MCPUPDAttackTool.NETWORK_ACCESS_TOOL
            }
            for t in data['mcp_upd_tools']:
                if isinstance(t, str):
                    try:
                        tools.append(MCPUPDAttackTool(t))
                    except ValueError:
                        # Try abbreviations
                        if t in abbrev_map:
                            tools.append(abbrev_map[t])
                            continue
                        # Try partial match (e.g. "External Ingestion Tool")
                        found = False
                        for member in MCPUPDAttackTool:
                            if t in member.value:
                                tools.append(member)
                                found = True
                                break
                        if not found:
                            pass
                elif isinstance(t, MCPUPDAttackTool):
                    tools.append(t)
            data['mcp_upd_tools'] = tools
        
        # Convert attack steps
        if 'attack_steps' in data and data['attack_steps']:
            attack_steps = []
            for step_data in data['attack_steps']:
                if isinstance(step_data, dict):
                    attack_steps.append(AttackStep(**step_data))
                else:
                    attack_steps.append(step_data)
            data['attack_steps'] = attack_steps
        
        # Convert detection methods
        if 'detection_methods' in data and data['detection_methods']:
            detection_methods = []
            for method_data in data['detection_methods']:
                if isinstance(method_data, dict):
                    detection_methods.append(DetectionMethod(**method_data))
                else:
                    detection_methods.append(method_data)
            data['detection_methods'] = detection_methods
        
        # Convert mitigation controls
        if 'recommended_controls' in data and data['recommended_controls']:
            controls = []
            for control_data in data['recommended_controls']:
                if isinstance(control_data, dict):
                    controls.append(MitigationControl(**control_data))
                else:
                    controls.append(control_data)
            data['recommended_controls'] = controls
        
        # Convert references
        if 'references' in data and data['references']:
            references = []
            for ref_data in data['references']:
                if isinstance(ref_data, dict):
                    references.append(Reference(**ref_data))
                else:
                    references.append(ref_data)
            data['references'] = references
        
        return cls(**data)

