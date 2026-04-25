"""
MCP Security Scanner - Data Models

Defines data structures for scan results, vulnerabilities, configurations,
and all scanner-related entities.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(str, Enum):
    """Vulnerability categories"""
    TOOL_POISONING = "tool_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    PARAMETER_INJECTION = "parameter_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_LEAK = "credential_leak"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    SUPPLY_CHAIN = "supply_chain"
    CONFIG_INSECURE = "config_insecure"
    PERMISSION_ISSUE = "permission_issue"
    PROTOCOL_VIOLATION = "protocol_violation"
    CRYPTO_MISUSE = "crypto_misuse"
    TOOL_MUTATION = "tool_mutation"
    SERVER_SPOOFING = "server_spoofing"
    TOXIC_FLOW = "toxic_flow"
    CONVERSATION_EXFILTRATION = "conversation_exfiltration"
    ANSI_INJECTION = "ansi_injection"


class ScanMode(str, Enum):
    """Scanning modes"""
    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    FULL = "full"


@dataclass
class Vulnerability:
    """Vulnerability representation with comprehensive metadata"""
    id: str
    category: VulnerabilityCategory
    severity: SeverityLevel
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    
    # Detection metadata
    detection_method: str = ""  # static, dynamic, llm, threat_intel
    confidence: float = 0.0  # 0.0-1.0
    llm_analysis: Optional[Dict[str, Any]] = None
    
    # Impact and remediation
    impact: str = ""
    remediation: str = ""
    recommended_controls: List[str] = field(default_factory=list)
    
    # Scoring
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    aivss_score: Optional[float] = None
    risk_score: float = 0.0  # 0.0-10.0
    
    # Threat intelligence
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    mitre_attack: List[str] = field(default_factory=list)
    threat_intel_refs: List[str] = field(default_factory=list)
    
    # Attack chain context
    attack_chain_id: Optional[str] = None
    related_vulnerabilities: List[str] = field(default_factory=list)
    
    # Metadata
    detected_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'category': self.category.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'detection_method': self.detection_method,
            'confidence': self.confidence,
            'llm_analysis': self.llm_analysis,
            'impact': self.impact,
            'remediation': self.remediation,
            'recommended_controls': self.recommended_controls,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'aivss_score': self.aivss_score,
            'risk_score': self.risk_score,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'mitre_attack': self.mitre_attack,
            'threat_intel_refs': self.threat_intel_refs,
            'attack_chain_id': self.attack_chain_id,
            'related_vulnerabilities': self.related_vulnerabilities,
            'detected_at': self.detected_at.isoformat(),
            'metadata': self.metadata
        }


@dataclass
class ScanConfig:
    """Scan configuration"""
    target: str  # Path or GitHub URL
    mode: ScanMode = ScanMode.HYBRID
    
    # Module toggles
    enable_static_analysis: bool = True
    enable_llm_detection: bool = True
    enable_supply_chain: bool = True
    enable_runtime_proxy: bool = False
    enable_threat_intel: bool = True
    enable_attack_chain: bool = True
    
    # Static analysis options
    static_include_patterns: List[str] = field(default_factory=lambda: [
        '*.py', '*.js', '*.ts', '*.json', '*.yaml', '*.yml', '*.toml'
    ])
    static_exclude_patterns: List[str] = field(default_factory=lambda: [
        '**/node_modules/**', '**/__pycache__/**', '**/.git/**'
    ])
    
    # LLM options
    llm_provider: str = "openai"
    llm_model: Optional[str] = field(default_factory=lambda: os.getenv("LITELLM_MODEL"))
    llm_api_key: Optional[str] = None
    llm_temperature: float = 0.1
    llm_max_tokens: int = 2000
    
    # Severity filter
    min_severity: SeverityLevel = SeverityLevel.INFO
    
    # Output options
    output_format: str = "json"  # json, html, sarif, terminal
    output_file: Optional[str] = None
    
    # Advanced options
    fail_on_severity: Optional[SeverityLevel] = None
    include_metadata: bool = True
    include_code_snippets: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'target': self.target,
            'mode': self.mode.value,
            'enable_static_analysis': self.enable_static_analysis,
            'enable_llm_detection': self.enable_llm_detection,
            'enable_supply_chain': self.enable_supply_chain,
            'enable_runtime_proxy': self.enable_runtime_proxy,
            'enable_threat_intel': self.enable_threat_intel,
            'enable_attack_chain': self.enable_attack_chain,
            'static_include_patterns': self.static_include_patterns,
            'static_exclude_patterns': self.static_exclude_patterns,
            'llm_provider': self.llm_provider,
            'llm_model': self.llm_model,
            'min_severity': self.min_severity.value,
            'output_format': self.output_format,
            'output_file': self.output_file
        }


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    target: str
    config: ScanConfig
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Results
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    # Statistics
    total_files_scanned: int = 0
    total_tools_analyzed: int = 0
    total_dependencies_checked: int = 0
    
    # Summary
    severity_counts: Dict[str, int] = field(default_factory=dict)
    category_counts: Dict[str, int] = field(default_factory=dict)
    
    # Attack chains
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration"""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score"""
        if not self.vulnerabilities:
            return 0.0
        
        # Weighted average based on severity
        weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.0,
            SeverityLevel.MEDIUM: 4.0,
            SeverityLevel.LOW: 1.0,
            SeverityLevel.INFO: 0.5
        }
        
        total_weight = sum(weights.get(v.severity, 0) for v in self.vulnerabilities)
        count = len(self.vulnerabilities)
        
        return total_weight / count if count > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'config': self.config.to_dict(),
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'total_files_scanned': self.total_files_scanned,
            'total_tools_analyzed': self.total_tools_analyzed,
            'total_dependencies_checked': self.total_dependencies_checked,
            'severity_counts': self.severity_counts,
            'category_counts': self.category_counts,
            'attack_chains': self.attack_chains,
            'risk_score': self.risk_score,
            'errors': self.errors,
            'warnings': self.warnings,
            'metadata': self.metadata
        }

