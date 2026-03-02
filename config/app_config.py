"""
MCP Threat Platform - Application Configuration

Centralized configuration management with environment variable support.
NO HARDCODED VALUES - All configuration is externalized.
"""

from __future__ import annotations

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from functools import lru_cache


# ==================== Configuration Paths ====================

def get_project_root() -> Path:
    """Get project root directory"""
    return Path(__file__).parent.parent


def get_config_dir() -> Path:
    """Get configuration directory"""
    return get_project_root() / "config"


def get_data_dir() -> Path:
    """Get data directory"""
    data_dir = get_project_root() / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


# ==================== Environment Variable Helpers ====================

def get_env(key: str, default: Any = None, required: bool = False) -> Any:
    """Get environment variable with optional default"""
    value = os.environ.get(key, default)
    if required and value is None:
        raise ValueError(f"Required environment variable {key} is not set")
    return value


def get_env_bool(key: str, default: bool = False) -> bool:
    """Get boolean environment variable"""
    value = os.environ.get(key, "").lower()
    if value in ("true", "1", "yes", "on"):
        return True
    elif value in ("false", "0", "no", "off"):
        return False
    return default


def get_env_int(key: str, default: int = 0) -> int:
    """Get integer environment variable"""
    try:
        return int(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default


def get_env_list(key: str, default: List[str] = None, separator: str = ",") -> List[str]:
    """Get list environment variable"""
    value = os.environ.get(key)
    if value:
        return [item.strip() for item in value.split(separator)]
    return default or []


# ==================== Configuration Classes ====================

@dataclass
class DatabaseConfig:
    """Database configuration"""
    type: str = field(default_factory=lambda: get_env("DB_TYPE", "sqlite"))
    url: str = field(default_factory=lambda: get_env(
        "DATABASE_URL", 
        f"sqlite:///{get_data_dir() / 'mcp_threat_platform.db'}"
    ))
    echo: bool = field(default_factory=lambda: get_env_bool("DB_ECHO", False))
    pool_size: int = field(default_factory=lambda: get_env_int("DB_POOL_SIZE", 5))
    max_overflow: int = field(default_factory=lambda: get_env_int("DB_MAX_OVERFLOW", 10))


@dataclass
class LLMEndpointConfig:
    """Single LLM endpoint configuration"""
    name: str
    api_base: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    enabled: bool = True
    priority: int = 0


@dataclass
class LLMConfig:
    """LLM configuration"""
    default_provider: str = field(default_factory=lambda: get_env("LLM_PROVIDER", "litellm"))
    
    # Endpoint configurations
    endpoints: List[LLMEndpointConfig] = field(default_factory=list)
    
    # Model assignments for different tasks (fallback to LITELLM_MODEL if not set)
    model_analysis: str = field(default_factory=lambda: get_env("LLM_MODEL_ANALYSIS") or get_env("LITELLM_MODEL"))
    model_summarization: str = field(default_factory=lambda: get_env("LLM_MODEL_SUMMARY") or get_env("LITELLM_MODEL"))
    model_attack: str = field(default_factory=lambda: get_env("LLM_MODEL_ATTACK") or get_env("LITELLM_MODEL"))
    model_risk: str = field(default_factory=lambda: get_env("LLM_MODEL_RISK") or get_env("LITELLM_MODEL"))
    
    # Rate limiting
    max_requests_per_minute: int = field(default_factory=lambda: get_env_int("LLM_RPM", 60))
    max_tokens_per_request: int = field(default_factory=lambda: get_env_int("LLM_MAX_TOKENS", 4096))
    
    def __post_init__(self):
        """Initialize endpoints from environment"""
        if not self.endpoints:
            # Primary endpoint (LiteLLM)
            if get_env("LITELLM_API_BASE"):
                self.endpoints.append(LLMEndpointConfig(
                    name="litellm_primary",
                    api_base=get_env("LITELLM_API_BASE"),
                    api_key=get_env("LITELLM_API_KEY"),
                    priority=0
                ))
            
            # Secondary endpoint (LiteLLM Latest)
            if get_env("LITELLM_API_LATEST"):
                self.endpoints.append(LLMEndpointConfig(
                    name="litellm_latest",
                    api_base=get_env("LITELLM_API_LATEST"),
                    api_key=get_env("LITELLM_API_KEY"),
                    priority=1
                ))
            
            # OpenAI fallback
            if get_env("OPENAI_API_KEY"):
                self.endpoints.append(LLMEndpointConfig(
                    name="openai",
                    api_base=get_env("OPENAI_API_BASE", "https://api.openai.com/v1"),
                    api_key=get_env("OPENAI_API_KEY"),
                    model=get_env("OPENAI_MODEL") or get_env("LITELLM_MODEL"),
                    priority=2
                ))
            
            # Anthropic fallback
            if get_env("ANTHROPIC_API_KEY"):
                self.endpoints.append(LLMEndpointConfig(
                    name="anthropic",
                    api_base=get_env("ANTHROPIC_API_BASE", "https://api.anthropic.com"),
                    api_key=get_env("ANTHROPIC_API_KEY"),
                    model=get_env("ANTHROPIC_MODEL", "claude-3-sonnet-20240229"),
                    priority=3
                ))


@dataclass
class Neo4jConfig:
    """Neo4j configuration"""
    enabled: bool = field(default_factory=lambda: get_env_bool("NEO4J_ENABLED", False))
    uri: str = field(default_factory=lambda: get_env("NEO4J_URI", "bolt://localhost:7687"))
    user: str = field(default_factory=lambda: get_env("NEO4J_USER", "neo4j"))
    password: str = field(default_factory=lambda: get_env("NEO4J_PASSWORD", ""))
    database: str = field(default_factory=lambda: get_env("NEO4J_DATABASE", "neo4j"))


@dataclass
class IntelSourceConfig:
    """Intelligence source configuration"""
    name: str
    source_type: str
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntelConfig:
    """Intelligence gathering configuration"""
    enabled: bool = field(default_factory=lambda: get_env_bool("INTEL_ENABLED", True))
    gather_interval_hours: int = field(default_factory=lambda: get_env_int("INTEL_INTERVAL", 24))
    max_items_per_source: int = field(default_factory=lambda: get_env_int("INTEL_MAX_ITEMS", 50))
    
    # Search keywords (configurable)
    mcp_keywords: List[str] = field(default_factory=lambda: get_env_list(
        "INTEL_MCP_KEYWORDS",
        ["MCP", "Model Context Protocol", "claude desktop", "mcp server"]
    ))
    
    security_keywords: List[str] = field(default_factory=lambda: get_env_list(
        "INTEL_SECURITY_KEYWORDS",
        ["security", "vulnerability", "injection", "attack", "exploit", "bypass"]
    ))
    
    # Sources
    sources: List[IntelSourceConfig] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize default sources"""
        if not self.sources:
            self.sources = [
                IntelSourceConfig(
                    name="github_security",
                    source_type="github",
                    enabled=get_env_bool("INTEL_GITHUB_ENABLED", True),
                    config={
                        "token": get_env("GITHUB_TOKEN"),
                        "repos": get_env_list("INTEL_GITHUB_REPOS", [
                            "anthropics/anthropic-cookbook",
                            "modelcontextprotocol/servers"
                        ])
                    }
                ),
                IntelSourceConfig(
                    name="cve_nvd",
                    source_type="cve",
                    enabled=get_env_bool("INTEL_CVE_ENABLED", True),
                    config={
                        "api_key": get_env("NVD_API_KEY")
                    }
                ),
                IntelSourceConfig(
                    name="arxiv_papers",
                    source_type="arxiv",
                    enabled=get_env_bool("INTEL_ARXIV_ENABLED", True),
                    config={
                        "categories": ["cs.CR", "cs.AI", "cs.CL"]
                    }
                )
            ]


@dataclass
class AttackConfig:
    """Attack engine configuration"""
    enabled: bool = field(default_factory=lambda: get_env_bool("ATTACK_ENABLED", True))
    max_concurrent: int = field(default_factory=lambda: get_env_int("ATTACK_MAX_CONCURRENT", 3))
    timeout_seconds: int = field(default_factory=lambda: get_env_int("ATTACK_TIMEOUT", 30))
    max_attempts_per_test: int = field(default_factory=lambda: get_env_int("ATTACK_MAX_ATTEMPTS", 10))
    
    # Dangerous tools that should be flagged
    dangerous_tools: List[str] = field(default_factory=lambda: get_env_list(
        "ATTACK_DANGEROUS_TOOLS",
        ["read_file", "write_file", "execute", "run_command", "browser-fetch", "shell"]
    ))
    
    # Attack categories to enable
    enabled_categories: List[str] = field(default_factory=lambda: get_env_list(
        "ATTACK_CATEGORIES",
        ["prompt_injection", "tool_abuse", "path_traversal", "ssrf"]
    ))


@dataclass
class DetectionConfig:
    """Detection and monitoring configuration"""
    enabled: bool = field(default_factory=lambda: get_env_bool("DETECTION_ENABLED", True))
    log_retention_days: int = field(default_factory=lambda: get_env_int("DETECTION_LOG_RETENTION", 30))
    alert_threshold: str = field(default_factory=lambda: get_env("DETECTION_ALERT_THRESHOLD", "medium"))
    
    # Rate limit detection
    rate_limit_window_seconds: int = field(default_factory=lambda: get_env_int("DETECTION_RATE_WINDOW", 60))
    rate_limit_max_calls: int = field(default_factory=lambda: get_env_int("DETECTION_RATE_MAX", 100))


@dataclass
class ReportConfig:
    """Reporting configuration"""
    output_dir: Path = field(default_factory=lambda: Path(get_env("REPORT_OUTPUT_DIR", str(get_data_dir() / "reports"))))
    formats: List[str] = field(default_factory=lambda: get_env_list("REPORT_FORMATS", ["pdf", "html", "json"]))
    include_evidence: bool = field(default_factory=lambda: get_env_bool("REPORT_INCLUDE_EVIDENCE", True))
    include_recommendations: bool = field(default_factory=lambda: get_env_bool("REPORT_INCLUDE_RECOMMENDATIONS", True))


@dataclass
class ServerConfig:
    """Server configuration"""
    host: str = field(default_factory=lambda: get_env("SERVER_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: get_env_int("SERVER_PORT", 5000))
    debug: bool = field(default_factory=lambda: get_env_bool("SERVER_DEBUG", True))
    cors_origins: List[str] = field(default_factory=lambda: get_env_list("CORS_ORIGINS", ["*"]))


@dataclass
class AppConfig:
    """Main application configuration"""
    name: str = field(default_factory=lambda: get_env("APP_NAME", "MCP Threat Platform"))
    version: str = field(default_factory=lambda: get_env("APP_VERSION", "2.0.0"))
    environment: str = field(default_factory=lambda: get_env("APP_ENV", "development"))
    
    # Sub-configurations
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    attack: AttackConfig = field(default_factory=AttackConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (hiding sensitive values)"""
        from dataclasses import asdict
        
        def hide_sensitive(obj, sensitive_keys={"api_key", "password", "token", "secret"}):
            if isinstance(obj, dict):
                return {
                    k: "***" if any(s in k.lower() for s in sensitive_keys) else hide_sensitive(v, sensitive_keys)
                    for k, v in obj.items()
                }
            elif isinstance(obj, list):
                return [hide_sensitive(item, sensitive_keys) for item in obj]
            return obj
        
        return hide_sensitive(asdict(self))


# ==================== YAML Configuration Loading ====================

def load_yaml_config(path: Path) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    if path.exists():
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}


def save_yaml_config(config: Dict[str, Any], path: Path):
    """Save configuration to YAML file"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        yaml.safe_dump(config, f, default_flow_style=False)


# ==================== Global Configuration Instance ====================

_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Get or create global configuration instance"""
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def reload_config():
    """Reload configuration from environment"""
    global _config
    _config = AppConfig()
    return _config


# ==================== Threat Templates (Loaded from YAML) ====================

def get_threat_templates() -> Dict[str, Any]:
    """Get threat templates from configuration file"""
    templates_path = get_config_dir() / "threat_templates.yaml"
    return load_yaml_config(templates_path)


def get_control_templates() -> Dict[str, Any]:
    """Get control templates from configuration file"""
    templates_path = get_config_dir() / "control_templates.yaml"
    return load_yaml_config(templates_path)


def get_attack_payloads() -> Dict[str, Any]:
    """Get attack payload templates from configuration file"""
    payloads_path = get_config_dir() / "attack_payloads.yaml"
    return load_yaml_config(payloads_path)


def get_detection_rules() -> Dict[str, Any]:
    """Get detection rules from configuration file"""
    rules_path = get_config_dir() / "detection_rules.yaml"
    return load_yaml_config(rules_path)


# ==================== Framework Mappings ====================

def get_stride_mapping() -> Dict[str, Any]:
    """Get STRIDE framework mapping"""
    mapping_path = get_config_dir() / "mappings" / "stride.yaml"
    return load_yaml_config(mapping_path)


def get_aatmf_mapping() -> Dict[str, Any]:
    """Get AATMF v2 framework mapping"""
    mapping_path = get_config_dir() / "mappings" / "aatmf_v2.yaml"
    return load_yaml_config(mapping_path)


def get_owasp_mapping() -> Dict[str, Any]:
    """Get OWASP LLM Top 10 mapping"""
    mapping_path = get_config_dir() / "mappings" / "owasp_llm.yaml"
    return load_yaml_config(mapping_path)


def get_mitre_atlas_mapping() -> Dict[str, Any]:
    """Get MITRE ATLAS mapping"""
    mapping_path = get_config_dir() / "mappings" / "mitre_atlas.yaml"
    return load_yaml_config(mapping_path)


