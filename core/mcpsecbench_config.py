"""
MCPSecBench Configuration Loader

Dynamically loads all MCPSecBench-related configurations from data sources
to avoid hardcoded strings in the codebase.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any
from pathlib import Path
import json


class MCPSecBenchConfig:
    """Configuration loader for MCPSecBench framework"""
    
    _instance: Optional[MCPSecBenchConfig] = None
    _surfaces: List[str] = []
    _attack_types: List[str] = []
    _matrix_data: Dict[str, Any] = {}
    _loaded: bool = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._loaded:
            self._load_config()
    
    def _load_config(self) -> None:
        """Load MCPSecBench configuration from JSON file"""
        try:
            from schemas.mcpsecbench_schema import (
                MCPSurface, MCPSecBenchAttackType,
                initialize_matrix, MCPSECBENCH_MATRIX
            )
            
            # Initialize matrix from JSON
            initialize_matrix()
            
            # Load surfaces from enum
            self._surfaces = [s.value for s in MCPSurface]
            
            # Load attack types from enum
            self._attack_types = [a.value for a in MCPSecBenchAttackType]
            
            # Load full matrix data from JSON file
            json_path = Path(__file__).parent.parent / "data" / "mcpsecbench_matrix.json"
            if json_path.exists():
                with open(json_path, 'r', encoding='utf-8') as f:
                    self._matrix_data = json.load(f)
            
            self._loaded = True
            
        except Exception as e:
            print(f"[MCPSecBenchConfig] Error loading config: {e}")
            # Fallback to empty lists
            self._surfaces = []
            self._attack_types = []
            self._matrix_data = {}
    
    @property
    def surfaces(self) -> List[str]:
        """Get list of MCP attack surfaces"""
        return self._surfaces.copy()
    
    @property
    def attack_types(self) -> List[str]:
        """Get list of MCPSecBench attack types"""
        return self._attack_types.copy()
    
    @property
    def matrix_data(self) -> Dict[str, Any]:
        """Get full matrix data"""
        return self._matrix_data.copy()
    
    def get_surface_by_keyword(self, keyword: str) -> Optional[str]:
        """
        Infer MCP surface from keyword (for intelligence matching).
        This is business logic for matching intel to MCP attack patterns.
        
        Args:
            keyword: Keyword to match against surface descriptions
            
        Returns:
            Surface name if matched, None otherwise
        """
        keyword_lower = keyword.lower()
        
        # Match keywords to surfaces (business logic for intel matching)
        surface_keywords = {
            self._surfaces[0] if len(self._surfaces) > 0 else "Server APIs & Functionality": [
                'server', 'endpoint', 'api', 'function', 'service'
            ],
            self._surfaces[1] if len(self._surfaces) > 1 else "Tool Metadata & Toolchain": [
                'metadata', 'manifest', 'registry', 'toolchain', 'tool definition', 'tool catalog'
            ],
            self._surfaces[2] if len(self._surfaces) > 2 else "Runtime / Invocation Flow": [
                'runtime', 'invocation', 'agent', 'decision', 'response handling'
            ],
            self._surfaces[3] if len(self._surfaces) > 3 else "Client / Integration Surface": [
                'client', 'sdk', 'integration', 'third-party'
            ]
        }
        
        for surface, keywords in surface_keywords.items():
            if any(kw in keyword_lower for kw in keywords):
                return surface
        
        return None
    
    def get_attack_type_by_keyword(self, keyword: str) -> Optional[str]:
        """
        Infer MCPSecBench attack type from keyword (for intelligence matching).
        This is business logic for matching intel to MCP attack patterns.
        
        Args:
            keyword: Keyword to match against attack type descriptions
            
        Returns:
            Attack type name if matched, None otherwise
        """
        keyword_lower = keyword.lower()
        
        # Match keywords to attack types (business logic for intel matching)
        # Match keywords to attack types (business logic for intel matching)
        attack_type_keywords = {
            "Prompt Injection": ['prompt injection', 'jailbreak', 'ignore previous instructions'],
            "Tool/Service Misuse": ['tool misuse', 'service misuse', 'confused ai', 'wrong tool'],
            "Schema Inconsistencies": ['schema', 'inconsistency', 'malformed', 'serialization'],
            "Slash Command Overlap": ['slash command', 'command overlap', 'ambiguous command'],
            "Vulnerable Client Exploitation": ['vulnerable client', 'client exploit', 'cve-2025-6514', 'client vulnerability'],
            "MCP Rebinding": ['rebinding', 'dns rebinding', 'redirect', 'connection hijack'],
            "Man-in-the-Middle (MitM)": ['mitm', 'man-in-the-middle', 'interception', 'eavesdropping'],
            "Tool Shadowing": ['tool shadowing', 'shadowing', 'masking', 'hidden tool'],
            "Data Exfiltration via Metadata": ['exfiltration', 'metadata leak', 'history leak', 'conversation leak'],
            "Package Name Squatting (Tool Level)": ['squatting', 'typosquatting', 'fake tool name'],
            "Indirect Prompt Injection": ['indirect injection', 'embedded content', 'log injection'],
            "Package Name Squatting (Server Level)": ['server spoofing', 'fake server', 'server identity'],
            "Configuration Drift": ['config drift', 'configuration drift', 'security drift'],
            "Sandbox Escape": ['sandbox escape', 'container escape', 'breakout'],
            "Tool Poisoning": ['tool poisoning', 'malicious tool', 'poisoned'],
            "Vulnerable Server Exploitation": ['vulnerable server', 'server exploit', 'rce', 'sqli'],
            "Rug Pull Attack": ['rug pull', 'malicious update', 'trust betrayal', 'delayed attack']
        }
        
        for attack_type, keywords in attack_type_keywords.items():
            if any(kw in keyword_lower for kw in keywords):
                return attack_type
        
        return None
    
    def get_default_surface(self) -> str:
        """Get default surface (first surface in list)"""
        return self._surfaces[0] if self._surfaces else "Server APIs & Functionality"
    
    def get_default_attack_type(self) -> str:
        """Get default attack type (first attack type in list)"""
        return self._attack_types[0] if self._attack_types else "Metadata Poisoning"
    
    def get_cell_data(self, surface: str, attack_type: str) -> Optional[Dict[str, Any]]:
        """Get cell data from matrix"""
        matrix = self._matrix_data.get('matrix', {})
        surface_data = matrix.get(surface, {})
        return surface_data.get(attack_type)


# Global instance
_config_instance: Optional[MCPSecBenchConfig] = None


def get_mcpsecbench_config() -> MCPSecBenchConfig:
    """Get global MCPSecBench configuration instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = MCPSecBenchConfig()
    return _config_instance


