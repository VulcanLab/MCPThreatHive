"""
MCP Knowledge Base - Centralized MCP Security Knowledge
making it available to all platform features without hardcoding.
"""

from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

from database.db_manager import get_db_manager


@dataclass
class MCPThreatKnowledge:
    """MCP Threat Knowledge Item"""
    id: str
    component: str  # MCP Server, MCP Client, Host Environment, etc.
    threat_category: str
    description: str
    maestro_layers: List[str] = field(default_factory=list)
    mitigation_controls: List[str] = field(default_factory=list)
    stride_category: str = ""
    risk_score: float = 7.0
    affected_asset_types: List[str] = field(default_factory=list)
    abuse_cases: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPControlKnowledge:
    """MCP Control Knowledge Item"""
    id: str
    name: str
    description: str
    category: str  # Transport, Authentication, Authorization, etc.
    control_measures: List[str] = field(default_factory=list)
    mitigates_threats: List[str] = field(default_factory=list)
    maestro_layers: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPAbuseCase:
    """MCP Abuse Case"""
    id: str
    title: str
    description: str
    threat_actor: str = ""
    entry_point: str = ""
    related_threats: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPKnowledgeBase:
    """
    Centralized MCP Security Knowledge Base
    
    - Threat Matrix (for threat mapping)
    - Knowledge Graph (for relationship visualization)
    - Config (for rule settings)
    - Canvas (for threat templates)
    - Intel Gathering (for threat type references)
    """
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager or get_db_manager()
        self.threats: Dict[str, MCPThreatKnowledge] = {}
        self.controls: Dict[str, MCPControlKnowledge] = {}
        self.abuse_cases: Dict[str, MCPAbuseCase] = {}
        self.maestro_layers = [
            "L1 - Foundation Models",
            "L2 - Data Operations",
            "L3 - Agent Frameworks",
            "L4 - Deployment Infrastructure",
            "L5 - Evaluation & Observability",
            "L6 - Security & Compliance",
            "L7 - Agent Ecosystem"
        ]
    
    def _load_initial_knowledge(self) -> Dict[str, int]:
        """
        Load initial MCP security knowledge from internal data.
        
        Returns:
            Dict with counts of loaded items
        """
        try:
            from core.mcp_knowledge_data import INITIAL_THREATS, INITIAL_CONTROLS, INITIAL_ABUSE_CASES
        except ImportError:
            print("Failed to import initial knowledge data")
            return {'threats': 0, 'controls': 0, 'abuse_cases': 0}
        
        counts = {
            'threats': 0,
            'controls': 0,
            'abuse_cases': 0
        }
        
        # Load Threats
        for item in INITIAL_THREATS:
            threat = MCPThreatKnowledge(
                id=item['id'],
                component=item['component'],
                threat_category=item['threat_category'],
                description=item['description'],
                maestro_layers=item.get('maestro_layers', []),
                mitigation_controls=item.get('mitigation_controls', []),
                stride_category=item.get('stride_category', 'Tampering'),
                risk_score=item.get('risk_score', 7.0),
                affected_asset_types=item.get('affected_asset_types', []),
                abuse_cases=item.get('abuse_cases', []),
                metadata=item.get('metadata', {})
            )
            self.threats[threat.id] = threat
            counts['threats'] += 1
            
        # Load Controls
        for item in INITIAL_CONTROLS:
            control = MCPControlKnowledge(
                id=item['id'],
                name=item['name'],
                description=item['description'],
                category=item['category'],
                control_measures=item.get('control_measures', []),
                mitigates_threats=item.get('mitigates_threats', []),
                maestro_layers=item.get('maestro_layers', []),
                metadata=item.get('metadata', {})
            )
            self.controls[control.id] = control
            counts['controls'] += 1
            
        # Load Abuse Cases
        for item in INITIAL_ABUSE_CASES:
            abuse_case = MCPAbuseCase(
                id=item.get('id', 'unknown'),
                title=item.get('title', 'Unknown Abuse Case'),
                description=item.get('description', ''),
                threat_actor=item.get('threat_actor', ''),
                entry_point=item.get('entry_point', ''),
                related_threats=item.get('related_threats', []),
                metadata=item.get('metadata', {})
            )
            self.abuse_cases[abuse_case.id] = abuse_case
            counts['abuse_cases'] += 1
            
        return counts
    
    def _map_to_stride(self, threat_category: str, description: str) -> str:
        """Map threat category to STRIDE category"""
        text = f"{threat_category} {description}".lower()
        
        if any(kw in text for kw in ['spoof', 'impersonat', 'fake', 'masquerade']):
            return 'Spoofing'
        elif any(kw in text for kw in ['tamper', 'modify', 'alter', 'inject', 'manipulate']):
            return 'Tampering'
        elif any(kw in text for kw in ['repudiat', 'deny', 'audit', 'log']):
            return 'Repudiation'
        elif any(kw in text for kw in ['disclosur', 'leak', 'expose', 'exfiltrat']):
            return 'Information Disclosure'
        elif any(kw in text for kw in ['denial', 'dos', 'flood', 'exhaust', 'crash']):
            return 'Denial of Service'
        elif any(kw in text for kw in ['elevat', 'privilege', 'escalat', 'bypass']):
            return 'Elevation of Privilege'
        else:
            return 'Tampering'  # Default
    
    def _estimate_risk_score(self, threat_category: str, description: str) -> float:
        """Estimate risk score based on threat category and description"""
        text = f"{threat_category} {description}".lower()
        
        # High risk keywords
        if any(kw in text for kw in ['compromise', 'exfiltrat', 'unauthorized', 'malicious', 'exploit']):
            return 9.0
        elif any(kw in text for kw in ['vulnerable', 'insecure', 'leak', 'disclosure']):
            return 7.5
        elif any(kw in text for kw in ['error', 'mismatch', 'unpredictable']):
            return 5.0
        else:
            return 7.0  # Default medium-high
    
    def store_to_database(self, project_id: str = 'default-project') -> Dict[str, int]:
        """
        Store knowledge base data to database as threats and controls.
        
        Returns:
            Dict with counts of stored items
        """
        stored = {'threats': 0, 'controls': 0}
        
        # Store threats
        for threat_knowledge in self.threats.values():
            # Check for duplicates? db_manager likely handles it or throws constraint error
            # We'll rely on db_manager to handle duplicate IDs/Names if possible, or catch error
            
            threat_data = {
                'name': f"{threat_knowledge.component}: {threat_knowledge.threat_category}",
                'description': threat_knowledge.description,
                'stride_category': threat_knowledge.stride_category,
                'threat_type': 'mcp_knowledge_base',
                'attack_vector': ', '.join(threat_knowledge.abuse_cases) if threat_knowledge.abuse_cases else '',
                'impact': threat_knowledge.description,
                'risk_score': threat_knowledge.risk_score,
                'risk_level': 'high' if threat_knowledge.risk_score >= 8.0 else 'medium',
                'source': 'MCP Knowledge Base',
                'tags': threat_knowledge.maestro_layers + [threat_knowledge.component],
                'schema_data': {
                    'maestro_layers': threat_knowledge.maestro_layers,
                    'mitigation_controls': threat_knowledge.mitigation_controls,
                    'component': threat_knowledge.component,
                    'threat_category': threat_knowledge.threat_category,
                    'is_knowledge_base': True
                }
            }
            
            try:
                self.db_manager.create_threat(threat_data, project_id)
                stored['threats'] += 1
            except Exception as e:
                # Expected if duplicate
                pass
        
        # Store controls
        for control_knowledge in self.controls.values():
            control_data = {
                'name': control_knowledge.name,
                'description': control_knowledge.description,
                'control_type': 'mcp_knowledge_base',
                'effectiveness': 85.0,  # Default effectiveness
                'configuration': {
                    'control_measures': control_knowledge.control_measures,
                    'category': control_knowledge.category,
                    'maestro_layers': control_knowledge.maestro_layers,
                    'is_knowledge_base': True
                }
            }
            
            try:
                self.db_manager.create_control(control_data, project_id)
                stored['controls'] += 1
            except Exception as e:
                # Expected if duplicate
                pass
        
        return stored
    
    def get_threats_by_component(self, component: str) -> List[MCPThreatKnowledge]:
        """Get threats for a specific component"""
        return [t for t in self.threats.values() if t.component == component]
    
    def get_threats_by_stride(self, stride_category: str) -> List[MCPThreatKnowledge]:
        """Get threats for a specific STRIDE category"""
        return [t for t in self.threats.values() if t.stride_category == stride_category]
    
    def get_controls_by_category(self, category: str) -> List[MCPControlKnowledge]:
        """Get controls for a specific category"""
        return [c for c in self.controls.values() if c.category == category]
    
    def get_controls_for_threat(self, threat_id: str) -> List[MCPControlKnowledge]:
        """Get recommended controls for a threat"""
        threat = self.threats.get(threat_id)
        if not threat:
            return []
        
        # Find controls that match mitigation recommendations
        matching_controls = []
        for control in self.controls.values():
            for mitigation in threat.mitigation_controls:
                if any(measure.lower() in mitigation.lower() for measure in control.control_measures):
                    matching_controls.append(control)
                    break
        
        return matching_controls
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert knowledge base to dictionary"""
        return {
            'threats': {k: asdict(v) for k, v in self.threats.items()},
            'controls': {k: asdict(v) for k, v in self.controls.items()},
            'abuse_cases': {k: asdict(v) for k, v in self.abuse_cases.items()},
            'maestro_layers': self.maestro_layers
        }


# Global instance
_knowledge_base: Optional[MCPKnowledgeBase] = None


def get_knowledge_base() -> MCPKnowledgeBase:
    """Get or create knowledge base instance"""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = MCPKnowledgeBase()
    return _knowledge_base


def import_mcp_knowledge(force_reimport: bool = False) -> Dict[str, int]:
    """
    Import MCP knowledge from internal data and store to database.
    
    Args:
        force_reimport: If True, re-import even if already imported
        
    Returns:
        Dict with import counts
    """
    kb = get_knowledge_base()
    
    # Check if already imported
    if not force_reimport and kb.threats:
        return {
            'threats': len(kb.threats),
            'controls': len(kb.controls),
            'abuse_cases': len(kb.abuse_cases)
        }
    
    # Import from internal data
    import_counts = kb._load_initial_knowledge()
    
    # Store to database
    stored_counts = kb.store_to_database()
    
    return {
        'imported': import_counts,
        'stored': stored_counts
    }

