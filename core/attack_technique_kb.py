"""
Attack Technique Knowledge Base

Knowledge base specifically for attack techniques, extracting detailed attack technique information from intelligence.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

from database.db_manager import get_db_manager
from core.mcpsecbench import AttackSurface, AttackType


class AttackComplexity(Enum):
    """Attack complexity"""
    LOW = "Low"  # Simple, directly exploitable
    MEDIUM = "Medium"  # Requires some technical skill
    HIGH = "High"  # Requires advanced technical skill
    EXPERT = "Expert"  # Requires expert-level technical skill


class ExploitationCondition(Enum):
    """Exploitation conditions"""
    NONE = "None"  # No special conditions required
    AUTHENTICATION = "Authentication Required"  # Authentication required
    NETWORK_ACCESS = "Network Access Required"  # Network access required
    LOCAL_ACCESS = "Local Access Required"  # Local access required
    PRIVILEGED_ACCESS = "Privileged Access Required"  # Privileged access required
    USER_INTERACTION = "User Interaction Required"  # User interaction required


@dataclass
class AttackStep:
    """Attack step"""
    step_number: int
    description: str
    action: str  # Specific operation
    expected_result: str  # Expected result
    tools_needed: List[str] = field(default_factory=list)  # Required tools
    prerequisites: List[str] = field(default_factory=list)  # Prerequisites


@dataclass
class AttackExample:
    """Real attack case"""
    title: str
    description: str
    source: str  # Source (CVE, paper, GitHub issue, etc.)
    source_url: Optional[str] = None
    date: Optional[str] = None
    payload: Optional[str] = None  # Attack payload example
    impact: Optional[str] = None  # Actual impact
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionMethod:
    """Detection method"""
    method_type: str  # static, dynamic, behavioral, signature-based
    description: str
    indicators: List[str] = field(default_factory=list)  # Detection indicators
    tools: List[str] = field(default_factory=list)  # Detection tools
    false_positive_rate: Optional[float] = None  # False positive rate


@dataclass
class AttackTechnique:
    """
    Attack technique knowledge base entry
    
    This is the core data structure containing complete attack technique information.
    """
    id: str = field(default_factory=lambda: f"AT-{uuid.uuid4().hex[:8].upper()}")
    
    # Basic information
    name: str = ""  # Attack technique name
    description: str = ""  # Detailed description
    alias: List[str] = field(default_factory=list)  # Aliases
    
    # Classification
    attack_surface: Optional[AttackSurface] = None  # MCPSecBench attack surface
    attack_type: Optional[AttackType] = None  # MCPSecBench attack type
    stride_category: str = ""  # STRIDE classification
    
    # Attack steps (core content)
    attack_steps: List[AttackStep] = field(default_factory=list)  # Detailed attack steps
    
    # Attack vectors
    attack_vectors: List[str] = field(default_factory=list)  # Attack vector list
    
    # Exploitation conditions
    exploitation_conditions: List[ExploitationCondition] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)  # Prerequisites for exploitation
    
    # Real cases
    examples: List[AttackExample] = field(default_factory=list)  # Real attack cases
    
    # Detection methods
    detection_methods: List[DetectionMethod] = field(default_factory=list)
    
    # Mitigation measures
    mitigations: List[str] = field(default_factory=list)  # Mitigation measures
    controls: List[str] = field(default_factory=list)  # Related control measures
    
    # Risk assessment
    complexity: AttackComplexity = AttackComplexity.MEDIUM
    impact: str = ""  # Impact description
    likelihood: str = "Possible"  # Likelihood
    risk_score: float = 7.0  # Risk score 0-10
    
    # Related information
    related_vulnerabilities: List[str] = field(default_factory=list)  # Related vulnerability CVE IDs
    related_threats: List[str] = field(default_factory=list)  # Related threat IDs
    related_techniques: List[str] = field(default_factory=list)  # Related attack techniques
    
    # Source information
    sources: List[str] = field(default_factory=list)  # Source list
    source_urls: List[str] = field(default_factory=list)  # Source URLs
    discovered_date: Optional[str] = None  # Discovery date
    last_updated: Optional[str] = None  # Last update date
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        # Handle enum types
        if self.attack_surface:
            data['attack_surface'] = self.attack_surface.value
        if self.attack_type:
            data['attack_type'] = self.attack_type.value
        data['complexity'] = self.complexity.value
        data['exploitation_conditions'] = [ec.value for ec in self.exploitation_conditions]
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackTechnique':
        """Create from dictionary"""
        # Handle enum types
        if 'attack_surface' in data and data['attack_surface']:
            data['attack_surface'] = AttackSurface(data['attack_surface'])
        if 'attack_type' in data and data['attack_type']:
            data['attack_type'] = AttackType(data['attack_type'])
        if 'complexity' in data:
            data['complexity'] = AttackComplexity(data['complexity'])
        if 'exploitation_conditions' in data:
            data['exploitation_conditions'] = [
                ExploitationCondition(ec) for ec in data['exploitation_conditions']
            ]
        
        # Handle nested objects
        if 'attack_steps' in data:
            data['attack_steps'] = [AttackStep(**step) for step in data['attack_steps']]
        if 'examples' in data:
            data['examples'] = [AttackExample(**ex) for ex in data['examples']]
        if 'detection_methods' in data:
            data['detection_methods'] = [DetectionMethod(**dm) for dm in data['detection_methods']]
        
        return cls(**data)


class AttackTechniqueKB:
    """
    Attack technique knowledge base manager
    
    Extracts attack techniques from intelligence and provides query and analysis functions.
    """
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager or get_db_manager()
        self.techniques: Dict[str, AttackTechnique] = {}
    
    def extract_from_intel(
        self,
        intel_items: List[Dict[str, Any]],
        use_ai: bool = True
    ) -> List[AttackTechnique]:
        """
        Extract attack techniques from intelligence
        
        Args:
            intel_items: List of intelligence items
            use_ai: Whether to use AI extraction (if False, use rule-based extraction)
        
        Returns:
            List of extracted attack techniques
        """
        if use_ai:
            return self._extract_with_ai(intel_items)
        else:
            return self._extract_with_rules(intel_items)
    
    def _extract_with_ai(
        self,
        intel_items: List[Dict[str, Any]]
    ) -> List[AttackTechnique]:
        """Extract attack techniques from intelligence using AI"""
        from core.intel_threat_generator import IntelThreatGenerator
        from config.model_selector import get_model_selector
        
        # Get model selector
        selector = get_model_selector()
        model_selection = selector.get_selection() or selector.load_config()
        
        # Use IntelThreatGenerator to extract threats
        generator = IntelThreatGenerator(model_selection=model_selection)
        
        # Build prompt specifically for attack techniques
        techniques = []
        
        for item in intel_items:
            content = item.get('ai_summary') or item.get('content') or ''
            title = item.get('title', '')
            
            if not content:
                continue
            
            # Build prompt to extract attack techniques
            prompt = f"""Analyze the following MCP security intelligence and extract detailed attack techniques.

Title: {title}
Content: {content[:2000]}

For each attack technique identified, provide:
1. Technique name (specific attack method)
2. Detailed description
3. Step-by-step attack procedure:
   - Step 1: [action] → [expected result]
   - Step 2: [action] → [expected result]
   - ...
4. Attack vectors (how the attack is executed)
5. Exploitation conditions (what's needed to exploit)
6. Prerequisites (required conditions)
7. Real-world examples (if mentioned)
8. Detection methods (how to detect this attack)
9. Mitigation measures (how to prevent/defend)
10. MCPSecBench classification (Attack Surface and Attack Type)
11. STRIDE category
12. Complexity (Low/Medium/High/Expert)
13. Impact description
14. Risk score (0-10)

Return ONLY a JSON array with this structure:
[
    {{
        "name": "Attack Technique Name",
        "description": "Detailed description",
        "attack_steps": [
            {{
                "step_number": 1,
                "description": "Step description",
                "action": "Specific action taken",
                "expected_result": "What happens",
                "tools_needed": ["tool1", "tool2"],
                "prerequisites": ["condition1"]
            }}
        ],
        "attack_vectors": ["vector1", "vector2"],
        "exploitation_conditions": ["None", "Authentication Required"],
        "prerequisites": ["prerequisite1"],
        "examples": [
            {{
                "title": "Example Title",
                "description": "Example description",
                "source": "CVE-2024-XXXX",
                "source_url": "https://...",
                "payload": "example payload",
                "impact": "actual impact"
            }}
        ],
        "detection_methods": [
            {{
                "method_type": "behavioral",
                "description": "Detection description",
                "indicators": ["indicator1"],
                "tools": ["tool1"]
            }}
        ],
        "mitigations": ["mitigation1", "mitigation2"],
        "attack_surface": "MCP Server",
        "attack_type": "Prompt Injection",
        "stride_category": "Tampering",
        "complexity": "Medium",
        "impact": "Impact description",
        "risk_score": 7.5
    }}
]"""
            
            # Call LLM
            try:
                response = generator._call_llm(prompt)
                if response:
                    techniques.extend(self._parse_ai_response(response, item))
            except Exception as e:
                print(f"[AttackTechniqueKB] Failed to extract from {item.get('id')}: {e}")
        
        return techniques
    
    def _parse_ai_response(
        self,
        response: str,
        source_item: Dict[str, Any]
    ) -> List[AttackTechnique]:
        """Parse AI response"""
        techniques = []
        
        try:
            # Clean response
            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]
            response = response.strip()
            
            data = json.loads(response)
            
            for tech_data in data:
                technique = AttackTechnique(
                    name=tech_data.get('name', 'Unknown Attack'),
                    description=tech_data.get('description', ''),
                    attack_steps=[
                        AttackStep(**step) for step in tech_data.get('attack_steps', [])
                    ],
                    attack_vectors=tech_data.get('attack_vectors', []),
                    exploitation_conditions=[
                        ExploitationCondition(ec) for ec in tech_data.get('exploitation_conditions', [])
                    ],
                    prerequisites=tech_data.get('prerequisites', []),
                    examples=[
                        AttackExample(**ex) for ex in tech_data.get('examples', [])
                    ],
                    detection_methods=[
                        DetectionMethod(**dm) for dm in tech_data.get('detection_methods', [])
                    ],
                    mitigations=tech_data.get('mitigations', []),
                    attack_surface=AttackSurface(tech_data['attack_surface']) if tech_data.get('attack_surface') else None,
                    attack_type=AttackType(tech_data['attack_type']) if tech_data.get('attack_type') else None,
                    stride_category=tech_data.get('stride_category', 'Tampering'),
                    complexity=AttackComplexity(tech_data.get('complexity', 'Medium')),
                    impact=tech_data.get('impact', ''),
                    risk_score=float(tech_data.get('risk_score', 7.0)),
                    sources=[source_item.get('title', 'Unknown')],
                    source_urls=[source_item.get('url', '')] if source_item.get('url') else [],
                    discovered_date=source_item.get('created_at', datetime.now().isoformat())
                )
                techniques.append(technique)
        except Exception as e:
            print(f"[AttackTechniqueKB] Failed to parse AI response: {e}")
        
        return techniques
    
    def _extract_with_rules(
        self,
        intel_items: List[Dict[str, Any]]
    ) -> List[AttackTechnique]:
        """Extract attack techniques from intelligence using rules"""
        techniques = []
        
        # Define attack technique keyword patterns
        attack_patterns = {
            'Prompt Injection': {
                'keywords': ['prompt injection', 'inject prompt', 'instruction injection'],
                'attack_surface': AttackSurface.USER_INTERACTION,
                'attack_type': AttackType.PROMPT_INJECTION
            },
            'Tool Poisoning': {
                'keywords': ['tool poisoning', 'tool manipulation', 'malicious tool'],
                'attack_surface': AttackSurface.MCP_CLIENT,
                'attack_type': AttackType.TOOL_POISONING
            },
            'Data Exfiltration': {
                'keywords': ['data exfiltration', 'data leak', 'unauthorized access'],
                'attack_surface': AttackSurface.MCP_SERVER,
                'attack_type': AttackType.DATA_EXFILTRATION
            }
        }
        
        for item in intel_items:
            content = (item.get('ai_summary') or item.get('content') or '').lower()
            title = (item.get('title') or '').lower()
            
            for technique_name, pattern in attack_patterns.items():
                if any(kw in content or kw in title for kw in pattern['keywords']):
                    technique = AttackTechnique(
                        name=technique_name,
                        description=item.get('ai_summary') or item.get('content', '')[:500],
                        attack_surface=pattern['attack_surface'],
                        attack_type=pattern['attack_type'],
                        sources=[item.get('title', 'Unknown')],
                        source_urls=[item.get('url', '')] if item.get('url') else [],
                        discovered_date=item.get('created_at', datetime.now().isoformat())
                    )
                    techniques.append(technique)
        
        return techniques
    
    def store_to_database(
        self,
        techniques: List[AttackTechnique],
        project_id: str = 'default-project'
    ) -> Dict[str, int]:
        """
        Store attack techniques to database
        
        Returns:
            Storage statistics
        """
        stored = {'techniques': 0, 'threats': 0}
        
        for technique in techniques:
            # Store as Threat (attack techniques are essentially threats)
            threat_data = {
                'name': technique.name,
                'description': technique.description,
                'stride_category': technique.stride_category,
                'threat_type': 'attack_technique',
                'attack_vector': '\n'.join(technique.attack_vectors) if technique.attack_vectors else '',
                'impact': technique.impact,
                'risk_score': technique.risk_score,
                'risk_level': 'high' if technique.risk_score >= 8.0 else 'medium',
                'source': 'Attack Technique KB',
                'tags': technique.tags + [technique.complexity.value],
                'schema_data': {
                    'attack_technique_id': technique.id,
                    'attack_steps': [asdict(step) for step in technique.attack_steps],
                    'attack_vectors': technique.attack_vectors,
                    'exploitation_conditions': [ec.value for ec in technique.exploitation_conditions],
                    'prerequisites': technique.prerequisites,
                    'examples': [asdict(ex) for ex in technique.examples],
                    'detection_methods': [asdict(dm) for dm in technique.detection_methods],
                    'mitigations': technique.mitigations,
                    'complexity': technique.complexity.value,
                    'attack_surface': technique.attack_surface.value if technique.attack_surface else None,
                    'attack_type': technique.attack_type.value if technique.attack_type else None,
                    'related_vulnerabilities': technique.related_vulnerabilities,
                    'sources': technique.sources,
                    'source_urls': technique.source_urls,
                    'is_attack_technique': True
                }
            }
            
            try:
                self.db_manager.create_threat(threat_data, project_id)
                stored['techniques'] += 1
                stored['threats'] += 1
            except Exception as e:
                print(f"[AttackTechniqueKB] Failed to store technique {technique.id}: {e}")
        
        return stored
    
    def get_technique_by_id(self, technique_id: str) -> Optional[AttackTechnique]:
        """Get attack technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_attack_type(
        self,
        attack_type: AttackType
    ) -> List[AttackTechnique]:
        """Get attack techniques by attack type"""
        return [
            t for t in self.techniques.values()
            if t.attack_type == attack_type
        ]
    
    def get_techniques_by_surface(
        self,
        attack_surface: AttackSurface
    ) -> List[AttackTechnique]:
        """Get attack techniques by attack surface"""
        return [
            t for t in self.techniques.values()
            if t.attack_surface == attack_surface
        ]
    
    def search_techniques(
        self,
        query: str,
        limit: int = 20
    ) -> List[AttackTechnique]:
        """Search attack techniques"""
        query_lower = query.lower()
        results = []
        
        for technique in self.techniques.values():
            score = 0
            if query_lower in technique.name.lower():
                score += 10
            if query_lower in technique.description.lower():
                score += 5
            if any(query_lower in tag.lower() for tag in technique.tags):
                score += 3
            if any(query_lower in vector.lower() for vector in technique.attack_vectors):
                score += 2
            
            if score > 0:
                results.append((score, technique))
        
        # Sort by score
        results.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in results[:limit]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'techniques': {k: t.to_dict() for k, t in self.techniques.items()}
        }


# Global instance
_attack_technique_kb: Optional[AttackTechniqueKB] = None


def get_attack_technique_kb() -> AttackTechniqueKB:
    """Get attack technique knowledge base instance"""
    global _attack_technique_kb
    if _attack_technique_kb is None:
        _attack_technique_kb = AttackTechniqueKB()
    return _attack_technique_kb

