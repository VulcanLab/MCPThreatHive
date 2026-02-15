"""
Analyzes Agentic AI architecture patterns and their associated threats.
"""

from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass


class ArchitecturePattern(str, Enum):
    """Agentic AI architecture patterns"""
    SINGLE_AGENT = "single_agent"
    MULTI_AGENT = "multi_agent"
    UNCONSTRAINED_CONVERSATIONAL = "unconstrained_conversational"
    TASK_ORIENTED = "task_oriented"
    HIERARCHICAL = "hierarchical"
    DISTRIBUTED_ECOSYSTEM = "distributed_ecosystem"
    HUMAN_IN_THE_LOOP = "human_in_the_loop"
    SELF_LEARNING = "self_learning"


@dataclass
class PatternThreat:
    """Threat associated with an architecture pattern"""
    pattern: ArchitecturePattern
    threat_name: str
    description: str
    affected_layers: List[int]  # MAESTRO layers
    stride_category: str
    mitigation: List[str]


# Architecture pattern threat mappings
PATTERN_THREATS: Dict[ArchitecturePattern, List[PatternThreat]] = {
    ArchitecturePattern.SINGLE_AGENT: [
        PatternThreat(
            pattern=ArchitecturePattern.SINGLE_AGENT,
            threat_name="Goal Manipulation",
            description="The AI agent has been designed to maximize some value, but the attacker can change this goal to minimize this value.",
            affected_layers=[1, 3, 7],
            stride_category="elevation_of_privilege",
            mitigation=["Input validation", "Limit access to agent's internal parameters"]
        )
    ],
    ArchitecturePattern.MULTI_AGENT: [
        PatternThreat(
            pattern=ArchitecturePattern.MULTI_AGENT,
            threat_name="Communication Channel Attack",
            description="An attacker intercepts messages between AI agents.",
            affected_layers=[3, 7],
            stride_category="tampering",
            mitigation=["Secure communication protocols", "Mutual authentication", "Input validation"]
        ),
        PatternThreat(
            pattern=ArchitecturePattern.MULTI_AGENT,
            threat_name="Identity Attack",
            description="An attacker masquerades as a legitimate AI agent or creates fake identities.",
            affected_layers=[7],
            stride_category="spoofing",
            mitigation=["Secure communication protocols", "Mutual authentication", "Input validation"]
        )
    ],
    ArchitecturePattern.UNCONSTRAINED_CONVERSATIONAL: [
        PatternThreat(
            pattern=ArchitecturePattern.UNCONSTRAINED_CONVERSATIONAL,
            threat_name="Prompt Injection/Jailbreaking",
            description="An attacker crafts malicious prompts to bypass safety filters and elicit harmful outputs.",
            affected_layers=[1, 3],
            stride_category="elevation_of_privilege",
            mitigation=["Robust input validation", "Safety filters designed for conversational AI"]
        )
    ],
    ArchitecturePattern.TASK_ORIENTED: [
        PatternThreat(
            pattern=ArchitecturePattern.TASK_ORIENTED,
            threat_name="Denial-of-Service (DoS) through Overload",
            description="An attacker floods the AI agent with requests, making it unavailable to legitimate users.",
            affected_layers=[4, 3],
            stride_category="denial_of_service",
            mitigation=["Rate limiting", "Load balancing designed for API interactions"]
        )
    ],
    ArchitecturePattern.HIERARCHICAL: [
        PatternThreat(
            pattern=ArchitecturePattern.HIERARCHICAL,
            threat_name="Compromise of Higher-Level Agent to Control Subordinates",
            description="An attacker gains control of a higher level AI agent and can manipulate other subordinate AI agents.",
            affected_layers=[3, 7],
            stride_category="elevation_of_privilege",
            mitigation=["Secure communication between AI agents", "Strong access controls", "Regular monitoring"]
        )
    ],
    ArchitecturePattern.DISTRIBUTED_ECOSYSTEM: [
        PatternThreat(
            pattern=ArchitecturePattern.DISTRIBUTED_ECOSYSTEM,
            threat_name="Sybil Attack through Agent Impersonation",
            description="An attacker creates fake AI agent identities to gain disproportionate influence within the ecosystem.",
            affected_layers=[7],
            stride_category="spoofing",
            mitigation=["Robust identity management", "Reputation based systems"]
        )
    ],
    ArchitecturePattern.HUMAN_IN_THE_LOOP: [
        PatternThreat(
            pattern=ArchitecturePattern.HUMAN_IN_THE_LOOP,
            threat_name="Manipulation of Human Input/Feedback to Skew Agent Behavior",
            description="An attacker manipulates human input to cause the AI agent to learn unwanted behaviors or bias.",
            affected_layers=[1, 2, 7],
            stride_category="tampering",
            mitigation=["Input validation", "Strong audit trails for all user interactions"]
        )
    ],
    ArchitecturePattern.SELF_LEARNING: [
        PatternThreat(
            pattern=ArchitecturePattern.SELF_LEARNING,
            threat_name="Data Poisoning through Backdoor Trigger Injection",
            description="An attacker injects malicious data into the AI agent's training set that contains a hidden trigger.",
            affected_layers=[1, 2],
            stride_category="tampering",
            mitigation=["Data sanitization", "Strong validation of training data"]
        )
    ]
}


class ArchitecturePatternAnalyzer:
    """Analyzes architecture patterns and identifies associated threats"""
    
    def __init__(self):
        self.pattern_threats = PATTERN_THREATS
    
    def detect_pattern(self, architecture_description: str) -> List[ArchitecturePattern]:
        """Detect architecture patterns from description"""
        description_lower = architecture_description.lower()
        detected = []
        
        # Simple keyword-based detection (can be enhanced with ML)
        if any(keyword in description_lower for keyword in ['single agent', 'one agent', 'standalone']):
            detected.append(ArchitecturePattern.SINGLE_AGENT)
        
        if any(keyword in description_lower for keyword in ['multiple agents', 'multi-agent', 'agent collaboration']):
            detected.append(ArchitecturePattern.MULTI_AGENT)
        
        if any(keyword in description_lower for keyword in ['conversational', 'chat', 'dialogue', 'unconstrained']):
            detected.append(ArchitecturePattern.UNCONSTRAINED_CONVERSATIONAL)
        
        if any(keyword in description_lower for keyword in ['task', 'api', 'orchestration', 'workflow']):
            detected.append(ArchitecturePattern.TASK_ORIENTED)
        
        if any(keyword in description_lower for keyword in ['hierarchical', 'hierarchy', 'manager', 'coordinator']):
            detected.append(ArchitecturePattern.HIERARCHICAL)
        
        if any(keyword in description_lower for keyword in ['ecosystem', 'marketplace', 'distributed', 'decentralized']):
            detected.append(ArchitecturePattern.DISTRIBUTED_ECOSYSTEM)
        
        if any(keyword in description_lower for keyword in ['human', 'user feedback', 'human-in-the-loop']):
            detected.append(ArchitecturePattern.HUMAN_IN_THE_LOOP)
        
        if any(keyword in description_lower for keyword in ['learning', 'adaptive', 'self-improving', 'training']):
            detected.append(ArchitecturePattern.SELF_LEARNING)
        
        return detected if detected else [ArchitecturePattern.SINGLE_AGENT]  # Default
    
    def get_pattern_threats(self, pattern: ArchitecturePattern) -> List[PatternThreat]:
        """Get threats associated with an architecture pattern"""
        return self.pattern_threats.get(pattern, [])
    
    def analyze_architecture(self, architecture_description: str) -> Dict[str, Any]:
        """Analyze architecture and identify threats"""
        patterns = self.detect_pattern(architecture_description)
        
        all_threats = []
        for pattern in patterns:
            threats = self.get_pattern_threats(pattern)
            all_threats.extend(threats)
        
        return {
            'detected_patterns': [p.value for p in patterns],
            'threats': [
                {
                    'pattern': t.pattern.value,
                    'threat_name': t.threat_name,
                    'description': t.description,
                    'affected_layers': t.affected_layers,
                    'stride_category': t.stride_category,
                    'mitigation': t.mitigation
                }
                for t in all_threats
            ],
            'total_threats': len(all_threats)
        }

