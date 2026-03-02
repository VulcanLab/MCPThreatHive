"""
Canvas Threat Analyzer - Auto Threat Generation from Architecture

This module implements the automatic threat analysis engine for Canvas components.

1. Pattern-based Threat Generation (MCPSecBench 4×17 matrix matching)
2. Behavior-based Threat Generation (capability → threat mapping)
3. Semantic Threat Generation (embedding-based pattern matching)
4. Auto Attack Path Reconstruction (attack chain generation)
5. Intelligence Binding (CVE, IOC, Jailbreak history matching)
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from pathlib import Path

from schemas.mcpsecbench_schema import (
    MCPSurface, MCPSecBenchAttackType,
    initialize_matrix, get_threat_cell, MCPSECBENCH_MATRIX
)


@dataclass
class CanvasComponent:
    """Represents a component on the Canvas"""
    id: str
    component_type: str  # MCP Server, Tool, LLM Provider, API Key Store, etc.
    name: str
    capabilities: List[str] = field(default_factory=list)  # e.g., ["write_file", "network_access"]
    metadata: Dict[str, Any] = field(default_factory=dict)
    connections: List[str] = field(default_factory=list)  # IDs of connected components


@dataclass
class ThreatPattern:
    """Represents a threat pattern that can be matched"""
    pattern_id: str
    name: str
    description: str
    surface: MCPSurface
    attack_type: MCPSecBenchAttackType
    severity: int
    component_types: List[str]  # Which component types trigger this
    capability_triggers: List[str]  # Which capabilities trigger this
    graph_pattern: Dict[str, Any] = field(default_factory=dict)
    test_template: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """Represents an attack path through multiple components"""
    path_id: str
    steps: List[Dict[str, Any]]  # Sequence of attack steps
    source_component: str
    target_component: str
    severity: int
    description: str
    mitigations: List[str] = field(default_factory=list)


class CanvasThreatAnalyzer:
    """
    Analyzes Canvas architecture and automatically generates threats.
    
    Features:
    - Pattern-based threat generation from MCPSecBench matrix
    - Behavior-based threat generation from component capabilities
    - Attack path reconstruction from component connections
    - Intelligence binding (CVE, IOC, etc.)
    """
    
    def __init__(self):
        """Initialize the analyzer"""
        # Load MCPSecBench matrix
        initialize_matrix()
        
        # Component type to threat pattern mapping
        self.component_threat_patterns = self._build_component_threat_mapping()
        
        # Capability to threat mapping
        self.capability_threat_mapping = self._build_capability_threat_mapping()
        
        # Attack path patterns
        self.attack_path_patterns = self._build_attack_path_patterns()
    
    def _build_component_threat_mapping(self) -> Dict[str, List[ThreatPattern]]:
        """Build mapping from component types to threat patterns"""
        patterns = {}
        
        # MCP Server patterns
        patterns['MCP Server'] = [
            ThreatPattern(
                pattern_id='server-metadata-poisoning',
                name='Server Metadata Poisoning',
                description='Server serves or consumes poisoned metadata',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.METADATA_POISONING,
                severity=8,
                component_types=['MCP Server'],
                capability_triggers=['metadata_handling', 'tool_registry']
            ),
            ThreatPattern(
                pattern_id='server-unauthorized-invocation',
                name='Unauthorized Tool Invocation',
                description='Server exposes function that lets agent run privileged actions',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.UNAUTHORIZED_TOOL_INVOCATION,
                severity=10,
                component_types=['MCP Server'],
                capability_triggers=['exec', 'file_write', 'network_access']
            ),
        ]
        
        # Tool patterns
        patterns['Tool'] = [
            ThreatPattern(
                pattern_id='tool-poisoning',
                name='Tool Poisoning',
                description='Tool metadata contains malicious instructions',
                surface=MCPSurface.TOOL_METADATA_TOOLCHAIN,
                attack_type=MCPSecBenchAttackType.TOOL_POISONING,
                severity=9,
                component_types=['Tool'],
                capability_triggers=['metadata']
            ),
            ThreatPattern(
                pattern_id='tool-chain-attack',
                name='Chain-of-Tools Attack',
                description='Multiple tools form gadget chain',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.CHAIN_OF_TOOLS_ATTACK,
                severity=10,
                component_types=['Tool'],
                capability_triggers=['multi_tool']
            ),
        ]
        
        # LLM Provider patterns
        patterns['LLM Provider'] = [
            ThreatPattern(
                pattern_id='llm-logic-flaws',
                name='Model-induced Logic Flaws',
                description='LLM reasoning leads to unsafe behavior',
                surface=MCPSurface.RUNTIME_INVOCATION_FLOW,
                attack_type=MCPSecBenchAttackType.MODEL_INDUCED_LOGIC_FLAWS,
                severity=9,
                component_types=['LLM Provider'],
                capability_triggers=['reasoning', 'planning']
            ),
            ThreatPattern(
                pattern_id='llm-preference-manipulation',
                name='Preference Manipulation',
                description='Descriptions bias model to choose certain tools',
                surface=MCPSurface.RUNTIME_INVOCATION_FLOW,
                attack_type=MCPSecBenchAttackType.PREFERENCE_MANIPULATION,
                severity=7,
                component_types=['LLM Provider'],
                capability_triggers=['tool_selection']
            ),
        ]
        
        # API Key Store patterns
        patterns['API Key Store'] = [
            ThreatPattern(
                pattern_id='key-store-exposure',
                name='Sensitive Data Exposure',
                description='API keys may be exposed via tool outputs',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.SENSITIVE_DATA_EXPOSURE,
                severity=9,
                component_types=['API Key Store'],
                capability_triggers=['key_access', 'credential_storage']
            ),
        ]
        
        return patterns
    
    def _build_capability_threat_mapping(self) -> Dict[str, List[ThreatPattern]]:
        """Build mapping from capabilities to threat patterns"""
        mapping = {}
        
        # File system capabilities
        mapping['write_file'] = [
            ThreatPattern(
                pattern_id='fs-write-unauthorized',
                name='Unauthorized File Write',
                description='Tool can write files without proper validation',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.UNAUTHORIZED_TOOL_INVOCATION,
                severity=10,
                component_types=['Tool'],
                capability_triggers=['write_file']
            ),
            ThreatPattern(
                pattern_id='fs-path-traversal',
                name='Directory Traversal',
                description='Path manipulation exposes files',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.DIRECTORY_TRAVERSAL,
                severity=9,
                component_types=['Tool'],
                capability_triggers=['write_file', 'read_file']
            ),
        ]
        
        # Network capabilities
        mapping['network_access'] = [
            ThreatPattern(
                pattern_id='network-ssrf',
                name='SSRF via Tool',
                description='Tool can make network requests to internal resources',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.UNSAFE_THIRD_PARTY_API,
                severity=8,
                component_types=['Tool'],
                capability_triggers=['network_access']
            ),
        ]
        
        # Execution capabilities
        mapping['exec'] = [
            ThreatPattern(
                pattern_id='exec-command-injection',
                name='Command Injection',
                description='Direct exec of user input or insufficient sanitization',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.UNVALIDATED_INPUT_SHELL_FS,
                severity=10,
                component_types=['Tool', 'MCP Server'],
                capability_triggers=['exec']
            ),
        ]
        
        # Database capabilities
        mapping['db_access'] = [
            ThreatPattern(
                pattern_id='db-data-exposure',
                name='Database Data Exposure',
                description='Database access may expose sensitive data',
                surface=MCPSurface.SERVER_APIS_FUNCTIONALITY,
                attack_type=MCPSecBenchAttackType.SENSITIVE_DATA_EXPOSURE,
                severity=9,
                component_types=['Tool'],
                capability_triggers=['db_access']
            ),
        ]
        
        return mapping
    
    def _build_attack_path_patterns(self) -> List[Dict[str, Any]]:
        """Build common attack path patterns"""
        return [
            {
                'pattern_id': 'prompt-injection-to-rce',
                'name': 'Prompt Injection → Tool Response → File Write → RCE',
                'description': 'Multi-step attack: prompt injection leads to tool response manipulation, then file write, then code execution',
                'steps': [
                    {'component_type': 'LLM Provider', 'attack': 'Prompt Injection'},
                    {'component_type': 'Tool', 'attack': 'Tool Response Manipulation'},
                    {'component_type': 'Tool', 'capability': 'write_file', 'attack': 'File Write'},
                    {'component_type': 'MCP Server', 'attack': 'Code Execution'}
                ],
                'severity': 10
            },
            {
                'pattern_id': 'browser-ssrf-chain',
                'name': 'Browser Tool → SSRF → Cloud Metadata → API Key Steal',
                'description': 'Browser tool used for SSRF to access cloud metadata and steal API keys',
                'steps': [
                    {'component_type': 'Tool', 'capability': 'browser_access'},
                    {'component_type': 'Tool', 'capability': 'network_access', 'attack': 'SSRF'},
                    {'component_type': 'API Key Store', 'attack': 'Key Exfiltration'}
                ],
                'severity': 9
            },
            {
                'pattern_id': 'tool-chain-exfiltration',
                'name': 'Tool Chain → Data Exfiltration',
                'description': 'Multiple tools chained together to exfiltrate sensitive data',
                'steps': [
                    {'component_type': 'Tool', 'capability': 'read_file'},
                    {'component_type': 'Tool', 'capability': 'network_access'},
                    {'component_type': 'Tool', 'attack': 'Data Exfiltration'}
                ],
                'severity': 9
            }
        ]
    
    def analyze_canvas(self, components: List[CanvasComponent]) -> Dict[str, Any]:
        """
        Analyze Canvas architecture and generate threats.
        
        Args:
            components: List of components on the Canvas
            
        Returns:
            Dictionary containing:
            - threats: List of generated threats
            - attack_paths: List of identified attack paths
            - risk_score: Overall risk score
            - recommendations: Security recommendations
        """
        threats = []
        attack_paths = []
        
        # 1. Pattern-based threat generation
        pattern_threats = self._generate_pattern_based_threats(components)
        threats.extend(pattern_threats)
        
        # 2. Behavior-based threat generation
        behavior_threats = self._generate_behavior_based_threats(components)
        threats.extend(behavior_threats)
        
        # 3. Attack path reconstruction
        attack_paths = self._reconstruct_attack_paths(components)
        
        # 4. Calculate overall risk score
        risk_score = self._calculate_risk_score(threats, attack_paths)
        
        # 5. Generate recommendations
        recommendations = self._generate_recommendations(components, threats, attack_paths)
        
        return {
            'threats': threats,
            'attack_paths': attack_paths,
            'risk_score': risk_score,
            'recommendations': recommendations,
            'component_count': len(components),
            'threat_count': len(threats),
            'attack_path_count': len(attack_paths)
        }
    
    def _generate_pattern_based_threats(self, components: List[CanvasComponent]) -> List[Dict[str, Any]]:
        """Generate threats based on component types and MCPSecBench patterns"""
        threats = []
        
        for component in components:
            # Check component type patterns
            if component.component_type in self.component_threat_patterns:
                patterns = self.component_threat_patterns[component.component_type]
                
                for pattern in patterns:
                    # Check if component has triggering capabilities
                    if any(cap in component.capabilities for cap in pattern.capability_triggers):
                        threat = self._create_threat_from_pattern(component, pattern)
                        threats.append(threat)
        
        return threats
    
    def _generate_behavior_based_threats(self, components: List[CanvasComponent]) -> List[Dict[str, Any]]:
        """Generate threats based on component capabilities"""
        threats = []
        
        for component in components:
            for capability in component.capabilities:
                if capability in self.capability_threat_mapping:
                    patterns = self.capability_threat_mapping[capability]
                    
                    for pattern in patterns:
                        threat = self._create_threat_from_pattern(component, pattern)
                        threat['capability'] = capability
                        threats.append(threat)
        
        return threats
    
    def _create_threat_from_pattern(self, component: CanvasComponent, pattern: ThreatPattern) -> Dict[str, Any]:
        """Create a threat dictionary from a pattern and component"""
        # Get MCPSecBench cell data
        cell = get_threat_cell(pattern.surface, pattern.attack_type)
        
        threat = {
            'id': f"canvas-{component.id}-{pattern.pattern_id}",
            'name': pattern.name,
            'description': pattern.description,
            'component_id': component.id,
            'component_name': component.name,
            'component_type': component.component_type,
            'surface': pattern.surface.value,
            'attack_type': pattern.attack_type.value,
            'severity': pattern.severity,
            'risk_score': pattern.severity * 1.0,
            'mcp_surface': pattern.surface.value,
            'mcpsecbench_attack_type': pattern.attack_type.value,
            'mcpsecbench_severity': pattern.severity,
            'graph_pattern': pattern.graph_pattern,
            'test_template': pattern.test_template,
            'source': 'canvas_auto_generated',
            'status': 'active'
        }
        
        # Add MCPSecBench cell details if available
        if cell:
            threat['graph_pattern'] = {
                'node_types': cell.graph_pattern.node_types,
                'edge_types': cell.graph_pattern.edge_types,
                'pattern_description': cell.graph_pattern.pattern_description,
                'example_pattern': cell.graph_pattern.example_pattern
            }
            threat['test_template'] = {
                'static_analysis': cell.test_template.static_analysis,
                'blackbox_test': cell.test_template.blackbox_test,
                'test_description': cell.test_template.test_description
            }
            threat['how_used_in_product'] = cell.how_used_in_product
        
        return threat
    
    def _reconstruct_attack_paths(self, components: List[CanvasComponent]) -> List[Dict[str, Any]]:
        """Reconstruct attack paths from component connections"""
        attack_paths = []
        component_map = {c.id: c for c in components}
        
        # Check each attack path pattern
        for path_pattern in self.attack_path_patterns:
            # Try to match pattern to actual components
            matched_path = self._match_attack_path_pattern(path_pattern, components, component_map)
            if matched_path:
                attack_paths.append(matched_path)
        
        # Also generate paths from component connections
        connection_paths = self._generate_paths_from_connections(components, component_map)
        attack_paths.extend(connection_paths)
        
        return attack_paths
    
    def _match_attack_path_pattern(self, pattern: Dict[str, Any], components: List[CanvasComponent], 
                                   component_map: Dict[str, CanvasComponent]) -> Optional[Dict[str, Any]]:
        """Try to match an attack path pattern to actual components"""
        matched_steps = []
        
        for step in pattern['steps']:
            # Find components matching this step
            matching_components = [
                c for c in components
                if c.component_type == step.get('component_type')
                and (not step.get('capability') or step.get('capability') in c.capabilities)
            ]
            
            if matching_components:
                matched_steps.append({
                    'component_id': matching_components[0].id,
                    'component_name': matching_components[0].name,
                    'component_type': matching_components[0].component_type,
                    'attack': step.get('attack', ''),
                    'capability': step.get('capability', '')
                })
        
        if len(matched_steps) >= 2:  # At least 2 steps for a valid path
            return {
                'path_id': f"path-{pattern['pattern_id']}",
                'name': pattern['name'],
                'description': pattern['description'],
                'steps': matched_steps,
                'severity': pattern['severity'],
                'risk_score': pattern['severity'] * 1.0
            }
        
        return None
    
    def _generate_paths_from_connections(self, components: List[CanvasComponent], 
                                        component_map: Dict[str, CanvasComponent]) -> List[Dict[str, Any]]:
        """Generate attack paths from component connections"""
        paths = []
        
        # Find chains of connected components with dangerous capabilities
        for component in components:
            if component.connections:
                # Check if this component and its connections form a dangerous chain
                dangerous_caps = ['write_file', 'exec', 'network_access', 'db_access']
                
                if any(cap in component.capabilities for cap in dangerous_caps):
                    for connected_id in component.connections:
                        if connected_id in component_map:
                            connected = component_map[connected_id]
                            if any(cap in connected.capabilities for cap in dangerous_caps):
                                # Found a potential attack path
                                path = {
                                    'path_id': f"path-{component.id}-{connected_id}",
                                    'name': f'Attack Path: {component.name} → {connected.name}',
                                    'description': f'Potential attack path through {component.component_type} and {connected.component_type}',
                                    'steps': [
                                        {
                                            'component_id': component.id,
                                            'component_name': component.name,
                                            'component_type': component.component_type,
                                            'capabilities': component.capabilities
                                        },
                                        {
                                            'component_id': connected.id,
                                            'component_name': connected.name,
                                            'component_type': connected.component_type,
                                            'capabilities': connected.capabilities
                                        }
                                    ],
                                    'severity': 8,  # Default high severity for multi-component paths
                                    'risk_score': 8.0
                                }
                                paths.append(path)
        
        return paths
    
    def _calculate_risk_score(self, threats: List[Dict[str, Any]], 
                             attack_paths: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score from threats and attack paths"""
        if not threats and not attack_paths:
            return 0.0
        
        # Weighted average of threat severities
        threat_scores = [t.get('severity', 5) for t in threats]
        path_scores = [p.get('severity', 5) for p in attack_paths]
        
        all_scores = threat_scores + path_scores
        
        if not all_scores:
            return 0.0
        
        # Calculate weighted average (higher severity threats weighted more)
        weighted_sum = sum(score ** 1.5 for score in all_scores)
        weighted_count = sum(score ** 0.5 for score in all_scores)
        
        return weighted_sum / weighted_count if weighted_count > 0 else 0.0
    
    def _generate_recommendations(self, components: List[CanvasComponent], 
                                 threats: List[Dict[str, Any]], 
                                 attack_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Check for high-severity threats
        high_severity_threats = [t for t in threats if t.get('severity', 0) >= 9]
        if high_severity_threats:
            recommendations.append({
                'type': 'critical',
                'title': 'High Severity Threats Detected',
                'description': f'Found {len(high_severity_threats)} critical threats. Immediate action required.',
                'actions': [
                    'Review and mitigate high-severity threats',
                    'Implement sandboxing for dangerous capabilities',
                    'Add input validation and output sanitization'
                ]
            })
        
        # Check for attack paths
        if attack_paths:
            recommendations.append({
                'type': 'warning',
                'title': 'Attack Paths Identified',
                'description': f'Found {len(attack_paths)} potential attack paths through component chains.',
                'actions': [
                    'Break attack chains by adding guardrails',
                    'Implement least-privilege access controls',
                    'Add monitoring for multi-step attacks'
                ]
            })
        
        # Check for dangerous capabilities
        dangerous_caps = ['exec', 'write_file', 'network_access']
        components_with_dangerous_caps = [
            c for c in components
            if any(cap in c.capabilities for cap in dangerous_caps)
        ]
        
        if components_with_dangerous_caps:
            recommendations.append({
                'type': 'info',
                'title': 'Components with Dangerous Capabilities',
                'description': f'{len(components_with_dangerous_caps)} components have dangerous capabilities.',
                'actions': [
                    'Sandbox components with exec/write_file capabilities',
                    'Implement rate limiting for network_access',
                    'Add audit logging for all dangerous operations'
                ]
            })
        
        return recommendations


def analyze_canvas_architecture(components: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convenience function to analyze Canvas architecture.
    
    Args:
        components: List of component dictionaries from Canvas
        
    Returns:
        Analysis results with threats, attack paths, and recommendations
    """
    analyzer = CanvasThreatAnalyzer()
    
    # Convert dictionaries to CanvasComponent objects
    canvas_components = [
        CanvasComponent(
            id=comp.get('id', ''),
            component_type=comp.get('type', comp.get('component_type', 'Unknown')),
            name=comp.get('name', 'Unnamed'),
            capabilities=comp.get('capabilities', []),
            metadata=comp.get('metadata', {}),
            connections=comp.get('connections', [])
        )
        for comp in components
    ]
    
    return analyzer.analyze_canvas(canvas_components)


