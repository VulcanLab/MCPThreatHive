"""
Analyzes threats that span multiple layers.
"""

from typing import Dict, List, Any, Optional, Tuple
from .threat_mapper import MaestroThreatMapper
from .layers import get_layer_by_number


class CrossLayerThreat:
    """Represents a cross-layer threat"""
    
    def __init__(self, threat: Dict, affected_layers: List[int], attack_path: str = ""):
        self.threat = threat
        self.affected_layers = affected_layers
        self.attack_path = attack_path
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'threat': self.threat,
            'affected_layers': self.affected_layers,
            'layer_names': [get_layer_by_number(l).name if get_layer_by_number(l) else f'Layer {l}' 
                           for l in self.affected_layers],
            'attack_path': self.attack_path,
            'is_cross_layer': True
        }


class CrossLayerAnalyzer:
    """Analyzes cross-layer threats"""
    
    # Common cross-layer attack patterns
    CROSS_LAYER_PATTERNS = {
        'supply_chain': {
            'description': 'Supply Chain Attacks - Compromising a component in one layer to affect other layers',
            'example': 'Layer 3 (Framework) -> Layer 7 (Ecosystem)',
            'common_paths': [(3, 7), (2, 3), (4, 2)]
        },
        'lateral_movement': {
            'description': 'Lateral Movement - Gaining access to one layer and using it to compromise others',
            'example': 'Layer 4 (Infrastructure) -> Layer 2 (Data Operations)',
            'common_paths': [(4, 2), (4, 3), (3, 2)]
        },
        'privilege_escalation': {
            'description': 'Privilege Escalation - Gaining unauthorized privileges in one layer to access others',
            'example': 'Layer 3 (Frameworks) -> Layer 4 (Infrastructure)',
            'common_paths': [(3, 4), (7, 4), (2, 4)]
        },
        'data_leakage': {
            'description': 'Data Leakage - Sensitive data from one layer exposed through another',
            'example': 'Layer 2 (Data) -> Layer 5 (Observability)',
            'common_paths': [(2, 5), (2, 7), (1, 5)]
        },
        'goal_misalignment': {
            'description': 'Goal Misalignment Cascades - Goal misalignment propagating through layers',
            'example': 'Layer 2 (Data Poisoning) -> Layer 7 (Ecosystem)',
            'common_paths': [(2, 7), (1, 7), (3, 7)]
        }
    }
    
    def __init__(self):
        self.mapper = MaestroThreatMapper()
    
    def identify_cross_layer_threats(self, threats: List[Dict]) -> List[CrossLayerThreat]:
        """Identify threats that span multiple layers"""
        cross_layer_threats = []
        
        for threat in threats:
            threat_name = threat.get('name', '')
            stride_category = threat.get('stride_category', '')
            
            mapping = self.mapper.map_threat(threat_name, stride_category)
            affected_layers = [mapping['primary_layer']] + mapping.get('secondary_layers', [])
            
            if len(affected_layers) > 1:
                # Determine attack path
                attack_path = self._determine_attack_path(affected_layers, threat_name)
                
                cross_threat = CrossLayerThreat(
                    threat=threat,
                    affected_layers=affected_layers,
                    attack_path=attack_path
                )
                cross_layer_threats.append(cross_threat)
        
        return cross_layer_threats
    
    def _determine_attack_path(self, layers: List[int], threat_name: str) -> str:
        """Determine the attack path for a cross-layer threat"""
        threat_lower = threat_name.lower()
        
        # Check against known patterns
        for pattern_name, pattern_info in self.CROSS_LAYER_PATTERNS.items():
            for path in pattern_info['common_paths']:
                if set(path).issubset(set(layers)):
                    return f"{pattern_info['description']}: {pattern_info['example']}"
        
        # Default: describe the layers involved
        layer_names = [get_layer_by_number(l).name if get_layer_by_number(l) else f'Layer {l}' 
                      for l in sorted(layers)]
        return f"Threat spans: {' -> '.join(layer_names)}"
    
    def analyze_cross_layer_relationships(self, threats: List[Dict]) -> Dict[str, Any]:
        """Analyze relationships between layers based on cross-layer threats"""
        cross_layer_threats = self.identify_cross_layer_threats(threats)
        
        # Build layer relationship graph
        relationships = {}
        for cross_threat in cross_layer_threats:
            layers = sorted(cross_threat.affected_layers)
            for i in range(len(layers)):
                for j in range(i + 1, len(layers)):
                    layer_pair = (layers[i], layers[j])
                    if layer_pair not in relationships:
                        relationships[layer_pair] = []
                    relationships[layer_pair].append(cross_threat.threat.get('name', 'Unknown'))
        
        # Count threats per relationship
        relationship_stats = {
            f"L{src}->L{dst}": {
                'source_layer': src,
                'target_layer': dst,
                'threat_count': len(threats),
                'threats': threats
            }
            for (src, dst), threats in relationships.items()
        }
        
        return {
            'cross_layer_threats': [ct.to_dict() for ct in cross_layer_threats],
            'total_cross_layer_threats': len(cross_layer_threats),
            'layer_relationships': relationship_stats,
            'patterns': self.CROSS_LAYER_PATTERNS
        }
    
    def get_attack_paths(self, source_layer: int, target_layer: int, threats: List[Dict]) -> List[Dict]:
        """Get potential attack paths from source layer to target layer"""
        cross_layer_threats = self.identify_cross_layer_threats(threats)
        
        paths = []
        for cross_threat in cross_layer_threats:
            if source_layer in cross_threat.affected_layers and target_layer in cross_threat.affected_layers:
                paths.append({
                    'threat': cross_threat.threat,
                    'path': cross_threat.attack_path,
                    'layers': cross_threat.affected_layers
                })
        
        return paths

