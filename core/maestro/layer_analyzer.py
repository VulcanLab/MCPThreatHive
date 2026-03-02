"""
Analyzes threats for specific layers.
"""

from typing import Dict, List, Any, Optional
from .layers import MaestroLayer, MAESTRO_LAYERS, get_layer_by_number
from .threat_mapper import MaestroThreatMapper


class MaestroLayerAnalyzer:
    """Analyzes threats for  layers"""
    
    def __init__(self):
        self.mapper = MaestroThreatMapper()
    
    def analyze_layer(self, layer_number: int, threats: List[Dict]) -> Dict[str, Any]:
        """Analyze threats for a specific MAESTRO layer"""
        layer = get_layer_by_number(layer_number)
        if not layer:
            return {
                'error': f'Invalid layer number: {layer_number}',
                'layer_number': layer_number
            }
        
        # Get threats for this layer
        layer_threats = self.mapper.get_layer_threats(layer_number, threats)
        
        # Calculate statistics
        total_threats = len(layer_threats)
        by_category = {}
        by_risk_level = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}
        mitigated_count = 0
        
        for threat in layer_threats:
            # Count by STRIDE category
            stride = threat.get('stride_category', 'unknown')
            by_category[stride] = by_category.get(stride, 0) + 1
            
            # Count by risk level
            risk_level = threat.get('risk_level', 'none').lower()
            if risk_level in by_risk_level:
                by_risk_level[risk_level] += 1
            
            # Count mitigated
            if threat.get('is_mitigated', False):
                mitigated_count += 1
        
        return {
            'layer': layer.to_dict(),
            'threats': layer_threats,
            'statistics': {
                'total_threats': total_threats,
                'mitigated': mitigated_count,
                'unmitigated': total_threats - mitigated_count,
                'by_category': by_category,
                'by_risk_level': by_risk_level,
                'coverage': (mitigated_count / total_threats * 100) if total_threats > 0 else 0
            }
        }
    
    def analyze_all_layers(self, threats: List[Dict]) -> Dict[str, Any]:
        """Analyze threats across all MAESTRO layers"""
        results = {}
        for layer_number in range(1, 8):
            results[f'layer_{layer_number}'] = self.analyze_layer(layer_number, threats)
        
        # Overall statistics
        total_threats = len(threats)
        total_mitigated = sum(1 for t in threats if t.get('is_mitigated', False))
        
        return {
            'layers': results,
            'overall': {
                'total_threats': total_threats,
                'total_mitigated': total_mitigated,
                'total_unmitigated': total_threats - total_mitigated,
                'coverage': (total_mitigated / total_threats * 100) if total_threats > 0 else 0
            }
        }
    
    def get_layer_threat_summary(self, layer_number: int, threats: List[Dict]) -> Dict[str, Any]:
        """Get a summary of threats for a layer"""
        analysis = self.analyze_layer(layer_number, threats)
        layer = get_layer_by_number(layer_number)
        
        return {
            'layer_name': layer.name if layer else f'Layer {layer_number}',
            'layer_number': layer_number,
            'threat_count': analysis['statistics']['total_threats'],
            'top_threats': sorted(
                analysis['threats'],
                key=lambda x: x.get('risk_score', 0),
                reverse=True
            )[:5],
            'risk_distribution': analysis['statistics']['by_risk_level'],
            'coverage': analysis['statistics']['coverage']
        }

