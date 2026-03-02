"""
MAESTRO Threat Mapper

Maps threats between STRIDE categories and MAESTRO layers.
"""

from typing import Dict, List, Optional, Tuple
from enum import Enum

from core.stride_analyzer import StrideCategory
from .layers import MaestroLayer, MAESTRO_LAYERS


class ThreatMapping:
    """Represents a mapping between STRIDE and MAESTRO"""
    
    def __init__(self):
        # STRIDE -> Primary MAESTRO Layer mapping
        # Handle both enum values and string variations
        self.stride_to_maestro: Dict[str, Tuple[int, List[int]]] = {
            # Enum values
            StrideCategory.SPOOFING.value: (7, [3, 6]),  # Primary: L7, Secondary: L3, L6
            StrideCategory.TAMPERING.value: (2, [3, 4]),  # Primary: L2, Secondary: L3, L4
            StrideCategory.REPUDIATION.value: (5, [7]),   # Primary: L5, Secondary: L7
            StrideCategory.INFO_DISCLOSURE.value: (2, [5, 7]),  # Primary: L2, Secondary: L5, L7
            StrideCategory.DENIAL_OF_SERVICE.value: (4, [1, 3]),  # Primary: L4, Secondary: L1, L3
            StrideCategory.ELEVATION_OF_PRIVILEGE.value: (3, [4, 7]),  # Primary: L3, Secondary: L4, L7
            # String variations (for compatibility)
            "Spoofing": (7, [3, 6]),
            "Tampering": (2, [3, 4]),
            "Repudiation": (5, [7]),
            "Information Disclosure": (2, [5, 7]),
            "Denial of Service": (4, [1, 3]),
            "Elevation of Privilege": (3, [4, 7]),
        }
        
        # MCP-specific threat mappings
        self.mcp_threat_mappings: Dict[str, Tuple[int, str]] = {
            "MCP Server Impersonation": (7, "spoofing"),
            "Tool Response Injection": (3, "tampering"),
            "Context Flooding": (1, "denial_of_service"),
            "Prompt Injection": (1, "elevation_of_privilege"),
            "API Key Leakage": (2, "info_disclosure"),
            "Insecure Communication": (3, "tampering"),
            "Denial of Service (DoS)": (4, "denial_of_service"),
            "Data Leakage & Compliance Violations": (2, "info_disclosure"),
            "Impersonation": (7, "spoofing"),
            "Client Interference": (3, "denial_of_service"),
        }
    
    def get_maestro_layers_for_stride(self, stride_category: str) -> Tuple[int, List[int]]:
        """Get primary and secondary MAESTRO layers for a STRIDE category"""
        return self.stride_to_maestro.get(stride_category, (3, []))  # Default to L3
    
    def get_stride_for_maestro_layer(self, layer_number: int) -> List[str]:
        """Get STRIDE categories that map to a MAESTRO layer"""
        result = []
        for stride, (primary, secondary) in self.stride_to_maestro.items():
            if primary == layer_number or layer_number in secondary:
                result.append(stride)
        return result
    
    def get_maestro_layer_for_mcp_threat(self, threat_name: str) -> Optional[Tuple[int, str]]:
        """Get MAESTRO layer and STRIDE category for an MCP-specific threat"""
        # Direct mapping
        if threat_name in self.mcp_threat_mappings:
            return self.mcp_threat_mappings[threat_name]
        
        # Fuzzy matching
        threat_lower = threat_name.lower()
        for mcp_threat, (layer, stride) in self.mcp_threat_mappings.items():
            if mcp_threat.lower() in threat_lower or threat_lower in mcp_threat.lower():
                return (layer, stride)
        
        return None
    
    def map_threat_to_layers(self, threat_name: str, stride_category: str) -> Dict[str, any]:
        """Map a threat to MAESTRO layers"""
        # Try MCP-specific mapping first
        mcp_mapping = self.get_maestro_layer_for_mcp_threat(threat_name)
        if mcp_mapping:
            primary_layer, mapped_stride = mcp_mapping
            return {
                'primary_layer': primary_layer,
                'secondary_layers': [],
                'stride_category': mapped_stride,
                'mapping_method': 'mcp_specific'
            }
        
        # Fall back to STRIDE mapping
        primary_layer, secondary_layers = self.get_maestro_layers_for_stride(stride_category)
        return {
            'primary_layer': primary_layer,
            'secondary_layers': secondary_layers,
            'stride_category': stride_category,
            'mapping_method': 'stride_based'
        }


class MaestroThreatMapper:
    """Main class for mapping threats to MAESTRO layers"""
    
    def __init__(self):
        self.mapping = ThreatMapping()
    
    def map_threat(self, threat_name: str, stride_category: str) -> Dict[str, any]:
        """Map a threat to MAESTRO layers"""
        return self.mapping.map_threat_to_layers(threat_name, stride_category)
    
    def get_layer_threats(self, layer_number: int, threats: List[Dict]) -> List[Dict]:
        """Filter threats for a specific MAESTRO layer"""
        result = []
        for threat in threats:
            threat_name = threat.get('name', '')
            stride_category = threat.get('stride_category', '')
            
            mapping = self.map_threat(threat_name, stride_category)
            if mapping['primary_layer'] == layer_number or layer_number in mapping.get('secondary_layers', []):
                threat_copy = threat.copy()
                threat_copy['maestro_layer'] = layer_number
                threat_copy['maestro_mapping'] = mapping
                result.append(threat_copy)
        
        return result
    
    def identify_cross_layer_threats(self, threats: List[Dict]) -> List[Dict]:
        """Identify threats that span multiple layers"""
        cross_layer = []
        for threat in threats:
            threat_name = threat.get('name', '')
            stride_category = threat.get('stride_category', '')
            
            mapping = self.map_threat(threat_name, stride_category)
            affected_layers = [mapping['primary_layer']] + mapping.get('secondary_layers', [])
            
            if len(affected_layers) > 1:
                threat_copy = threat.copy()
                threat_copy['maestro_layers'] = affected_layers
                threat_copy['is_cross_layer'] = True
                cross_layer.append(threat_copy)
        
        return cross_layer

