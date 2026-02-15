"""
Standard MCP Threat Matrix Schema

Based on the comprehensive 4 surfaces × 17 attack types matrix design.
Includes graph patterns, test templates, and severity weighting.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


class MCPSurface(Enum):
    """MCP Attack Surfaces (4 surfaces)"""
    SERVER_APIS_FUNCTIONALITY = "Server APIs & Functionality"
    TOOL_METADATA_TOOLCHAIN = "Tool Metadata & Toolchain"
    RUNTIME_INVOCATION_FLOW = "Runtime / Invocation Flow"
    CLIENT_INTEGRATION = "Client / Integration Surface"


class MCPSecBenchAttackType(Enum):
    """Standard MCP 17 Attack Types (from MCPSecBench Paper)"""
    # User Interaction Surface
    PROMPT_INJECTION = "Prompt Injection"
    TOOL_MISUSE = "Tool/Service Misuse"
    
    # Client Surface
    SCHEMA_INCONSISTENCIES = "Schema Inconsistencies"
    SLASH_COMMAND_OVERLAP = "Slash Command Overlap"
    VULNERABLE_CLIENT = "Vulnerable Client Exploitation"
    
    # Protocol Surface
    MCP_REBINDING = "MCP Rebinding"
    MITM = "Man-in-the-Middle (MitM)"
    
    # Server Surface
    TOOL_SHADOWING = "Tool Shadowing"
    DATA_EXFILTRATION = "Data Exfiltration via Metadata"
    PACKAGE_NAME_SQUATTING_TOOL = "Package Name Squatting (Tool Level)"
    INDIRECT_PROMPT_INJECTION = "Indirect Prompt Injection"
    PACKAGE_NAME_SQUATTING_SERVER = "Package Name Squatting (Server Level)"
    CONFIGURATION_DRIFT = "Configuration Drift"
    SANDBOX_ESCAPE = "Sandbox Escape"
    TOOL_POISONING = "Tool Poisoning"
    VULNERABLE_SERVER = "Vulnerable Server Exploitation"
    RUG_PULL = "Rug Pull Attack"


@dataclass
class GraphPattern:
    """Graph pattern template for knowledge graph construction"""
    node_types: List[str] = field(default_factory=list)
    edge_types: List[str] = field(default_factory=list)
    pattern_description: str = ""
    example_pattern: str = ""  # e.g., "Tool -> provides_capability -> NetworkAccess"


@dataclass
class TestTemplate:
    """Test template for vulnerability detection"""
    static_analysis: str = ""  # SAST/CodeQL rules or manifest checks
    blackbox_test: str = ""  # Blackbox test cases or payload simulation
    test_description: str = ""


@dataclass
class MCPSecBenchThreatCell:
    """Represents a single cell in the 4×17 threat matrix"""
    surface: MCPSurface
    attack_type: MCPSecBenchAttackType
    short_description: str
    graph_pattern: GraphPattern
    test_template: TestTemplate
    severity: int  # 0-10 scale
    how_used_in_product: str = "TBD"


# Pre-defined threat matrix data
MCPSECBENCH_MATRIX: Dict[str, Dict[str, MCPSecBenchThreatCell]] = {}
_matrix_loaded = False


def load_matrix_from_json(json_path: Optional[str] = None) -> None:
    """Load threat matrix data from JSON file"""
    import json
    from pathlib import Path
    
    global MCPSECBENCH_MATRIX, _matrix_loaded
    
    if _matrix_loaded:
        return
    
    if json_path is None:
        # Default path
        json_path = Path(__file__).parent.parent / "data" / "mcpsecbench_matrix.json"
    
    json_path = Path(json_path)
    if not json_path.exists():
        print(f"[Schema] Warning: Matrix JSON file not found at {json_path}")
        return
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        matrix_data = data.get('matrix', {})
        
        for surface_name, attacks in matrix_data.items():
            if surface_name not in MCPSECBENCH_MATRIX:
                MCPSECBENCH_MATRIX[surface_name] = {}
            
            for attack_name, cell_data in attacks.items():
                # Convert to dataclass
                graph_pattern = GraphPattern(
                    node_types=cell_data.get('graph_pattern', {}).get('node_types', []),
                    edge_types=cell_data.get('graph_pattern', {}).get('edge_types', []),
                    pattern_description=cell_data.get('graph_pattern', {}).get('pattern_description', ''),
                    example_pattern=cell_data.get('graph_pattern', {}).get('example_pattern', '')
                )
                
                test_template = TestTemplate(
                    static_analysis=cell_data.get('test_template', {}).get('static_analysis', ''),
                    blackbox_test=cell_data.get('test_template', {}).get('blackbox_test', ''),
                    test_description=cell_data.get('test_template', {}).get('test_description', '')
                )
                
                # Find matching enum values
                surface_enum = None
                for s in MCPSurface:
                    if s.value == surface_name:
                        surface_enum = s
                        break
                
                attack_enum = None
                for a in MCPSecBenchAttackType:
                    if a.value == attack_name:
                        attack_enum = a
                        break
                
                if surface_enum and attack_enum:
                    threat_cell = MCPSecBenchThreatCell(
                        surface=surface_enum,
                        attack_type=attack_enum,
                        short_description=cell_data.get('short_description', ''),
                        graph_pattern=graph_pattern,
                        test_template=test_template,
                        severity=cell_data.get('severity', 5),
                        how_used_in_product=cell_data.get('how_used_in_product', 'TBD')
                    )
                    MCPSECBENCH_MATRIX[surface_name][attack_name] = threat_cell
        
        _matrix_loaded = True
        print(f"[Schema] Loaded {sum(len(v) for v in MCPSECBENCH_MATRIX.values())} threat cells from {json_path}")
        
    except Exception as e:
        print(f"[Schema] Error loading matrix from JSON: {e}")
        import traceback
        traceback.print_exc()


def initialize_matrix():
    """Initialize the 4×17 threat matrix with default values"""
    load_matrix_from_json()


def get_threat_cell(surface: MCPSurface, attack_type: MCPSecBenchAttackType) -> Optional[MCPSecBenchThreatCell]:
    """Get threat cell data for a specific surface × attack type combination"""
    surface_key = surface.value
    attack_key = attack_type.value
    
    if surface_key in MCPSECBENCH_MATRIX and attack_key in MCPSECBENCH_MATRIX[surface_key]:
        return MCPSECBENCH_MATRIX[surface_key][attack_key]
    return None


def get_severity(surface: MCPSurface, attack_type: MCPSecBenchAttackType) -> int:
    """Get severity score (0-10) for a specific combination"""
    cell = get_threat_cell(surface, attack_type)
    if cell:
        return cell.severity
    return 5  # Default medium severity


def get_graph_pattern(surface: MCPSurface, attack_type: MCPSecBenchAttackType) -> Optional[GraphPattern]:
    """Get graph pattern for knowledge graph construction"""
    cell = get_threat_cell(surface, attack_type)
    if cell:
        return cell.graph_pattern
    return None


def get_test_template(surface: MCPSurface, attack_type: MCPSecBenchAttackType) -> Optional[TestTemplate]:
    """Get test template for vulnerability detection"""
    cell = get_threat_cell(surface, attack_type)
    if cell:
        return cell.test_template
    return None

