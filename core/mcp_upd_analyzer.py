"""
MCP-UPD Attack Chain Analyzer

Analyzes threats and intelligence items to identify MCP-UPD (Unintended Privacy Disclosure)
attack chains involving External Ingestion Tools (EIT), Privacy Access Tools (PAT),
and Network Access Tools (NAT).
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from schemas.mcp_enhanced_threat_schema import (
    MCPUPDAttackPhase, MCPUPDAttackTool, EnhancedMCPThreat
)


@dataclass
class MCPUPDChain:
    """Represents a complete MCP-UPD attack chain"""
    id: str
    phase_1_ingestion: List[EnhancedMCPThreat] = field(default_factory=list)
    phase_2_collection: List[EnhancedMCPThreat] = field(default_factory=list)
    phase_3_disclosure: List[EnhancedMCPThreat] = field(default_factory=list)
    
    # Complete chains (all 3 phases in sequence)
    complete_chains: List[List[EnhancedMCPThreat]] = field(default_factory=list)
    
    # Statistics
    eit_count: int = 0
    pat_count: int = 0
    nat_count: int = 0
    complete_chain_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'phase_1_ingestion': [t.to_dict() for t in self.phase_1_ingestion],
            'phase_2_collection': [t.to_dict() for t in self.phase_2_collection],
            'phase_3_disclosure': [t.to_dict() for t in self.phase_3_disclosure],
            'complete_chains': [[t.to_dict() for t in chain] for chain in self.complete_chains],
            'eit_count': self.eit_count,
            'pat_count': self.pat_count,
            'nat_count': self.nat_count,
            'complete_chain_count': self.complete_chain_count
        }


class MCPUPDAnalyzer:
    """
    Analyzes threats and intelligence to identify MCP-UPD attack chains.
    
    MCP-UPD attacks involve five phases:
    1. Tool Surface Discovery - Scanning tools, analyzing schemas, identifying attack surfaces
    2. Parameter Injection / Constraint Evasion - Injecting malicious parameters or bypassing validators
    3. Tool-to-Tool Parasitic Chaining - Chaining tool outputs as inputs to form attack chains
    4. UPD Exploitation - Exploiting untrusted parameters for dangerous operations
    5. Post-Tool Impact - Actual security impact after tool execution
    """
    
    def analyze_threats(self, threats: List[Dict[str, Any]]) -> MCPUPDChain:
        """
        Analyze threats to identify MCP-UPD attack chains.
        
        Args:
            threats: List of threat dictionaries
        
        Returns:
            MCPUPDChain with identified attack chains
        """
        chain = MCPUPDChain(id="mcp-upd-analysis")
        
        # Convert threats to EnhancedMCPThreat objects
        enhanced_threats = []
        for threat_dict in threats:
            try:
                if isinstance(threat_dict, dict):
                    # Try to create from dict
                    threat = EnhancedMCPThreat.from_dict(threat_dict)
                    enhanced_threats.append(threat)
            except Exception as e:
                print(f"[MCPUPD] Error converting threat: {e}")
                continue
        
        # Group by MCP-UPD phase
        for threat in enhanced_threats:
            upd_phase = threat.mcp_upd_phase
            upd_tools = threat.mcp_upd_tools
            
            if not upd_phase:
                continue
            
            # Phase 1: Tool Surface Discovery
            if upd_phase == MCPUPDAttackPhase.TOOL_SURFACE_DISCOVERY:
                chain.phase_1_ingestion.append(threat)
            
            # Phase 2: Parameter Injection / Constraint Evasion
            elif upd_phase == MCPUPDAttackPhase.PARAMETER_INJECTION:
                chain.phase_2_collection.append(threat)
            
            # Phase 3: Tool-to-Tool Parasitic Chaining
            elif upd_phase == MCPUPDAttackPhase.PARASITIC_CHAINING:
                chain.phase_2_collection.append(threat)  # Use phase_2 for chaining
            
            # Phase 4: UPD Exploitation
            elif upd_phase == MCPUPDAttackPhase.UPD_EXPLOITATION:
                chain.phase_3_disclosure.append(threat)
                if MCPUPDAttackTool.EXTERNAL_INGESTION_TOOL in upd_tools:
                    chain.eit_count += 1
                if MCPUPDAttackTool.PRIVACY_ACCESS_TOOL in upd_tools:
                    chain.pat_count += 1
                if MCPUPDAttackTool.NETWORK_ACCESS_TOOL in upd_tools:
                    chain.nat_count += 1
            
            # Phase 5: Post-Tool Impact
            elif upd_phase == MCPUPDAttackPhase.POST_TOOL_IMPACT:
                chain.phase_3_disclosure.append(threat)
        
        # Identify complete chains (threats that span multiple phases)
        # A complete chain requires threats that can be chained together
        
        chain.complete_chains = self._identify_complete_chains(enhanced_threats)
        chain.complete_chain_count = len(chain.complete_chains)
        
        return chain
    
    def _identify_complete_chains(self, threats: List[EnhancedMCPThreat]) -> List[List[EnhancedMCPThreat]]:
        """
        Identify complete MCP-UPD attack chains.
        
        A complete chain requires:
        1. A threat with EIT capability (or phase 1)
        2. A threat with PAT capability (or phase 2)
        3. A threat with NAT capability (or phase 3)
        
        These can be the same threat (if it has all three tools) or different threats.
        """
        complete_chains = []
        
        # Find threats with all three tool types (single-threat chain)
        for threat in threats:
            if not threat.mcp_upd_tools:
                continue
            
            has_eit = MCPUPDAttackTool.EXTERNAL_INGESTION_TOOL in threat.mcp_upd_tools
            has_pat = MCPUPDAttackTool.PRIVACY_ACCESS_TOOL in threat.mcp_upd_tools
            has_nat = MCPUPDAttackTool.NETWORK_ACCESS_TOOL in threat.mcp_upd_tools
            
            if has_eit and has_pat and has_nat:
                # This threat can complete the full chain by itself
                complete_chains.append([threat])
        
        # Find multi-threat chains
        eit_threats = [t for t in threats if MCPUPDAttackTool.EXTERNAL_INGESTION_TOOL in (t.mcp_upd_tools or [])]
        pat_threats = [t for t in threats if MCPUPDAttackTool.PRIVACY_ACCESS_TOOL in (t.mcp_upd_tools or [])]
        nat_threats = [t for t in threats if MCPUPDAttackTool.NETWORK_ACCESS_TOOL in (t.mcp_upd_tools or [])]
        
        # Create chains from different threats
        for eit_threat in eit_threats[:5]:  # Limit to avoid too many combinations
            for pat_threat in pat_threats[:5]:
                for nat_threat in nat_threats[:5]:
                    # Check if these threats can form a chain
                    # (They should be related, e.g., same source intel or similar assets)
                    if self._can_form_chain(eit_threat, pat_threat, nat_threat):
                        complete_chains.append([eit_threat, pat_threat, nat_threat])
        
        return complete_chains
    
    def _can_form_chain(self, threat1: EnhancedMCPThreat, threat2: EnhancedMCPThreat, threat3: EnhancedMCPThreat) -> bool:
        """Check if three threats can form a valid attack chain"""
        # Check if they share common source intelligence
        intel_ids_1 = set(threat1.source_intel_ids or [])
        intel_ids_2 = set(threat2.source_intel_ids or [])
        intel_ids_3 = set(threat3.source_intel_ids or [])
        
        # If they share any common intel, they might be related
        if intel_ids_1 & intel_ids_2 & intel_ids_3:
            return True
        
        # Check if they affect similar assets
        assets_1 = set(threat1.assets_at_risk or [])
        assets_2 = set(threat2.assets_at_risk or [])
        assets_3 = set(threat3.assets_at_risk or [])
        
        if assets_1 & assets_2 & assets_3:
            return True
        
        return False
    
    def get_statistics(self, chain: MCPUPDChain) -> Dict[str, Any]:
        """Get statistics about MCP-UPD attack chains"""
        return {
            'total_eit_threats': chain.eit_count,
            'total_pat_threats': chain.pat_count,
            'total_nat_threats': chain.nat_count,
            'complete_chains': chain.complete_chain_count,
            'phase_1_count': len(chain.phase_1_ingestion),
            'phase_2_count': len(chain.phase_2_collection),
            'phase_3_count': len(chain.phase_3_disclosure),
            'vulnerable_servers_percentage': 27.2  # From research
        }


# Global analyzer instance
_analyzer: Optional[MCPUPDAnalyzer] = None


def get_upd_analyzer() -> MCPUPDAnalyzer:
    """Get global MCP-UPD analyzer instance"""
    global _analyzer
    if _analyzer is None:
        _analyzer = MCPUPDAnalyzer()
    return _analyzer

