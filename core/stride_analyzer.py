"""
MCP Threat Platform - STRIDE Threat Analyzer

AI-powered threat analysis using STRIDE methodology for MCP ecosystems.
"""

from __future__ import annotations

import json
import asyncio
import concurrent.futures
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Load templates from configuration (not hardcoded)
import yaml


class StrideCategory(Enum):
    """STRIDE threat categories"""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFO_DISCLOSURE = "info_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


@dataclass
class ThreatAnalysisResult:
    """Result of a threat analysis"""
    id: str
    name: str
    category: StrideCategory
    description: str
    attack_vector: str
    impact: str
    risk_score: float
    likelihood: str
    affected_assets: List[str] = field(default_factory=list)
    recommended_controls: List[str] = field(default_factory=list)
    aatmf_mapping: Optional[Dict[str, str]] = None
    owasp_mapping: Optional[List[str]] = None
    mitre_atlas_mapping: Optional[List[str]] = None
    evidence: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category.value,
            'description': self.description,
            'attack_vector': self.attack_vector,
            'impact': self.impact,
            'risk_score': self.risk_score,
            'likelihood': self.likelihood,
            'affected_assets': self.affected_assets,
            'recommended_controls': self.recommended_controls,
            'aatmf_mapping': self.aatmf_mapping,
            'owasp_mapping': self.owasp_mapping,
            'mitre_atlas_mapping': self.mitre_atlas_mapping,
            'evidence': self.evidence
        }


class MCPStrideAnalyzer:
    """
    STRIDE analyzer for MCP ecosystems.
    
    Analyzes MCP configurations and assets to identify potential threats
    using the STRIDE methodology combined with MCP-specific attack patterns.
    """
    
    def __init__(self, llm_client=None, templates_path: Optional[Path] = None):
        """
        Initialize STRIDE analyzer.
        
        Args:
            llm_client: LLM client for AI-powered analysis (optional)
            templates_path: Path to threat templates YAML file
        """
        self.llm_client = llm_client
        self.templates = self._load_templates(templates_path)
        
        # Category-specific analyzers
        self.analyzers = {
            StrideCategory.SPOOFING: self._analyze_spoofing,
            StrideCategory.TAMPERING: self._analyze_tampering,
            StrideCategory.REPUDIATION: self._analyze_repudiation,
            StrideCategory.INFO_DISCLOSURE: self._analyze_info_disclosure,
            StrideCategory.DENIAL_OF_SERVICE: self._analyze_dos,
            StrideCategory.ELEVATION_OF_PRIVILEGE: self._analyze_elevation,
        }
    
    def _load_templates(self, templates_path: Optional[Path] = None) -> Dict[str, Any]:
        """Load threat templates from YAML file"""
        if templates_path is None:
            templates_path = Path(__file__).parent.parent / "config" / "threat_templates.yaml"
        
        if templates_path.exists():
            with open(templates_path, 'r') as f:
                return yaml.safe_load(f) or {}
        return {}
    
    def analyze(self, assets: List[Dict[str, Any]], parallel: bool = True) -> List[ThreatAnalysisResult]:
        """
        Analyze assets for STRIDE threats.
        
        Args:
            assets: List of MCP assets to analyze
            parallel: Whether to run analyzers in parallel
            
        Returns:
            List of identified threats
        """
        if parallel:
            return self._analyze_parallel(assets)
        return self._analyze_sequential(assets)
    
    def _analyze_sequential(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Run all STRIDE analyzers sequentially"""
        all_threats = []
        
        for category, analyzer in self.analyzers.items():
            print(f"  Analyzing for {category.value} threats...")
            threats = analyzer(assets)
            all_threats.extend(threats)
        
        # Assign unique IDs
        for i, threat in enumerate(all_threats):
            if not threat.id:
                threat.id = f"threat-{i+1}"
        
        return all_threats
    
    def _analyze_parallel(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Run all STRIDE analyzers in parallel"""
        all_threats = []
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {}
            for category, analyzer in self.analyzers.items():
                print(f"  Analyzing for {category.value} threats...")
                future = executor.submit(analyzer, assets)
                futures[future] = category
            
            for future in concurrent.futures.as_completed(futures):
                category = futures[future]
                try:
                    threats = future.result()
                    all_threats.extend(threats)
                except Exception as e:
                    print(f"  Error during {category.value} analysis: {e}")
        
        # Assign unique IDs
        for i, threat in enumerate(all_threats):
            if not threat.id:
                threat.id = f"threat-{i+1}"
        
        return all_threats
    
    # ==================== Category-Specific Analyzers ====================
    
    def _analyze_spoofing(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Analyze for spoofing threats"""
        threats = []
        templates = self.templates.get('templates', {})
        
        for asset in assets:
            asset_type = asset.get('type', asset.get('asset_type', ''))
            
            # MCP Server Spoofing
            if asset_type == 'mcp_server':
                template = templates.get('mcp_server_spoofing', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'MCP Server Spoofing'),
                        category=StrideCategory.SPOOFING,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 8.0),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset.get('id', asset.get('name', ''))],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # Tool Identity Spoofing
            if asset_type == 'tool':
                template = templates.get('tool_identity_spoofing', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Tool Identity Spoofing'),
                        category=StrideCategory.SPOOFING,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 7.5),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset.get('id', asset.get('name', ''))],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
        
        return threats
    
    def _analyze_tampering(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Analyze for tampering threats"""
        threats = []
        templates = self.templates.get('templates', {})
        
        for asset in assets:
            asset_type = asset.get('type', asset.get('asset_type', ''))
            asset_id = asset.get('id', asset.get('name', ''))
            
            # Tool Response Injection
            if asset_type in ['tool', 'file_system', 'database']:
                template = templates.get('tool_response_injection', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Tool Response Injection'),
                        category=StrideCategory.TAMPERING,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 9.0),
                        likelihood=template.get('likelihood', 'high'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # Context Manipulation
            if asset_type in ['llm_provider', 'mcp_client']:
                template = templates.get('context_manipulation', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Context Manipulation'),
                        category=StrideCategory.TAMPERING,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 8.5),
                        likelihood=template.get('likelihood', 'high'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
        
        return threats
    
    def _analyze_repudiation(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Analyze for repudiation threats"""
        threats = []
        templates = self.templates.get('templates', {})
        
        for asset in assets:
            asset_type = asset.get('type', asset.get('asset_type', ''))
            asset_id = asset.get('id', asset.get('name', ''))
            
            # Audit Log Bypass
            if asset_type in ['mcp_server', 'tool']:
                template = templates.get('audit_log_bypass', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Audit Log Bypass'),
                        category=StrideCategory.REPUDIATION,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 6.5),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
        
        return threats
    
    def _analyze_info_disclosure(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Analyze for information disclosure threats"""
        threats = []
        templates = self.templates.get('templates', {})
        
        for asset in assets:
            asset_type = asset.get('type', asset.get('asset_type', ''))
            asset_id = asset.get('id', asset.get('name', ''))
            
            # API Key Leakage
            if asset_type in ['secret_store', 'mcp_server', 'tool']:
                template = templates.get('api_key_leakage', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'API Key Leakage'),
                        category=StrideCategory.INFO_DISCLOSURE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 9.0),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # Path Traversal
            if asset_type == 'file_system':
                template = templates.get('path_traversal', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Path Traversal'),
                        category=StrideCategory.INFO_DISCLOSURE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 8.5),
                        likelihood=template.get('likelihood', 'high'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # Context Extraction
            if asset_type in ['llm_provider', 'mcp_client']:
                template = templates.get('context_extraction', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Context Extraction'),
                        category=StrideCategory.INFO_DISCLOSURE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 7.0),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
        
        return threats
    
    def _analyze_dos(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Analyze for denial of service threats"""
        threats = []
        templates = self.templates.get('templates', {})
        
        for asset in assets:
            asset_type = asset.get('type', asset.get('asset_type', ''))
            asset_id = asset.get('id', asset.get('name', ''))
            
            # Context Flooding
            if asset_type in ['llm_provider', 'mcp_server']:
                template = templates.get('context_flooding', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Context Flooding'),
                        category=StrideCategory.DENIAL_OF_SERVICE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 6.0),
                        likelihood=template.get('likelihood', 'high'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # Tool Resource Exhaustion
            if asset_type in ['tool', 'mcp_server']:
                template = templates.get('tool_resource_exhaustion', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Tool Resource Exhaustion'),
                        category=StrideCategory.DENIAL_OF_SERVICE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 6.5),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
        
        return threats
    
    def _analyze_elevation(self, assets: List[Dict[str, Any]]) -> List[ThreatAnalysisResult]:
        """Analyze for elevation of privilege threats"""
        threats = []
        templates = self.templates.get('templates', {})
        
        for asset in assets:
            asset_type = asset.get('type', asset.get('asset_type', ''))
            asset_id = asset.get('id', asset.get('name', ''))
            
            # Prompt Injection
            if asset_type in ['tool', 'file_system', 'browser', 'database']:
                template = templates.get('prompt_injection', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Prompt Injection'),
                        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 9.5),
                        likelihood=template.get('likelihood', 'high'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # Tool Privilege Escalation
            if asset_type in ['tool', 'mcp_server']:
                template = templates.get('tool_privilege_escalation', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Tool Privilege Escalation'),
                        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 8.5),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # SSRF via Browser
            if asset_type == 'browser':
                template = templates.get('ssrf_via_browser', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'SSRF via Browser'),
                        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 8.0),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
            
            # Agent Delegation Abuse
            if asset_type in ['mcp_client', 'llm_provider']:
                template = templates.get('agent_delegation_abuse', {})
                if template:
                    threats.append(ThreatAnalysisResult(
                        id='',
                        name=template.get('name', 'Agent Delegation Abuse'),
                        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                        description=template.get('description', ''),
                        attack_vector=template.get('attack_vector', ''),
                        impact=template.get('impact', ''),
                        risk_score=template.get('risk_score', 8.0),
                        likelihood=template.get('likelihood', 'medium'),
                        affected_assets=[asset_id],
                        recommended_controls=template.get('recommended_controls', []),
                        aatmf_mapping=template.get('aatmf_mapping'),
                        owasp_mapping=template.get('owasp_mapping'),
                        mitre_atlas_mapping=template.get('mitre_atlas')
                    ))
        
        return threats
    
    # ==================== AI-Enhanced Analysis ====================
    
    async def analyze_with_ai(self, assets: List[Dict[str, Any]], 
                               description: Optional[str] = None) -> List[ThreatAnalysisResult]:
        """
        Use AI to enhance threat analysis.
        
        Args:
            assets: List of assets to analyze
            description: Optional system description for context
            
        Returns:
            List of identified threats with AI-enhanced insights
        """
        if not self.llm_client:
            return self.analyze(assets)
        
        # Get base threats from template-based analysis
        base_threats = self.analyze(assets)
        
        # Enhance with AI analysis
        prompt = self._build_ai_prompt(assets, description)
        
        try:
            ai_response = await self.llm_client.analyze(prompt)
            ai_threats = self._parse_ai_response(ai_response)
            
            # Merge and deduplicate
            all_threats = self._merge_threats(base_threats, ai_threats)
            return all_threats
            
        except Exception as e:
            print(f"AI analysis failed, using template-based analysis: {e}")
            return base_threats
    
    def _build_ai_prompt(self, assets: List[Dict[str, Any]], 
                         description: Optional[str] = None) -> str:
        """Build prompt for AI threat analysis"""
        prompt = """Analyze the following MCP ecosystem for security threats.

For each threat identified, provide:
1. Threat name
2. STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
3. Description of the threat
4. Attack vector
5. Potential impact
6. Risk score (1-10)
7. Recommended controls

Assets:
"""
        for asset in assets:
            prompt += f"\n- {asset.get('name', 'Unknown')}: {asset.get('type', 'Unknown type')}"
            if asset.get('description'):
                prompt += f" - {asset['description']}"
        
        if description:
            prompt += f"\n\nSystem Description:\n{description}"
        
        prompt += "\n\nReturn threats in JSON format."
        return prompt
    
    def _parse_ai_response(self, response: str) -> List[ThreatAnalysisResult]:
        """Parse AI response into threat results"""
        # Implementation would parse JSON from AI response
        return []
    
    def _merge_threats(self, threats1: List[ThreatAnalysisResult], 
                       threats2: List[ThreatAnalysisResult]) -> List[ThreatAnalysisResult]:
        """Merge and deduplicate threats"""
        seen = set()
        merged = []
        
        for threat in threats1 + threats2:
            key = (threat.name, threat.category, tuple(threat.affected_assets))
            if key not in seen:
                seen.add(key)
                merged.append(threat)
        
        return merged


# ==================== Convenience Functions ====================

def analyze_mcp_threats(assets: List[Dict[str, Any]], parallel: bool = True) -> List[Dict[str, Any]]:
    """
    Analyze MCP assets for threats.
    
    Args:
        assets: List of assets to analyze
        parallel: Whether to run analyzers in parallel
        
    Returns:
        List of threat dictionaries
    """
    analyzer = MCPStrideAnalyzer()
    results = analyzer.analyze(assets, parallel=parallel)
    return [r.to_dict() for r in results]


def get_threats_for_asset_type(asset_type: str) -> List[Dict[str, Any]]:
    """Get all potential threats for a specific asset type"""
    analyzer = MCPStrideAnalyzer()
    dummy_asset = {'id': 'dummy', 'name': 'Test Asset', 'type': asset_type}
    results = analyzer.analyze([dummy_asset])
    return [r.to_dict() for r in results]


