"""
MCP Threat Analyzer

Uses AI to analyze threats, assess risks, and generate reports.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from schemas.mcp_threat_schema import (
    MCPThreat, MCPAsset, MCPControl, MCPAttackEvidence,
    StrideCategory, RiskLevel, Evidence,
    MCP_THREAT_TEMPLATES
)
from config.llm_config import get_llm_config


class MCPThreatAnalyzer:
    """
    MCP Threat Analyzer
    
    Features:
    - Analyzes content for MCP-related threats
    - Assesses risk levels and STRIDE categories
    - Generates threat cards (MCPThreat schema)
    - Suggests security controls
    """
    
    def __init__(self):
        self.llm_config = get_llm_config()
    
    def analyze_content(
        self,
        content: str,
        source_url: Optional[str] = None,
        source_type: str = "intel"
    ) -> Optional[MCPThreat]:
        """
        Analyze content and convert to MCPThreat schema
        
        Args:
            content: Content to analyze (intelligence, PoC, research reports, etc.)
            source_url: Source URL
            source_type: Source type (intel, github, cve, paper)
            
        Returns:
            MCPThreat object, or None if not relevant
        """
        prompt = f"""You are an MCP (Model Context Protocol) security threat analyst.

Analyze the following content and determine if it describes an MCP-related security threat.

CONTENT:
{content[:4000]}

SOURCE: {source_type}
{f"URL: {source_url}" if source_url else ""}

ANALYSIS REQUIREMENTS:
1. Determine if this content is related to MCP/Model Context Protocol security
2. If related, extract threat information and classify using STRIDE
3. Assess risk level (critical/high/medium/low/info)
4. Identify affected components
5. Suggest mitigation controls

STRIDE Categories for MCP:
- Spoofing: Server impersonation, tool spoofing
- Tampering: Tool output manipulation, context injection
- Repudiation: Lack of audit trail
- Information Disclosure: Data leakage, secret exposure
- Denial of Service: Resource exhaustion, context flooding
- Elevation of Privilege: Capability escalation, permission bypass

OUTPUT FORMAT (JSON):
{{
  "is_mcp_related": true/false,
  "title": "Brief threat title",
  "description": "Detailed threat description",
  "category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
  "risk_score": 0.0-10.0,
  "risk_level": "critical|high|medium|low|info",
  "impact": ["Impact 1", "Impact 2"],
  "attack_vector": ["Vector 1", "Vector 2"],
  "affected_components": ["Component 1", "Component 2"],
  "recommended_controls": ["Control 1", "Control 2"],
  "tags": ["tag1", "tag2"]
}}

If the content is NOT MCP-related, return:
{{"is_mcp_related": false}}"""

        response = self.llm_config.completion(
            messages=[{"role": "user", "content": prompt}],
            role="THREAT_ANALYZER",
            temperature=1
        )
        
        if response.get("error"):
            print(f"[ThreatAnalyzer] Error: {response['error']}")
            return None
        
        # Parse response
        try:
            content_text = response.get("content", "")
            
            # Extract JSON
            json_match = re.search(r'\{[\s\S]*\}', content_text)
            if json_match:
                data = json.loads(json_match.group())
                
                if not data.get("is_mcp_related", False):
                    return None
                
                # Map category
                category_map = {
                    "Spoofing": StrideCategory.SPOOFING,
                    "Tampering": StrideCategory.TAMPERING,
                    "Repudiation": StrideCategory.REPUDIATION,
                    "Information Disclosure": StrideCategory.INFORMATION_DISCLOSURE,
                    "Denial of Service": StrideCategory.DENIAL_OF_SERVICE,
                    "Elevation of Privilege": StrideCategory.ELEVATION_OF_PRIVILEGE
                }
                
                # Map risk level
                risk_map = {
                    "critical": RiskLevel.CRITICAL,
                    "high": RiskLevel.HIGH,
                    "medium": RiskLevel.MEDIUM,
                    "low": RiskLevel.LOW,
                    "info": RiskLevel.INFO
                }
                
                threat = MCPThreat(
                    title=data.get("title", "Unknown Threat"),
                    description=data.get("description", ""),
                    category=category_map.get(data.get("category"), StrideCategory.TAMPERING),
                    risk_score=float(data.get("risk_score", 5.0)),
                    risk_level=risk_map.get(data.get("risk_level", "medium"), RiskLevel.MEDIUM),
                    impact=data.get("impact", []),
                    attack_vector=data.get("attack_vector", []),
                    affected_components=data.get("affected_components", []),
                    recommended_controls=data.get("recommended_controls", []),
                    tags=data.get("tags", []),
                    source=source_type,
                    auto_generated=True,
                    evidence=Evidence(
                        source_type=source_type,
                        source_url=source_url
                    ) if source_url else None
                )
                
                return threat
                
        except Exception as e:
            print(f"[ThreatAnalyzer] Parse error: {e}")
        
        return None
    
    def assess_risk(self, threat: MCPThreat) -> Dict[str, Any]:
        """
        Detailed risk assessment
        
        Args:
            threat: MCPThreat object
            
        Returns:
            Risk assessment results
        """
        prompt = f"""Perform a detailed risk assessment for this MCP security threat:

THREAT:
Title: {threat.title}
Description: {threat.description}
Category: {threat.category.value}
Current Risk Score: {threat.risk_score}
Attack Vectors: {', '.join(threat.attack_vector)}
Affected Components: {', '.join(threat.affected_components)}

Provide assessment in JSON format:
{{
  "likelihood": 0.0-10.0,
  "impact_severity": 0.0-10.0,
  "exploitability": "easy|medium|hard",
  "adjusted_risk_score": 0.0-10.0,
  "risk_factors": ["factor1", "factor2"],
  "mitigating_factors": ["factor1", "factor2"],
  "urgency": "immediate|high|medium|low",
  "recommendation": "Brief recommendation"
}}"""

        response = self.llm_config.completion(
            messages=[{"role": "user", "content": prompt}],
            role="THREAT_ANALYZER",
            temperature=1
        )
        
        if response.get("error"):
            return {"error": response["error"]}
        
        try:
            content_text = response.get("content", "")
            json_match = re.search(r'\{[\s\S]*\}', content_text)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            return {"error": str(e)}
        
        return {}
    
    def suggest_controls(
        self,
        threat: MCPThreat,
        existing_controls: Optional[List[MCPControl]] = None
    ) -> List[Dict[str, Any]]:
        """
        Suggest security controls
        
        Args:
            threat: MCPThreat object
            existing_controls: Existing controls
            
        Returns:
            List of suggested controls
        """
        existing = []
        if existing_controls:
            existing = [c.name for c in existing_controls]
        
        prompt = f"""Suggest security controls to mitigate this MCP threat:

THREAT:
Title: {threat.title}
Category: {threat.category.value}
Attack Vectors: {', '.join(threat.attack_vector)}
Risk Score: {threat.risk_score}

EXISTING CONTROLS:
{', '.join(existing) if existing else 'None'}

Suggest additional controls in JSON format:
{{
  "controls": [
    {{
      "name": "Control Name",
      "type": "tool_sandbox|tool_permission|output_validation|rate_limit|path_whitelist|url_whitelist|audit_logging|input_sanitization",
      "description": "What this control does",
      "effectiveness": 0-100,
      "implementation_effort": "low|medium|high",
      "configuration": {{}}
    }}
  ]
}}"""

        response = self.llm_config.completion(
            messages=[{"role": "user", "content": prompt}],
            role="CONTROL_ADVISOR",
            temperature=1
        )
        
        if response.get("error"):
            return []
        
        try:
            content_text = response.get("content", "")
            json_match = re.search(r'\{[\s\S]*\}', content_text)
            if json_match:
                data = json.loads(json_match.group())
                return data.get("controls", [])
        except Exception:
            pass
        
        return []
    
    def generate_threat_summary(
        self,
        threats: List[MCPThreat],
        include_recommendations: bool = True
    ) -> str:
        """
        Generate threat summary report
        
        Args:
            threats: List of threats
            include_recommendations: Whether to include recommendations
            
        Returns:
            Summary text
        """
        threats_json = [t.to_dict() for t in threats[:20]]  # Limit count
        
        prompt = f"""Generate a concise threat summary report for these MCP security threats:

THREATS:
{json.dumps(threats_json, indent=2)}

Generate a summary including:
1. Executive Summary (2-3 sentences)
2. Key Findings (bullet points)
3. Risk Distribution (by category and level)
4. Top Priority Threats
{"5. Recommendations" if include_recommendations else ""}

Format as a readable report."""

        response = self.llm_config.completion(
            messages=[{"role": "user", "content": prompt}],
            role="REPORT_GENERATOR",
            temperature=1,
            max_tokens=2000
        )
        
        return response.get("content", "Unable to generate summary")


class IntelToThreatConverter:
    """
    Intel to Threat Card Converter
    
    Converts intelligence collected from mcp_intel_gatherer to MCPThreat schema
    """
    
    def __init__(self):
        self.analyzer = MCPThreatAnalyzer()
    
    def convert_intel_item(self, intel_item: Dict[str, Any]) -> Optional[MCPThreat]:
        """
        Convert a single intel item to MCPThreat
        
        Args:
            intel_item: Intel item (from mcp_intel_gatherer)
            
        Returns:
            MCPThreat or None
        """
        # Combine content
        content = f"""
Title: {intel_item.get('title', '')}
Summary: {intel_item.get('summary', '')}
Content: {intel_item.get('full_content', intel_item.get('snippet', ''))[:3000]}
Tags: {', '.join(intel_item.get('tags', []))}
"""
        
        threat = self.analyzer.analyze_content(
            content=content,
            source_url=intel_item.get('url'),
            source_type=intel_item.get('source_engine', 'intel')
        )
        
        if threat:
            # Add original intel metadata
            threat.metadata["original_intel"] = {
                "title": intel_item.get("title"),
                "url": intel_item.get("url"),
                "relevance_score": intel_item.get("relevance_score"),
                "timestamp": intel_item.get("timestamp")
            }
        
        return threat
    
    def batch_convert(
        self,
        intel_items: List[Dict[str, Any]],
        relevance_threshold: float = 60.0
    ) -> List[MCPThreat]:
        """
        Batch convert intel items to threat cards
        
        Args:
            intel_items: List of intel items
            relevance_threshold: Minimum relevance score
            
        Returns:
            List of MCPThreat objects
        """
        threats = []
        
        for item in intel_items:
            # Check relevance score
            if item.get("relevance_score", 0) < relevance_threshold:
                continue
            
            threat = self.convert_intel_item(item)
            if threat:
                threats.append(threat)
                print(f"[Converter] ✓ Converted: {threat.title[:50]}...")
        
        return threats


