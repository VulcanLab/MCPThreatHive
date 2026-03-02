"""
Threat Pattern Extractor

Extracts structured threat patterns from intelligence text using NLP and AI.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from datetime import datetime

from config.llm_config import get_llm_config
from schemas.mcp_threat_schema import StrideCategory, RiskLevel


class ThreatPatternExtractor:
    """
    Extracts threat patterns from intelligence text.
    
    Uses AI to extract:
    - Attack surface (client_side, server_side, protocol_level)
    - Attack type (prompt_injection, tool_abuse, etc.)
    - Indicators of Compromise (IoC)
    - CVE/CWE references
    - Detection methods
    - Mitigation recommendations
    """
    
    def __init__(self):
        self.llm = get_llm_config()
    
    def extract_patterns(self, text: str, source_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract threat patterns from text.
        
        Args:
            text: Intelligence text content
            source_url: Optional source URL
            
        Returns:
            Extracted threat pattern dictionary
        """
        if not text or len(text.strip()) < 50:
            return {}
        
        # Use AI to extract structured patterns
        prompt = f"""Analyze the following MCP security intelligence text and extract structured threat patterns.

Text:
{text[:3000]}

Extract the following information in JSON format:
{{
    "attack_surface": "client_side|server_side|protocol_level|tool_level|resource_level",
    "attack_type": "prompt_injection|tool_poisoning|tool_abuse|data_exfiltration|privilege_escalation|resource_exhaustion|context_contamination|message_tampering|replay_attack|path_traversal|etc",
    "threat_name": "Short descriptive name",
    "description": "Detailed description",
    "indicators": ["list", "of", "IoC", "patterns"],
    "cve_ids": ["CVE-YYYY-NNNNN"],
    "cwe_ids": ["CWE-XXX"],
    "detection_methods": ["static_analysis", "dynamic_testing", "behavioral_monitoring"],
    "mitigation": ["list", "of", "recommendations"],
    "severity": "critical|high|medium|low",
    "stride_category": "Spoofing|Tampering|Repudiation|Information_Disclosure|Denial_of_Service|Elevation_of_Privilege"
}}

Return only valid JSON, no markdown formatting."""

        try:
            response = self.llm.completion(
                messages=[{"role": "user", "content": prompt}],
                role="THREAT_ANALYZER",
                temperature=1,
                max_tokens=2000
            )
            
            if "error" in response:
                raise Exception(response.get("error", "LLM call failed"))
            
            content = response.get("content", "").strip()
            
            # Remove markdown code blocks if present
            if content.startswith("```"):
                content = re.sub(r'^```(?:json)?\s*\n', '', content)
                content = re.sub(r'\n```\s*$', '', content)
            
            # Robust JSON parsing
            try:
                if not content:
                    print("[ThreatPatternExtractor] Warning: Empty content from LLM")
                    return {}
                pattern = json.loads(content)
            except json.JSONDecodeError:
                # Try to find JSON object in text
                match = re.search(r'(\{.*\})', content, re.DOTALL)
                if match:
                    pattern = json.loads(match.group(1))
                else:
                    print(f"[ThreatPatternExtractor] Warning: Could not parse JSON from content: {content[:100]}...")
                    return {}

            # Handle list response (take first item)
            if isinstance(pattern, list):
                if pattern:
                    pattern = pattern[0]
                else:
                    pattern = {}
            
            if not isinstance(pattern, dict):
                pattern = {}
            
            # Validate and normalize
            pattern = self._normalize_pattern(pattern)
            
            # Add metadata
            pattern["extracted_at"] = datetime.now().isoformat()
            pattern["source_url"] = source_url
            
            return pattern
            
        except Exception as e:
            print(f"[ThreatPatternExtractor] Error extracting patterns: {e}")
            # Fallback: extract basic patterns using regex
            return self._extract_basic_patterns(text, source_url)
    
    def _normalize_pattern(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize extracted pattern to standard format"""
        # Normalize attack_surface
        surface = pattern.get("attack_surface", "").lower()
        valid_surfaces = ["client_side", "server_side", "protocol_level", "tool_level", "resource_level"]
        if surface not in valid_surfaces:
            pattern["attack_surface"] = "server_side"  # Default
        
        # Normalize attack_type
        attack_type = pattern.get("attack_type", "").lower()
        valid_types = [
            "prompt_injection", "tool_poisoning", "tool_abuse", "data_exfiltration",
            "privilege_escalation", "resource_exhaustion", "context_contamination",
            "message_tampering", "replay_attack", "path_traversal"
        ]
        if attack_type not in valid_types:
            pattern["attack_type"] = "unknown"
        
        # Normalize severity
        severity = pattern.get("severity", "medium").lower()
        if severity not in ["critical", "high", "medium", "low"]:
            pattern["severity"] = "medium"
        
        # Normalize STRIDE
        stride = pattern.get("stride_category", "Tampering")
        try:
            stride_enum = StrideCategory[stride.upper().replace(" ", "_")]
            pattern["stride_category"] = stride_enum.value
        except:
            pattern["stride_category"] = "Tampering"
        
        # Ensure lists
        for key in ["indicators", "cve_ids", "cwe_ids", "detection_methods", "mitigation"]:
            if key not in pattern or not isinstance(pattern[key], list):
                pattern[key] = []
        
        return pattern
    
    def _extract_basic_patterns(self, text: str, source_url: Optional[str] = None) -> Dict[str, Any]:
        """Fallback: extract basic patterns using regex"""
        text_lower = text.lower()
        
        # Detect attack types
        attack_type = "unknown"
        if "prompt injection" in text_lower or "jailbreak" in text_lower:
            attack_type = "prompt_injection"
        elif "tool" in text_lower and ("poison" in text_lower or "malicious" in text_lower):
            attack_type = "tool_poisoning"
        elif "privilege" in text_lower or "escalation" in text_lower:
            attack_type = "privilege_escalation"
        elif "exhaustion" in text_lower or "dos" in text_lower or "denial" in text_lower:
            attack_type = "resource_exhaustion"
        
        # Extract CVE/CWE
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        cwe_ids = re.findall(r'CWE-\d+', text, re.IGNORECASE)
        
        return {
            "attack_surface": "server_side",
            "attack_type": attack_type,
            "threat_name": text[:100] if len(text) > 100 else text,
            "description": text[:500],
            "indicators": [],
            "cve_ids": list(set(cve_ids)),
            "cwe_ids": list(set(cwe_ids)),
            "detection_methods": ["static_analysis"],
            "mitigation": [],
            "severity": "medium",
            "stride_category": "Tampering",
            "extracted_at": datetime.now().isoformat(),
            "source_url": source_url
        }
    
    def batch_extract(self, texts: List[str], source_urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Extract patterns from multiple texts"""
        if source_urls is None:
            source_urls = [None] * len(texts)
        
        patterns = []
        for text, url in zip(texts, source_urls):
            pattern = self.extract_patterns(text, url)
            if pattern:
                patterns.append(pattern)
        
        return patterns

