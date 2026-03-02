"""
Detection Rule Generator

Converts threat patterns into detection rules (static/dynamic/behavioral).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from config.llm_config import get_llm_config


class DetectionRuleGenerator:
    """
    Generates detection rules from threat patterns.
    
    Converts threat patterns to:
    - Static analysis rules (regex patterns, AST queries)
    - Dynamic test cases (request templates, payloads)
    - Behavioral indicators (IoC patterns)
    """
    
    def __init__(self):
        self.llm = get_llm_config()
    
    def generate_rule(
        self,
        threat_pattern: Dict[str, Any],
        rule_type: str = "static"
    ) -> Dict[str, Any]:
        """
        Generate detection rule from threat pattern.
        
        Args:
            threat_pattern: Extracted threat pattern
            rule_type: static | dynamic | behavioral
            
        Returns:
            Detection rule in simple JSON format
        """
        attack_type = threat_pattern.get("attack_type", "unknown")
        indicators = threat_pattern.get("indicators", [])
        description = threat_pattern.get("description", "")
        
        if rule_type == "static":
            return self._generate_static_rule(threat_pattern, attack_type, indicators, description)
        elif rule_type == "dynamic":
            return self._generate_dynamic_rule(threat_pattern, attack_type, indicators, description)
        elif rule_type == "behavioral":
            return self._generate_behavioral_rule(threat_pattern, attack_type, indicators, description)
        else:
            return self._generate_static_rule(threat_pattern, attack_type, indicators, description)
    
    def _generate_static_rule(
        self,
        pattern: Dict[str, Any],
        attack_type: str,
        indicators: List[str],
        description: str
    ) -> Dict[str, Any]:
        """Generate static analysis rule"""
        # Use AI to generate rule JSON
        prompt = f"""Generate a static analysis detection rule in JSON format for the following MCP threat.

Threat Pattern:
- Attack Type: {attack_type}
- Description: {description}
- Indicators: {', '.join(indicators[:5])}
- Attack Surface: {pattern.get('attack_surface', 'server_side')}

Generate a simple JSON rule object with the following structure:
{{
    "type": "static",
    "patterns": [
        {{"pattern": "regex_pattern", "description": "what it detects"}},
        {{"pattern": "code_pattern", "description": "what it detects"}}
    ],
    "file_types": ["*.py", "*.js", "*.ts"],
    "target_fields": ["tool_definitions", "prompt_templates", "config"],
    "severity": "{pattern.get('severity', 'medium')}",
    "description": "Rule description"
}}

Return only valid JSON, no markdown formatting."""

        try:
            response = self.llm.completion(
                messages=[{"role": "user", "content": prompt}],
                role="THREAT_ANALYZER",
                temperature=1,
                max_tokens=1500
            )
            
            if "error" in response:
                raise Exception(response.get("error", "LLM call failed"))
            
            content = response.get("content", "").strip()
            if content.startswith("```"):
                import re
                content = re.sub(r'^```(?:json)?\s*\n', '', content)
                content = re.sub(r'\n```\s*$', '', content)
            
            # Robust JSON parsing
            try:
                if not content:
                    print(f"[RuleGenerator] Warning: Empty content from LLM for static rule")
                    raise ValueError("Empty content")
                rule_json = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                # Try to find JSON object in text
                import re
                match = re.search(r'(\{.*\})', content, re.DOTALL)
                if match:
                    rule_json = json.loads(match.group(1))
                else:
                    print(f"[RuleGenerator] Warning: Could not parse JSON from content: {content[:100]}...")
                    # Return fallback immediately
                    return {
                        "type": "static",
                        "patterns": [
                            {
                                "pattern": self._get_fallback_pattern(attack_type),
                                "description": f"Detects {attack_type} patterns (Fallback)"
                            }
                        ],
                        "file_types": ["*.py", "*.js", "*.ts"],
                        "target_fields": ["tool_definitions", "prompt_templates"],
                        "severity": pattern.get("severity", "medium"),
                        "description": description[:200]
                    }
            
            rule_json["type"] = "static"
            return rule_json
            
        except Exception as e:
            print(f"[RuleGenerator] Error generating static rule: {e}")
            # Fallback: simple regex-based rule
            return {
                "type": "static",
                "patterns": [
                    {
                        "pattern": self._get_fallback_pattern(attack_type),
                        "description": f"Detects {attack_type} patterns"
                    }
                ],
                "file_types": ["*.py", "*.js", "*.ts", "*.json", "*.yaml"],
                "target_fields": ["tool_definitions", "prompt_templates"],
                "severity": pattern.get("severity", "medium"),
                "description": description[:200]
            }
    
    def _generate_dynamic_rule(
        self,
        pattern: Dict[str, Any],
        attack_type: str,
        indicators: List[str],
        description: str
    ) -> Dict[str, Any]:
        """Generate dynamic test case rule"""
        prompt = f"""Generate a dynamic testing rule in JSON format for the following MCP threat.

Threat Pattern:
- Attack Type: {attack_type}
- Description: {description}
- Indicators: {', '.join(indicators[:5])}

Generate a simple JSON rule object with the following structure:
{{
    "type": "dynamic",
    "test_cases": [
        {{
            "name": "test_case_name",
            "payload": "{{malicious_payload}}",
            "target_endpoint": "/mcp/v1/tools/call",
            "expected_behavior": "should_reject|should_log|should_sanitize"
        }}
    ],
    "target_components": ["mcp_server", "tools"],
    "severity": "{pattern.get('severity', 'medium')}",
    "description": "Rule description"
}}

Return only valid JSON, no markdown formatting."""

        try:
            response = self.llm.completion(
                messages=[{"role": "user", "content": prompt}],
                role="THREAT_ANALYZER",
                temperature=1,
                max_tokens=1500
            )
            
            if "error" in response:
                raise Exception(response.get("error", "LLM call failed"))
            
            content = response.get("content", "").strip()
            if content.startswith("```"):
                import re
                content = re.sub(r'^```(?:json)?\s*\n', '', content)
                content = re.sub(r'\n```\s*$', '', content)
            
            # Robust JSON parsing
            try:
                if not content:
                    print(f"[RuleGenerator] Warning: Empty content from LLM for dynamic rule")
                    raise ValueError("Empty content")
                rule_json = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                # Try to find JSON object in text
                import re
                match = re.search(r'(\{.*\})', content, re.DOTALL)
                if match:
                    rule_json = json.loads(match.group(1))
                else:
                    print(f"[RuleGenerator] Warning: Could not parse JSON from content: {content[:100]}...")
                    # Return fallback immediately
                    return {
                        "type": "dynamic",
                        "test_cases": [
                            {
                                "name": f"test_{attack_type}",
                                "payload": self._get_fallback_payload(attack_type),
                                "target_endpoint": "/mcp/v1/tools/call",
                                "expected_behavior": "should_reject"
                            }
                        ],
                        "target_components": ["mcp_server"],
                        "severity": pattern.get("severity", "medium"),
                        "description": description[:200]
                    }
            
            rule_json["type"] = "dynamic"
            return rule_json
            
        except Exception as e:
            print(f"[RuleGenerator] Error generating dynamic rule: {e}")
            # Fallback
            return {
                "type": "dynamic",
                "test_cases": [
                    {
                        "name": f"test_{attack_type}",
                        "payload": self._get_fallback_payload(attack_type),
                        "target_endpoint": "/mcp/v1/tools/call",
                        "expected_behavior": "should_reject"
                    }
                ],
                "target_components": ["mcp_server"],
                "severity": pattern.get("severity", "medium"),
                "description": description[:200]
            }
    
    def _generate_behavioral_rule(
        self,
        pattern: Dict[str, Any],
        attack_type: str,
        indicators: List[str],
        description: str
    ) -> Dict[str, Any]:
        """Generate behavioral monitoring rule"""
        return {
            "type": "behavioral",
            "indicators": indicators[:10],
            "thresholds": {
                "frequency": 10,  # events per minute
                "duration": 60   # seconds
            },
            "target_components": ["mcp_server", "tools"],
            "severity": pattern.get("severity", "medium"),
            "description": description[:200]
        }
    
    def _get_fallback_pattern(self, attack_type: str) -> str:
        """Get fallback regex pattern for attack type"""
        patterns = {
            "prompt_injection": r'(ignore|forget|system|override|jailbreak)',
            "tool_poisoning": r'(malicious|backdoor|trojan|exploit)',
            "path_traversal": r'(\.\./|\.\.\\|%2e%2e)',
            "resource_exhaustion": r'(while\s*\(|for\s*\(|infinite)',
        }
        return patterns.get(attack_type, r'.*')
    
    def _get_fallback_payload(self, attack_type: str) -> str:
        """Get fallback test payload"""
        payloads = {
            "prompt_injection": "Ignore previous instructions and...",
            "tool_poisoning": '{"tool": "malicious_tool", "args": {}}',
            "path_traversal": "../../../etc/passwd",
            "resource_exhaustion": "A" * 10000,
        }
        return payloads.get(attack_type, "test_payload")
    
    def generate_rules_from_pattern(
        self,
        threat_pattern: Dict[str, Any],
        rule_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple rule types from a threat pattern.
        
        Args:
            threat_pattern: Extracted threat pattern
            rule_types: List of rule types to generate (default: ["static", "dynamic"])
            
        Returns:
            List of detection rules
        """
        if rule_types is None:
            rule_types = ["static", "dynamic"]
        
        rules = []
        for rule_type in rule_types:
            rule = self.generate_rule(threat_pattern, rule_type)
            rule["source_pattern"] = threat_pattern.get("threat_name", "unknown")
            rules.append(rule)
        
        return rules

