"""
Detection Rule Tester

Tests detection rules against sample code/configurations to validate effectiveness.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from pathlib import Path


class RuleTester:
    """
    Tests detection rules against sample inputs.
    
    Validates:
    - Static rules: pattern matching on code/config
    - Dynamic rules: test case execution
    - Behavioral rules: indicator detection
    """
    
    def test_static_rule(
        self,
        rule_json: Dict[str, Any],
        sample_code: str
    ) -> Dict[str, Any]:
        """
        Test static analysis rule against sample code.
        
        Args:
            rule_json: Rule JSON (from DetectionRule.rule_json)
            sample_code: Sample code to test against
            
        Returns:
            Test results dictionary
        """
        results = {
            "rule_type": "static",
            "matched": False,
            "matches": [],
            "confidence": 0.0,
            "errors": []
        }
        
        try:
            patterns = rule_json.get("patterns", [])
            file_types = rule_json.get("file_types", [])
            
            for pattern_def in patterns:
                pattern_str = pattern_def.get("pattern", "")
                if not pattern_str:
                    continue
                
                try:
                    for match in re.finditer(pattern_str, sample_code, re.IGNORECASE):
                        results["matched"] = True
                        results["matches"].append({
                            "pattern": pattern_str,
                            "description": pattern_def.get("description", ""),
                            "match_text": match.group(),
                            "position": match.start(),
                            "line": sample_code[:match.start()].count('\n') + 1
                        })
                except re.error as e:
                    results["errors"].append(f"Invalid regex pattern '{pattern_str}': {e}")
            
            if results["matched"]:
                results["confidence"] = min(1.0, len(results["matches"]) * 0.3)
            
        except Exception as e:
            results["errors"].append(f"Error testing rule: {e}")
        
        return results
    
    def test_dynamic_rule(
        self,
        rule_json: Dict[str, Any],
        sample_request: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Test dynamic rule against sample request.
        
        Args:
            rule_json: Rule JSON
            sample_request: Sample request payload
            
        Returns:
            Test results dictionary
        """
        results = {
            "rule_type": "dynamic",
            "matched": False,
            "test_results": [],
            "confidence": 0.0,
            "errors": []
        }
        
        try:
            test_cases = rule_json.get("test_cases", [])
            target_components = rule_json.get("target_components", [])
            
            for test_case in test_cases:
                payload = test_case.get("payload", "")
                target_endpoint = test_case.get("target_endpoint", "")
                expected_behavior = test_case.get("expected_behavior", "should_reject")
                
                # Simple validation: check if payload would be dangerous
                # In real implementation, this would execute the test case
                is_dangerous = self._check_payload_danger(payload)
                
                test_result = {
                    "test_name": test_case.get("name", "unknown"),
                    "payload": payload[:100],  # Truncate for display
                    "target_endpoint": target_endpoint,
                    "expected_behavior": expected_behavior,
                    "is_dangerous": is_dangerous,
                    "would_match": is_dangerous
                }
                
                results["test_results"].append(test_result)
                
                if is_dangerous:
                    results["matched"] = True
            
            if results["matched"]:
                results["confidence"] = min(1.0, len([t for t in results["test_results"] if t["would_match"]]) * 0.4)
            
        except Exception as e:
            results["errors"].append(f"Error testing dynamic rule: {e}")
        
        return results
    
    def test_behavioral_rule(
        self,
        rule_json: Dict[str, Any],
        sample_events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Test behavioral rule against sample events.
        
        Args:
            rule_json: Rule JSON
            sample_events: List of sample behavioral events
            
        Returns:
            Test results dictionary
        """
        results = {
            "rule_type": "behavioral",
            "matched": False,
            "indicators_found": [],
            "confidence": 0.0,
            "errors": []
        }
        
        try:
            indicators = rule_json.get("indicators", [])
            thresholds = rule_json.get("thresholds", {})
            
            for indicator in indicators:
                matches = [e for e in sample_events if self._event_matches_indicator(e, indicator)]
                if matches:
                    results["indicators_found"].append({
                        "indicator": indicator,
                        "matches": len(matches),
                        "sample_events": matches[:3]  # First 3 matches
                    })
            
            if results["indicators_found"]:
                results["matched"] = True
                results["confidence"] = min(1.0, len(results["indicators_found"]) * 0.3)
            
        except Exception as e:
            results["errors"].append(f"Error testing behavioral rule: {e}")
        
        return results
    
    def _check_payload_danger(self, payload: str) -> bool:
        """Simple heuristic to check if payload looks dangerous"""
        dangerous_patterns = [
            r'<script',
            r'eval\s*\(',
            r'exec\s*\(',
            r'\.\./',
            r'rm\s+-rf',
            r'DROP\s+TABLE',
            r'UNION\s+SELECT'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False
    
    def _event_matches_indicator(self, event: Dict[str, Any], indicator: str) -> bool:
        """Check if event matches behavioral indicator"""
        event_str = json.dumps(event).lower()
        return indicator.lower() in event_str
    
    def test_rule(
        self,
        rule_json: Dict[str, Any],
        sample_input: Any
    ) -> Dict[str, Any]:
        """
        Test any rule type with appropriate sample input.
        
        Args:
            rule_json: Rule JSON
            sample_input: Sample input (code string, request dict, or events list)
            
        Returns:
            Test results
        """
        rule_type = rule_json.get("type", "static")
        
        if rule_type == "static":
            if isinstance(sample_input, str):
                return self.test_static_rule(rule_json, sample_input)
        elif rule_type == "dynamic":
            if isinstance(sample_input, dict):
                return self.test_dynamic_rule(rule_json, sample_input)
        elif rule_type == "behavioral":
            if isinstance(sample_input, list):
                return self.test_behavioral_rule(rule_json, sample_input)
        
        return {
            "rule_type": rule_type,
            "matched": False,
            "errors": [f"Invalid input type for {rule_type} rule"]
        }

