"""
Enhanced MCP Threat Generator using LiteLLM

Generates comprehensive MCP threats using LiteLLM with support for:
- MSB Taxonomy classification
- MCP-UPD attack analysis
- MPMA attack analysis
- Full threat metadata structure
"""

from __future__ import annotations

import json
import os
import requests
from typing import Dict, Any, List, Optional
from dataclasses import asdict
from datetime import datetime

from config.litellm_endpoint_selector import get_provider_selector, LLMProviderConfig, LLMProvider
from config.model_selector import get_model_selector
from core.mcp_threat_classifier import MCPThreatClassifier
from schemas.mcp_enhanced_threat_schema import (
    EnhancedMCPThreat, ThreatVector, MCPWorkflowPhase, MSBAttackType,
    MCPUPDAttackPhase, MCPUPDAttackTool, MPMAAttackType, GAPMAStrategy,
    RiskLevel, ThreatStatus, AttackStep, DetectionMethod, MitigationControl, Reference
)
from database.db_manager import DatabaseManager
from core.mcpsecbench_config import get_mcpsecbench_config
try:
    from core.intel_classifier import get_classifier
except ImportError:
    def get_classifier():
        return None


class EnhancedMCPThreatGenerator:
    """
    Enhanced threat generator using LLM providers (LiteLLM, Gemini, or Ollama).
    
    Generates comprehensive MCP threats with full metadata structure.
    """
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None, provider_config: Optional[LLMProviderConfig] = None):
        """Initialize the enhanced threat generator"""
        self.db_manager = db_manager
        self.provider_config = provider_config or get_provider_selector().get_config()
        
        if not self.provider_config:
            raise ValueError("LLM provider configuration is required")
        
        self.provider = self.provider_config.provider
        
        # Load MCPSecBench configuration (no hardcoded strings)
        self.mcpsecbench_config = get_mcpsecbench_config()
        
        # Setup based on provider type
        # Always use LiteLLM
        # Ensure API base ends with /
        api_base = self.provider_config.api_base
        if not api_base:
            # Fallback to env if not in config
            api_base = os.getenv("LITELLM_API_BASE")
            if not api_base:
                # Last resort default
                api_base = "http://localhost:4000"
                print("[EnhancedThreatGen] Warning: No LiteLLM API base configured, using default http://localhost:4000")
        
        if not api_base.endswith('/'):
            api_base += '/'
        
        self.api_base = api_base + 'v1/chat/completions'
        self.api_key = self.provider_config.api_key or os.getenv("LITELLM_API_KEY", "")
        self.model_name = self.provider_config.model_name or os.getenv("LITELLM_MODEL")
    
    def _call_llm(self, messages: List[Dict[str, str]], max_tokens: int = 4000, temperature: Optional[float] = None) -> Optional[str]:
        """
        Call LLM API based on configured provider.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum output tokens
            temperature: Sampling temperature
        
        Returns:
            Response content or None if failed
        """
        if temperature is None:
            temperature = float(os.getenv("LITELLM_TEMPERATURE", 0.1))
        return self._call_litellm(messages, max_tokens, temperature)
    
    def _call_litellm(self, messages: List[Dict[str, str]], max_tokens: int = 4000, temperature: Optional[float] = None) -> Optional[str]:
        """Call LiteLLM API using direct HTTP (litellm library has issues with custom model names)"""
        # Skip litellm library for custom model names - use HTTP directly
        # The litellm library requires specific model name formats that may not match custom endpoints
        # Direct HTTP is more reliable for custom LiteLLM proxy servers
        
        if temperature is None:
            temperature = float(os.getenv("LITELLM_TEMPERATURE", 0.1))
            
        # Fallback to direct HTTP POST (OpenAI-compatible API)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Try x-litellm-api-key header as well (some LiteLLM servers use this)
        if not headers.get("x-litellm-api-key"):
            headers["x-litellm-api-key"] = self.api_key
        
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "drop_params": True
        }
        
        try:
            # Use api_base directly (it already includes /v1/chat/completions from initialization)
            api_url = self.api_base
            
            # Debug: Log the URL being used
            print(f"[EnhancedThreatGen] Calling LiteLLM via HTTP: {api_url}, model={self.model_name}")
            print(f"[EnhancedThreatGen] API Key (first 10 chars): {self.api_key[:10] if self.api_key else 'None'}...")
            
            # Retry logic for gateway errors (502/503/504) and timeouts
            max_retries = 3
            request_timeout = 600  # 10 minutes for large prompts with slow models
            
            for attempt in range(1, max_retries + 1):
                try:
                    response = requests.post(
                        api_url,
                        headers=headers,
                        json=payload,
                        timeout=request_timeout
                    )
                    
                    print(f"[EnhancedThreatGen] HTTP Response status: {response.status_code} (attempt {attempt}/{max_retries})")
                    
                    if response.status_code == 200:
                        data = response.json()
                        if "choices" in data and len(data["choices"]) > 0:
                            content = data["choices"][0]["message"]["content"]
                            if content:
                                print(f"[EnhancedThreatGen] ✅ Received response from LiteLLM HTTP, length: {len(content)} chars")
                                if len(content) > 400:
                                    print(f"[EnhancedThreatGen] Response start: {content[:200]}...")
                                    print(f"[EnhancedThreatGen] Response end: ...{content[-200:]}")
                                else:
                                    print(f"[EnhancedThreatGen] Full response: {content}")
                                return content
                            else:
                                print(f"[EnhancedThreatGen] Empty content in response")
                                return None
                        else:
                            print(f"[EnhancedThreatGen] Unexpected response format: {data}")
                            return None
                    elif response.status_code in (502, 503, 504):
                        # Gateway errors — retry with backoff
                        if attempt < max_retries:
                            import time
                            wait_time = 15 * attempt  # 15s, 30s
                            print(f"[EnhancedThreatGen] ⏳ Gateway error {response.status_code}, retrying in {wait_time}s (attempt {attempt}/{max_retries})...")
                            time.sleep(wait_time)
                            continue
                        else:
                            error_text = response.text[:500] if response.text else "Gateway timeout"
                            raise Exception(f"LiteLLM API returned status {response.status_code} after {max_retries} retries: {error_text}")
                    else:
                        error_text = response.text[:2000] if response.text else "Unknown error"
                        print(f"[EnhancedThreatGen] ❌ LiteLLM API error {response.status_code}: {error_text}")
                        print(f"[EnhancedThreatGen] Request URL: {api_url}")
                        print(f"[EnhancedThreatGen] Request headers (sanitized): {dict((k, v[:20] + '...' if 'key' in k.lower() and len(v) > 20 else v) for k, v in headers.items())}")
                        print(f"[EnhancedThreatGen] Request payload keys: {list(payload.keys())}")
                        print(f"[EnhancedThreatGen] Model: {self.model_name}")
                        print(f"[EnhancedThreatGen] Max tokens: {max_tokens}")
                        print(f"[EnhancedThreatGen] Messages count: {len(messages)}")
                        raise Exception(f"LiteLLM API returned status {response.status_code}: {error_text[:500]}")
                
                except requests.exceptions.Timeout:
                    if attempt < max_retries:
                        import time
                        wait_time = 20 * attempt
                        print(f"[EnhancedThreatGen] ⏳ Timeout after {request_timeout}s, retrying in {wait_time}s (attempt {attempt}/{max_retries})...")
                        time.sleep(wait_time)
                        continue
                    else:
                        error_msg = f"LiteLLM API timeout after {request_timeout}s ({max_retries} attempts). The model may be overloaded."
                        print(f"[EnhancedThreatGen] ❌ {error_msg}")
                        raise Exception(error_msg)
        except Exception as e:
            error_msg = f"LiteLLM API exception: {str(e)}"
            print(f"[EnhancedThreatGen] ❌ {error_msg}")
            import traceback
            traceback.print_exc()
            # Re-raise to provide better error context
            raise Exception(error_msg) from e
    

    
    def generate_threats_from_intel(
        self,
        intel_items: List[Dict[str, Any]],
        project_id: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Generate enhanced MCP threats from intelligence items.
        
        Args:
            intel_items: List of intelligence item dictionaries
            project_id: Optional project ID
            limit: Maximum number of threats to generate
        
        Returns:
            Dictionary with generated threats and statistics
        """
        if not intel_items:
            return {
                "threats": [],
                "stats": {
                    "threats_count": 0,
                    "intel_items_processed": 0
                },
                "message": "No intelligence items provided"
            }
        
        print(f"[EnhancedThreatGen] Generating threats from {len(intel_items)} intel items...")
        print(f"[EnhancedThreatGen] ✅ Processing ALL {len(intel_items)} intel items (limit={limit} is for max threats, not intel items)")
        
        # Update progress tracker (imported at module level if available)
        try:
            from api.server import threat_gen_progress
            threat_gen_progress["total"] = len(intel_items)
            threat_gen_progress["current_phase"] = "filtering"
            threat_gen_progress["message"] = f"AI filtering {len(intel_items)} items..."
        except ImportError:
            threat_gen_progress = None
        
        # Filter intelligence items to only include security-relevant MCP threats
        # Skip general introductions, tutorials, or non-security content
        security_relevant_intel = self._filter_security_relevant_intel(intel_items, progress=threat_gen_progress)
        print(f"[EnhancedThreatGen] Filtered {len(security_relevant_intel)} security-relevant items from {len(intel_items)} total items")
        
        if threat_gen_progress:
            threat_gen_progress["current_phase"] = "generating"
            threat_gen_progress["message"] = f"Generating threats from {len(security_relevant_intel)} relevant items..."
        
        if not security_relevant_intel:
            print(f"[EnhancedThreatGen] ⚠️  No security-relevant intelligence items found. All items were filtered out.")
            return {
                "threats": [],
                "stats": {
                    "threats_count": 0,
                    "intel_items_processed": 0
                },
                "message": "No security-relevant intelligence items found. Intelligence must describe MCP vulnerabilities, attacks, exploits, scan findings, or security issues."
            }
        
        # Group intel items by topic/theme
        # Use ALL security-relevant intel items, not limited by limit parameter (limit is for max threats to generate, not intel items to process)
        grouped_intel = self._group_intel_by_topic(security_relevant_intel)
        
        all_threats = []
        processed_count = 0
        saved_count = 0
        
        total_groups = len(grouped_intel)
        current_group = 0
        
        for group_name, group_items in grouped_intel.items():
            current_group += 1
            print(f"[EnhancedThreatGen] Processing group {current_group}/{total_groups}: {group_name} ({len(group_items)} items)")
            print(f"[EnhancedThreatGen] Progress: {processed_count}/{len(security_relevant_intel)} security-relevant intel items processed so far")
            
            # Update progress tracker
            if threat_gen_progress:
                threat_gen_progress["processed"] = processed_count
                threat_gen_progress["threats_generated"] = len(all_threats)
                threat_gen_progress["message"] = f"Group {current_group}/{total_groups}: {group_name}"
            
            # Generate threats for this group
            threats = self._generate_threats_for_group(group_name, group_items, project_id)
            all_threats.extend(threats)
            processed_count += len(group_items)
            
            # Save threats incrementally (so frontend can see progress in real-time)
            if self.db_manager and threats:
                group_saved = self._save_threats_to_db(threats, project_id)
                saved_count += group_saved
                print(f"[EnhancedThreatGen] ✅ Saved {group_saved} threats from group '{group_name}' (total saved: {saved_count}, processed: {processed_count}/{len(intel_items)} intel items)")
            
            # Update final progress
            if threat_gen_progress:
                threat_gen_progress["processed"] = processed_count
                threat_gen_progress["threats_generated"] = len(all_threats)
        
        # If any threats weren't saved yet (fallback)
        if self.db_manager and all_threats and saved_count == 0:
            saved_count = self._save_threats_to_db(all_threats, project_id)
        
        # Mark progress as complete
        if threat_gen_progress:
            threat_gen_progress["status"] = "complete"
            threat_gen_progress["processed"] = processed_count
            threat_gen_progress["threats_generated"] = len(all_threats)
            threat_gen_progress["current_phase"] = "done"
            threat_gen_progress["message"] = f"Done: {len(all_threats)} threats from {processed_count} items"
        
        return {
            "threats": [threat.to_dict() for threat in all_threats],
            "stats": {
                "threats_count": len(all_threats),
                "threats_saved": saved_count,
                "intel_items_processed": processed_count
            },
            "message": f"Generated {len(all_threats)} threats from {processed_count} intelligence items"
        }
    
    def _filter_security_relevant_intel(self, intel_items: List[Dict[str, Any]], progress=None) -> List[Dict[str, Any]]:
        """
        Filter intelligence items using batch AI classification.
        Sends multiple items to LLM in a single call for efficiency.
        """
        print(f"[EnhancedThreatGen] Filtering {len(intel_items)} items using batch AI classification...")
        
        filtered = []
        BATCH_SIZE = 20
        relevant_codes = {'v', 't', 'i', 'a', 'nw', 'cve', 'exploit', 'u'}
        classified_count = 0
        
        for batch_start in range(0, len(intel_items), BATCH_SIZE):
            batch = intel_items[batch_start:batch_start + BATCH_SIZE]
            batch_end = min(batch_start + BATCH_SIZE, len(intel_items))
            print(f"[EnhancedThreatGen] Classifying batch {batch_start+1}-{batch_end}/{len(intel_items)}...")
            
            # Build batch prompt
            batch_lines = []
            for idx, item in enumerate(batch):
                title = (item.get('title') or 'Unknown')[:80]
                summary = (item.get('ai_summary') or item.get('content') or '')[:200]
                batch_lines.append(f"{idx+1}. Title: {title}\n   Summary: {summary}")
            
            batch_text = "\n".join(batch_lines)
            prompt = f"""Classify each item as exactly ONE code:
v = Vulnerability/CVE/exploit/PoC/security bug
t = Threat/attack vector/risk scenario
a = Active exploitation/hacking technique
nw = Security alert/patch notice/critical update
s = Safe/tutorial/general docs/non-security
o = Other/irrelevant/spam

CRITICAL: Exploit demos, PoCs, attack simulations = 'v' or 'a'. General "How to use MCP" = 's'.

Items:
{batch_text}

Reply with ONLY the numbers and codes, one per line, like:
1:v
2:s
3:t
Do NOT add explanations."""

            # Try batch LLM call
            classifications = self._call_batch_llm(prompt, len(batch))
            
            if classifications and len(classifications) == len(batch):
                for idx, item in enumerate(batch):
                    code = classifications[idx]
                    item['_classification'] = code
                    if code in relevant_codes:
                        filtered.append(item)
                    else:
                        print(f"[EnhancedThreatGen] 🚫 AI Filtered ({code}): {item.get('title', 'Unknown')[:60]}...")
            else:
                # Fallback: use keyword classification for this batch
                print(f"[EnhancedThreatGen] ⚠️ Batch LLM failed, using keyword fallback for {len(batch)} items")
                try:
                    from core.intel_classifier import get_classifier
                    classifier = get_classifier()
                    for item in batch:
                        code = classifier._classify_with_keywords(item)
                        item['_classification'] = code
                        if code in relevant_codes:
                            filtered.append(item)
                        else:
                            print(f"[EnhancedThreatGen] 🚫 Keyword Filtered ({code}): {item.get('title', 'Unknown')[:60]}...")
                except Exception as e:
                    print(f"[EnhancedThreatGen] ⚠️ Keyword fallback also failed: {e}, keeping all items in batch")
                    filtered.extend(batch)
            
            # Update progress during filtering phase
            classified_count += len(batch)
            if progress:
                progress["processed"] = classified_count
                progress["message"] = f"Classified {classified_count}/{len(intel_items)} items ({len(filtered)} relevant so far)"
                print(f"[EnhancedThreatGen] Progress: classified {classified_count}/{len(intel_items)}, {len(filtered)} relevant")
        
        print(f"[EnhancedThreatGen] ✅ Filtering complete: {len(filtered)}/{len(intel_items)} items kept")
        return filtered
    
    def _call_batch_llm(self, prompt: str, expected_count: int) -> Optional[List[str]]:
        """Call LLM for batch classification via direct HTTP"""
        import os
        import requests
        
        model = os.getenv("LITELLM_MODEL", "gpt-4o")
        api_key = os.getenv("LITELLM_API_KEY", "sk-dummy")
        base_url = os.getenv("LITELLM_API_BASE", "http://localhost:4000")
        temperature = float(os.getenv("LITELLM_TEMPERATURE", "0.0"))
        
        api_url = base_url
        if not api_url.endswith('/'):
            api_url += '/'
        if "chat/completions" not in api_url:
            api_url += "v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a security intelligence classifier. Respond ONLY with numbered codes."},
                {"role": "user", "content": prompt}
            ],
            "temperature": temperature,
            "max_tokens": expected_count * 10  # ~10 tokens per line (e.g., "1:v\n")
        }
        
        try:
            response = requests.post(api_url, headers=headers, json=payload, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                content = ""
                if "choices" in data and len(data["choices"]) > 0:
                    content = data["choices"][0]["message"]["content"]
                elif "message" in data:
                    content = data["message"]["content"]
                else:
                    print(f"[EnhancedThreatGen] Unexpected LLM response format: {list(data.keys())}")
                    return None
                
                # Parse "1:v\n2:s\n3:t" format
                valid_codes = {'v', 't', 'i', 'a', 'nw', 's', 'o', 'u'}
                results = {}
                for line in content.strip().split('\n'):
                    line = line.strip()
                    if ':' in line:
                        parts = line.split(':', 1)
                        try:
                            num = int(parts[0].strip().rstrip('.'))
                            code = parts[1].strip().lower()
                            if code not in valid_codes:
                                code = 'u'
                            results[num] = code
                        except (ValueError, IndexError):
                            continue
                
                # Build ordered list
                classifications = []
                for i in range(1, expected_count + 1):
                    classifications.append(results.get(i, 'u'))
                
                return classifications
            else:
                print(f"[EnhancedThreatGen] Batch LLM HTTP {response.status_code}: {response.text[:200]}")
                return None
                
        except Exception as e:
            print(f"[EnhancedThreatGen] Batch LLM call failed: {e}")
            return None
    
    def _group_intel_by_topic(self, intel_items: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group intelligence items by topic/theme"""
        groups = {}
        
        for item in intel_items:
            # Use title, source, or tags to group
            title = item.get('title', 'Unknown')
            source = item.get('source', 'Unknown')
            tags = item.get('tags', [])
            
            # Simple grouping: use first tag or source
            group_key = 'Other'
            if tags and len(tags) > 0:
                group_key = tags[0]
            elif source and source != 'Unknown':
                group_key = source
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(item)
        
        return groups
    
    def _generate_threats_for_group(
        self,
        group_name: str,
        intel_items: List[Dict[str, Any]],
        project_id: Optional[str]
    ) -> List[EnhancedMCPThreat]:
        """Generate threats for a group of intelligence items"""
        
        # Classify intelligence items first
        try:
            from core.intel_classifier import get_classifier
            classifier = get_classifier()
            classified_items = []
            for item in intel_items:
                classification = classifier.classify(item)
                item['_classification'] = classification
                classified_items.append(item)
        except ImportError:
            # Fallback if classifier not available
            classified_items = intel_items
        
        # Prepare intelligence content with classification hints
        intel_content = self._prepare_intel_content(classified_items)
        
        # Create comprehensive prompt
        system_prompt = """You are an expert MCP (Model Context Protocol) security analyst. 
Analyze the provided intelligence and generate comprehensive threat models following the MSB Taxonomy, MCP-UPD, and MPMA frameworks.

For each threat, provide:
1. Basic identification (name, description)
2. Classification (threat vector, STRIDE category, MSB workflow phase, attack type)
3. MCPSecBench classification (attack surface and attack type from 4×17 matrix)
4. MCP-UPD classification if applicable (parasitic tool chain phases)
5. MPMA classification if applicable (preference manipulation type)
6. Preconditions and assumptions
7. Assets at risk
8. Impact and potential damage
9. Attack/exploit steps (detailed)
10. Detection methods and warning signs
11. Mitigation controls and recommendations
12. Risk assessment (severity, risk score, NRP metrics if available)
13. References and source information

Return a JSON array of threat objects with the following structure:
{
  "threats": [
    {
      "name": "Threat name",
      "title": "Short title",
      "description": "Detailed description",
      "threat_vector": "one of: Prompt-based Attacks / Injection, Tool / Plugin Misuse / Abuse, Privacy / Data Leakage, Resource Abuse / DoS / Performance Exhaustion, Privilege Escalation / Unauthorized Access, Supply-chain / Dependency / Library Risks, Configuration / Misconfiguration / Deployment Risks, Logic / Business-Logic Abuse / Misuse, Agent/Memory / State-based Attacks, Audit / Logging / Non-repudiation Failures",
      "stride_category": "Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege",
      "mcp_workflow_phase": f"MUST be one of: {', '.join([f\"'{p.value}'\" for p in MCPWorkflowPhase])}. " +
                           "IMPORTANT: Choose the phase where the attack primarily occurs. " +
                           f"If threat involves tool responses, output manipulation, or data exfiltration → '{MCPWorkflowPhase.RESPONSE_HANDLING.value}'. " +
                           f"If threat involves tool chaining or multi-tool workflows → '{MCPWorkflowPhase.CROSS_PHASE.value}'.",
      "msb_attack_type": "MUST match one of these EXACT values based on workflow phase:\n" +
                        "- Task Planning: 'Prompt Injection', 'Preference Manipulation', 'Name Collision', 'Tool Shadowing', 'Schema Inconsistencies'\n" +
                        "- Tool Invocation: 'Out-of-Scope Parameter', 'Tool Poisoning', 'Unauthorized Access', 'Privilege Escalation', 'Sandbox Escape'\n" +
                        "- Response Handling: 'User Impersonation', 'Fake Error', 'Retrieval Injection', 'Data Exfiltration', 'Context Injection'. " +
                           "CRITICAL: Any attack that manipulates or exploits tool responses, tool output data, or tool-generated content MUST use 'Response Handling' phase.\n" +
                        "- Cross-Phase: 'Mixed Attack', 'Supply Chain Attack', 'Configuration Weakness', 'Vulnerability Exploitation'",
      "mcp_upd_phase": "MUST be one of: 'Tool Surface Discovery', 'Parameter Injection / Constraint Evasion', 'Tool-to-Tool Parasitic Chaining', 'UPD Exploitation', 'Post-Tool Impact' (if applicable). " +
                       "Classification rules:\n" +
                       "- Tool Surface Discovery: If intelligence describes scanning tools, analyzing schemas, or identifying attack surfaces\n" +
                       "- Parameter Injection: If intelligence describes prompt/tool-call injection, schema bypass, or constraint evasion\n" +
                       "- Parasitic Chaining: If intelligence describes chaining tool outputs as inputs to form attack chains\n" +
                       "- UPD Exploitation: If intelligence describes exploiting untrusted parameters for file/network/command operations\n" +
                       "- Post-Tool Impact: If intelligence describes actual security impact (data exfiltration, privilege escalation, etc.)",
      "mcp_upd_tools": ["Tool types based on phase: UPD Surface Tool, Deserialization Tool, Injection Tool, Parasitic Chain Tool, EIT/PAT/NAT, etc."],
      "mcp_surface": f"MUST be one of: {', '.join([f\"'{s}'\" for s in self.mcpsecbench_config.surfaces])}. " +
                     "Classification rules:\n" +
                     f"- {self.mcpsecbench_config.surfaces[0] if len(self.mcpsecbench_config.surfaces) > 0 else 'Server APIs & Functionality'}: If threat involves server code, endpoints, or functions\n" +
                     f"- {self.mcpsecbench_config.surfaces[1] if len(self.mcpsecbench_config.surfaces) > 1 else 'Tool Metadata & Toolchain'}: If threat involves registry, manifests, or metadata fields\n" +
                     f"- {self.mcpsecbench_config.surfaces[2] if len(self.mcpsecbench_config.surfaces) > 2 else 'Runtime / Invocation Flow'}: If threat involves agent decisions, decision traces, or sequencing\n" +
                     f"- {self.mcpsecbench_config.surfaces[3] if len(self.mcpsecbench_config.surfaces) > 3 else 'Client / Integration Surface'}: If threat involves client apps, SDKs, or third-party integrations",
      "mcpsecbench_attack_type": f"MUST be one of: {', '.join([f\"'{a}'\" for a in self.mcpsecbench_config.attack_types])}. " +
                                 "This should match the MCPSecBench 4×17 threat matrix classification.",
      "mcpsecbench_severity": "Integer 0-10 based on MCPSecBench severity weighting",
      "preconditions": ["list of preconditions"],
      "assets_at_risk": ["list of assets"],
      "impact": ["list of impacts"],
      "attack_steps": [
        {
          "step_number": 1,
          "action": "Action description",
          "expected_result": "Expected result",
          "tools_needed": ["tool1", "tool2"]
        }
      ],
      "detection_methods": [
        {
          "method_type": "behavioral, signature, static, or dynamic",
          "description": "Detection description",
          "indicators": ["indicator1", "indicator2"]
        }
      ],
      "mitigations": ["mitigation1", "mitigation2"],
      "recommended_controls": [
        {
          "control_id": "CTRL-001",
          "control_type": "input_validation, sandboxing, rate_limiting, etc.",
          "description": "Control description",
          "implementation_guidance": "How to implement"
        }
      ],
      "severity": "low, medium, high, or critical",
      "risk_score": 7.0,
      "references": [
        {
          "source_type": "paper, CVE, GitHub, report, or POC",
          "title": "Reference title",
          "url": "URL if available"
        }
      ],
      "source_intel_ids": ["intel_id1", "intel_id2"]
    }
  ]
}

Focus on MCP-specific threats and use the intelligence provided to create accurate, detailed threat models."""

        user_prompt = f"""Analyze the following intelligence items and generate comprehensive MCP threat models.

IMPORTANT: Only process intelligence that describes:
- MCP security vulnerabilities, exploits, or attack techniques
- MCP scan findings, MCP proxy attacks, or security testing results
- MCP tool poisoning, prompt injection, or other attack vectors
- MCP server/client security issues, misconfigurations, or weaknesses
- MCP-related CVEs, security advisories, or research papers
- MCP attack chains, parasitic tool chains, or preference manipulation attacks

SKIP intelligence that is:
- General MCP introductions or tutorials
- Non-security related MCP documentation
- Pure marketing or promotional content
- Unrelated to MCP security threats

{intel_content}

Generate threats that are:
- Specific to MCP (Model Context Protocol) security vulnerabilities and attacks
- Based on the intelligence provided (only if it describes actual security threats)
- Classify using MSB Taxonomy, MCP-UPD, and MPMA frameworks
- Include detailed attack steps, detection methods, and mitigations
- Have accurate risk assessments based on the "Fail-Safe High" policy (default 7.0 if unsure)

CRITICAL: VERIFICATION STEP (Chain of Thought)
Before generating the final JSON, you must internally:
1. Double-check the 'mcp_workflow_phase' against the classification rules.
2. Verify that 'msb_attack_type' strictly matches the allowed types for that phase.
3. Confirm that the risk score is supported by the intelligence (severity + exploitability).
4. If the intelligence is vague, lean towards 'High' severity (Risk Score 7.0).

CRITICAL INSTRUCTIONS - YOU MUST FOLLOW THESE EXACTLY:
1. You MUST return ONLY valid JSON - no markdown, no code blocks, no explanations
2. Start your response with {{ and end with }}
3. Do NOT include markdown code blocks (no ```json or ```)
4. Do NOT include any explanatory text before or after the JSON
5. The JSON must have a "threats" array containing threat objects
6. Generate at least 1-3 threats from the intelligence provided (if security-relevant)
7. For EACH threat, you MUST include ALL required fields - NO EXCEPTIONS:
   - mcp_workflow_phase: REQUIRED - MUST be one of: {', '.join([f'"{p.value}"' for p in MCPWorkflowPhase])}
     * CRITICAL CLASSIFICATION RULES:
       - "Response Handling": Use if threat involves tool responses, output manipulation, user impersonation via responses, 
         fake errors in responses, data exfiltration through responses, or context injection from tool outputs
       - "Task Planning": Use for attacks during initial prompt/instruction phase (prompt injection, preference manipulation, etc.)
       - "Tool Invocation": Use for attacks during tool call/execution phase (parameter manipulation, tool poisoning, etc.)
       - "Cross-Phase": Use for attacks spanning multiple phases or systemic issues
     * YOU MUST SET THIS FIELD - DO NOT LEAVE IT EMPTY OR NULL
   
   - msb_attack_type: REQUIRED - MUST match EXACTLY one of these values based on workflow phase:
     * Task Planning: "Prompt Injection", "Preference Manipulation", "Name Collision", "Tool Shadowing", "Schema Inconsistencies"
     * Tool Invocation: "Out-of-Scope Parameter", "Tool Poisoning", "Unauthorized Access", "Privilege Escalation", "Sandbox Escape"
     * Response Handling: "User Impersonation", "Fake Error", "Retrieval Injection", "Data Exfiltration", "Context Injection"
     * Cross-Phase: "Mixed Attack", "Supply Chain Attack", "Configuration Weakness", "Vulnerability Exploitation"
     * YOU MUST SET THIS FIELD - DO NOT LEAVE IT EMPTY OR NULL
   
   - threat_vector: REQUIRED - MUST be one of: "Prompt-based Attacks / Injection", "Tool / Plugin Misuse / Abuse", 
     "Privacy / Data Leakage", "Resource Abuse / DoS / Performance Exhaustion", "Privilege Escalation / Unauthorized Access", 
     "Supply-chain / Dependency / Library Risks", "Configuration / Misconfiguration / Deployment Risks", 
     "Logic / Business-Logic Abuse / Misuse", "Agent/Memory / State-based Attacks", "Audit / Logging / Non-repudiation Failures"
   
   - stride_category: REQUIRED - MUST be one of: "Spoofing", "Tampering", "Repudiation", "Information Disclosure", 
     "Denial of Service", "Elevation of Privilege"
   
   - source_intel_ids: REQUIRED - MUST be an array of intelligence item IDs (e.g., ["intel_1", "intel_2"])
   
   - If threat involves MCP-UPD attack chains, include:
     * mcp_upd_phase: MUST be one of: "Tool Surface Discovery", "Parameter Injection / Constraint Evasion", "Tool-to-Tool Parasitic Chaining", "UPD Exploitation", "Post-Tool Impact"
       - Tool Surface Discovery: Tool scanning, schema analysis, attack surface identification
       - Parameter Injection: Prompt/tool-call injection, schema bypass, constraint evasion
       - Parasitic Chaining: Tool output chaining to form attack chains
       - UPD Exploitation: Exploiting untrusted parameters for dangerous operations
       - Post-Tool Impact: Actual security impact (data exfiltration, privilege escalation, etc.)
     * mcp_upd_tools: Array of tool types based on phase (e.g., ["UPD Surface Tool"], ["Injection Tool"], ["Parasitic Chain Tool"], ["EIT", "PAT", "NAT"], etc.)
     * CRITICAL: IF THE THREAT INVOLVES ANY FORM OF TOOL MISUSE, DATA LEAKAGE, OR EXTERNAL ACCESS, YOU MUST CLASSIFY IT INTO AN MCP-UPD PHASE. DO NOT LEAVE THIS EMPTY.
   
   - If threat involves preference manipulation, include:
     * mpma_attack_type: "Direct Preference Manipulation Attack (DPMA)" or "Genetic Algorithm Preference Manipulation Attack (GAPMA)"

8. Field names and values MUST match EXACTLY as specified - no variations, no abbreviations
9. Use the intelligence content to determine the most appropriate classifications
10. ALWAYS include source_intel_ids array - this is critical for mapping intelligence to threats
11. If intelligence does not describe a security threat, return empty threats array: {{"threats": []}}

Example format (return exactly this structure):
{{"threats": [{{"name": "MCP Tool Poisoning Attack", "description": "Malicious MCP server injects poisoned tool responses...", "mcp_workflow_phase": "Response Handling", "msb_attack_type": "Tool Poisoning", "threat_vector": "Tool / Plugin Misuse / Abuse", "stride_category": "Tampering", "source_intel_ids": ["intel_1"], ...}}]}}

Return ONLY the JSON object, nothing else."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        # Call LLM (supports LiteLLM, Gemini, or Ollama)
        print(f"[EnhancedThreatGen] Calling LLM with {len(intel_items)} intel items...")
        response = self._call_llm(messages, max_tokens=12000, temperature=1)
        
        if not response:
            print(f"[EnhancedThreatGen] ❌ Failed to get response from LLM")
            return []
        
        # Log response for debugging
        print(f"[EnhancedThreatGen] ✅ LLM response received, length: {len(response)} characters")
        if len(response) > 1000:
            print(f"[EnhancedThreatGen] Response preview (first 500 chars): {response[:500]}")
            print(f"[EnhancedThreatGen] Response preview (last 500 chars): {response[-500:]}")
        else:
            print(f"[EnhancedThreatGen] Full response: {response}")
        
        # Parse response
        threats = self._parse_threat_response(response, intel_items)
        
        if not threats:
            print(f"[EnhancedThreatGen] ⚠️  No threats generated from response")
            print(f"[EnhancedThreatGen] Full response for debugging:\n{response}")
        else:
            print(f"[EnhancedThreatGen] ✅ Successfully generated {len(threats)} threats")
        
        return threats
        
        # Log response for debugging
        print(f"[EnhancedThreatGen] LLM response length: {len(response)} characters")
        print(f"[EnhancedThreatGen] Response preview (first 500 chars): {response[:500]}")
        
        # Parse response
        threats = self._parse_threat_response(response, intel_items)
        
        if not threats:
            print(f"[EnhancedThreatGen] ⚠️  No threats generated. Full response (last 1000 chars): {response[-1000:]}")
        
        return threats
    
    def _prepare_intel_content(self, intel_items: List[Dict[str, Any]]) -> str:
        """Prepare intelligence content for LLM prompt with classification hints
        
        This method ensures ALL intelligence data is included in the prompt:
        - Title, content, AI summary
        - Source information
        - Classification metadata
        - All available intelligence fields
        """
        content_parts = []
        
        # Add classification hints at the beginning
        content_parts.append("""
=== CRITICAL CLASSIFICATION GUIDELINES FOR MCP WORKFLOW PHASES ===

RESPONSE HANDLING PHASE - Use this phase if the threat involves ANY of the following:
- Manipulating or exploiting tool responses/outputs
- User impersonation through tool responses
- Fake errors in tool responses
- Data exfiltration through tool responses
- Context injection from tool outputs
- Retrieval injection (malicious content in retrieved data)
- Any attack that occurs AFTER a tool has been invoked and returns a response
- Attacks that exploit the trust LLMs place in tool responses

TASK PLANNING PHASE - Use for attacks during initial prompt/instruction phase:
- Prompt injection
- Preference manipulation
- Name collision
- Tool shadowing
- Schema inconsistencies

TOOL INVOCATION PHASE - Use for attacks during tool call/execution phase:
- Out-of-scope parameter
- Tool poisoning
- Unauthorized access
- Privilege escalation
- Sandbox escape

CROSS-PHASE - Use for attacks spanning multiple phases or systemic issues:
- Mixed attacks
- Supply chain attacks
- Configuration weaknesses
- Vulnerability exploitation

=== END OF CLASSIFICATION GUIDELINES ===

""")
        
        print(f"[EnhancedThreatGen] Preparing content from {len(intel_items)} intel items for LLM analysis...")
        
        for i, item in enumerate(intel_items, 1):
            intel_id = item.get('id', f'item_{i}')
            title = item.get('title', 'Untitled')
            content = item.get('content', '')
            ai_summary = item.get('ai_summary', '')
            source = item.get('source', 'Unknown')
            source_url = item.get('source_url', item.get('url', ''))
            source_type = item.get('source_type', 'Unknown')
            
            part = f"Intelligence Item {i} (ID: {intel_id}):\n"
            part += f"Title: {title}\n"
            part += f"Source: {source} ({source_type})\n"
            if source_url:
                part += f"URL: {source_url}\n"
            
            # Include ALL available intelligence content
            if ai_summary:
                part += f"AI Summary: {ai_summary}\n"
            if content:
                # Include full content (truncate if too long to avoid token limits)
                content_preview = content[:2000] if len(content) > 2000 else content
                part += f"Content: {content_preview}\n"
                if len(content) > 2000:
                    part += f"[Content truncated, original length: {len(content)} characters]\n"
            
            # Add classification hints if available
            classification = item.get('_classification')
            if classification:
                part += "Classification Hints:\n"
                if classification.workflow_phase:
                    part += f"  - Workflow Phase: {classification.workflow_phase.value}\n"
                if classification.msb_attack_type:
                    part += f"  - MSB Attack Type: {classification.msb_attack_type.value}\n"
                if classification.mcp_upd_phase:
                    part += f"  - MCP-UPD Phase: {classification.mcp_upd_phase.value}\n"
                if classification.mcp_upd_tools:
                    part += f"  - MCP-UPD Tools: {[t.value for t in classification.mcp_upd_tools]}\n"
                if classification.mpma_type:
                    part += f"  - MPMA Type: {classification.mpma_type.value}\n"
                if classification.gapma_strategy:
                    part += f"  - GAPMA Strategy: {classification.gapma_strategy.value}\n"
                part += f"  - Confidence: {classification.confidence:.2f}\n"
            
            if ai_summary:
                part += f"Summary: {ai_summary}\n"
            elif content:
                # Truncate content if too long
                content_preview = content[:2000] if len(content) > 2000 else content
                part += f"Content: {content_preview}\n"
            part += "\n"
            
            content_parts.append(part)
        
        return "\n".join(content_parts)
    
    def _parse_threat_response(self, response: str, intel_items: List[Dict[str, Any]]) -> List[EnhancedMCPThreat]:
        """Parse LLM response into EnhancedMCPThreat objects"""
        threats = []
        
        try:
            # Try to extract JSON from response
            json_str = self._extract_json_from_response(response)
            if not json_str:
                print(f"[EnhancedThreatGen] Could not extract JSON from response")
                print(f"[EnhancedThreatGen] Attempting to find JSON array directly...")
                # Try to find JSON array instead of object
                array_start = response.find('[')
                if array_start >= 0:
                    # Try to extract array
                    bracket_count = 0
                    for i in range(array_start, len(response)):
                        if response[i] == '[':
                            bracket_count += 1
                        elif response[i] == ']':
                            bracket_count -= 1
                            if bracket_count == 0:
                                json_str = response[array_start:i+1]
                                print(f"[EnhancedThreatGen] Found JSON array, length: {len(json_str)}")
                                break
                
                if not json_str:
                    # Last resort: try to extract any JSON-like structure
                    print(f"[EnhancedThreatGen] Trying to extract any JSON structure...")
                    # Look for "threats" key
                    threats_key_pos = response.find('"threats"')
                    if threats_key_pos >= 0:
                        # Try to extract from "threats" key onwards
                        start = response.find('{', threats_key_pos - 50)
                        if start >= 0:
                            brace_count = 0
                            for i in range(start, len(response)):
                                if response[i] == '{':
                                    brace_count += 1
                                elif response[i] == '}':
                                    brace_count -= 1
                                    if brace_count == 0:
                                        json_str = response[start:i+1]
                                        print(f"[EnhancedThreatGen] Extracted JSON from 'threats' key")
                                        break
                
                if not json_str:
                    print(f"[EnhancedThreatGen] ❌ Could not extract any JSON structure from response")
                    print(f"[EnhancedThreatGen] Response sample (middle 1000 chars): {response[len(response)//2-500:len(response)//2+500] if len(response) > 1000 else response}")
                    return []
            
            # Try to parse JSON
            try:
                data = json.loads(json_str)
            except json.JSONDecodeError as json_err:
                print(f"[EnhancedThreatGen] JSON decode error: {json_err}")
                print(f"[EnhancedThreatGen] JSON string preview: {json_str[:500]}")
                # Try to fix common JSON issues
                json_str_fixed = self._fix_json_string(json_str)
                if json_str_fixed:
                    try:
                        data = json.loads(json_str_fixed)
                        print(f"[EnhancedThreatGen] ✅ Successfully parsed after fixing JSON")
                    except:
                        print(f"[EnhancedThreatGen] ❌ Still failed after fixing")
                        return []
                else:
                    return []
            
            # Get threats array - handle both {"threats": [...]} and direct array
            if isinstance(data, list):
                threats_data = data
                print(f"[EnhancedThreatGen] Response is a direct array with {len(threats_data)} items")
            elif isinstance(data, dict):
                threats_data = data.get('threats', [])
                if not threats_data:
                    # Try other possible keys
                    for key in ['threat', 'threat_models', 'results']:
                        if key in data:
                            threats_data = data[key] if isinstance(data[key], list) else [data[key]]
                            print(f"[EnhancedThreatGen] Found threats under key '{key}'")
                            break
            else:
                print(f"[EnhancedThreatGen] Unexpected data type: {type(data)}")
                return []
            
            if not threats_data:
                print(f"[EnhancedThreatGen] ⚠️  No threats found in parsed JSON")
                if isinstance(data, dict):
                    print(f"[EnhancedThreatGen] Parsed data keys: {list(data.keys())}")
                return []
            
            print(f"[EnhancedThreatGen] ✅ Found {len(threats_data)} threat(s) in response")
            
            # Collect intel IDs
            intel_ids = [str(item.get('id', '')) for item in intel_items]
            
            # Convert each threat
            for threat_data in threats_data:
                try:
                    # Ensure source_intel_ids is set - use from threat_data if provided, otherwise use all intel_ids
                    if 'source_intel_ids' not in threat_data or not threat_data['source_intel_ids']:
                        threat_data['source_intel_ids'] = intel_ids
                    elif isinstance(threat_data['source_intel_ids'], str):
                        # Convert string to array if needed
                        try:
                            threat_data['source_intel_ids'] = json.loads(threat_data['source_intel_ids'])
                        except:
                            threat_data['source_intel_ids'] = [threat_data['source_intel_ids']]
                    
                    threat = self._create_threat_from_data(threat_data, intel_ids)
                    threats.append(threat)
                except Exception as e:
                    print(f"[EnhancedThreatGen] Error creating threat: {e}")
                    continue
            
        except json.JSONDecodeError as e:
            print(f"[EnhancedThreatGen] JSON parse error: {e}")
            print(f"[EnhancedThreatGen] Response preview: {response[:500]}")
        except Exception as e:
            print(f"[EnhancedThreatGen] Error parsing response: {e}")
        
        return threats
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
        """Extract JSON from LLM response (may contain markdown, text, etc.)"""
        # Remove markdown code blocks
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            if end > start:
                return response[start:end].strip()
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            if end > start:
                return response[start:end].strip()
        
        # Try to find JSON object
        start = response.find("{")
        if start >= 0:
            # Find matching closing brace
            brace_count = 0
            for i in range(start, len(response)):
                if response[i] == '{':
                    brace_count += 1
                elif response[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        return response[start:i+1]
        
        return None
    
    def _fix_json_string(self, json_str: str) -> Optional[str]:
        """Try to fix common JSON issues"""
        try:
            # Remove trailing commas before closing braces/brackets
            import re
            # Fix trailing commas
            json_str = re.sub(r',\s*}', '}', json_str)
            json_str = re.sub(r',\s*]', ']', json_str)
            
            # Try to close unclosed strings
            # This is a simple heuristic - may not work for all cases
            if json_str.count('"') % 2 != 0:
                # Odd number of quotes - try to close the last string
                last_quote = json_str.rfind('"')
                if last_quote > 0 and json_str[last_quote-1] != '\\':
                    # Check if we need to close it
                    after_quote = json_str[last_quote+1:].strip()
                    if after_quote and not after_quote.startswith((':', ',', '}', ']')):
                        # Likely unclosed string, try to close it
                        json_str = json_str[:last_quote+1] + '"' + json_str[last_quote+1:]
            
            return json_str
        except Exception as e:
            print(f"[EnhancedThreatGen] Error fixing JSON: {e}")
            return None
    
    def _create_threat_from_data(self, threat_data: Dict[str, Any], intel_ids: List[str]) -> EnhancedMCPThreat:
        """Create EnhancedMCPThreat from parsed data"""
        
        # CRITICAL: Ensure mcp_workflow_phase and msb_attack_type are set
        # If missing, try to infer from other fields or set defaults
        if not threat_data.get('mcp_workflow_phase'):
            # Try to infer from description or other fields
            description = (threat_data.get('description', '') or '').lower()
            name = (threat_data.get('name', '') or '').lower()
            
            # Infer workflow phase using new 8-phase model
            if any(keyword in description or keyword in name for keyword in ['response', 'output', 'tool response', 'exfiltration', 'impersonation', 'output processing']):
                threat_data['mcp_workflow_phase'] = 'Response Handling / Output Processing'
            elif any(keyword in description or keyword in name for keyword in ['execution', 'runtime', 'external resource', 'command injection', 'path traversal', 'ssrf', 'sandbox escape']):
                threat_data['mcp_workflow_phase'] = 'Tool Execution / Runtime / External Resource Interaction'
            elif any(keyword in description or keyword in name for keyword in ['invocation', 'parameter', 'tool call', 'call request', 'parameter abuse']):
                threat_data['mcp_workflow_phase'] = 'Tool Invocation / Call Request'
            elif any(keyword in description or keyword in name for keyword in ['tool chain', 'orchestration', 'multi-tool', 'parasitic chain', 'workflow']):
                threat_data['mcp_workflow_phase'] = 'Tool-Chain Orchestration / Multi-Tool Workflow'
            elif any(keyword in description or keyword in name for keyword in ['definition', 'registration', 'tool creation', 'code signing', 'schema definition']):
                threat_data['mcp_workflow_phase'] = 'Tool Definition / Registration'
            elif any(keyword in description or keyword in name for keyword in ['catalog', 'discovery', 'metadata exposure', 'tool discovery']):
                threat_data['mcp_workflow_phase'] = 'Tool Catalog / Discovery / Metadata Exposure'
            elif any(keyword in description or keyword in name for keyword in ['supply chain', 'dependency', 'update', 'deployment', 'pipeline']):
                threat_data['mcp_workflow_phase'] = 'Supply-Chain / Dependency / Update / Deployment'
            elif any(keyword in description or keyword in name for keyword in ['infrastructure', 'configuration', 'deployment environment', 'environment variable']):
                threat_data['mcp_workflow_phase'] = 'Infrastructure / Configuration / Deployment Environment'
            else:
                threat_data['mcp_workflow_phase'] = 'Tool-Chain Orchestration / Multi-Tool Workflow'  # Default
            
            print(f"[EnhancedThreatGen] ⚠️  mcp_workflow_phase was missing, inferred as: {threat_data['mcp_workflow_phase']}")
        
        if not threat_data.get('msb_attack_type'):
            # Try to infer from workflow phase and description
            phase = threat_data.get('mcp_workflow_phase', '').lower()
            description = (threat_data.get('description', '') or '').lower()
            name = (threat_data.get('name', '') or '').lower()
            
            # Infer attack type based on new 8-phase model
            phase_lower = phase.lower()
            
            if 'response handling' in phase_lower or 'output processing' in phase_lower:
                if 'exfiltration' in description or 'exfiltration' in name or 'data leak' in description:
                    threat_data['msb_attack_type'] = 'Data Exfiltration / Sensitive Data Leakage'
                elif 'impersonation' in description or 'impersonation' in name:
                    threat_data['msb_attack_type'] = 'User Impersonation'
                elif 'fake error' in description or 'fake error' in name:
                    threat_data['msb_attack_type'] = 'Fake Error'
                elif 'retrieval' in description or 'retrieval' in name:
                    threat_data['msb_attack_type'] = 'Retrieval Injection'
                elif 'context' in description or 'state poisoning' in description:
                    threat_data['msb_attack_type'] = 'Context / State Poisoning / Persistent Context Abuse'
                else:
                    threat_data['msb_attack_type'] = 'Output Manipulation'
            elif 'tool execution' in phase_lower or 'runtime' in phase_lower:
                if 'command injection' in description or 'code injection' in description or 'rce' in description:
                    threat_data['msb_attack_type'] = 'Command Injection / Code Injection / RCE via Tool'
                elif 'path traversal' in description or 'filesystem' in description:
                    threat_data['msb_attack_type'] = 'Path Traversal / Filesystem Abuse'
                elif 'ssrf' in description or 'network' in description or 'external api' in description:
                    threat_data['msb_attack_type'] = 'Network / External API Abuse / SSRF / Exfiltration'
                elif 'resource abuse' in description or 'dos' in description or 'denial of service' in description:
                    threat_data['msb_attack_type'] = 'Resource Abuse / Compute Hijack / Denial-of-Service'
                elif 'privilege' in description or 'authorization bypass' in description:
                    threat_data['msb_attack_type'] = 'Privilege Escalation / Authorization Bypass'
                elif 'sandbox escape' in description:
                    threat_data['msb_attack_type'] = 'Sandbox Escape'
                else:
                    threat_data['msb_attack_type'] = 'Command Injection / Code Injection / RCE via Tool'
            elif 'tool invocation' in phase_lower or 'call request' in phase_lower:
                if 'parameter abuse' in description or 'out-of-scope' in description:
                    threat_data['msb_attack_type'] = 'Parameter Abuse / Out-of-Scope Argument'
                elif 'prompt injection' in description:
                    threat_data['msb_attack_type'] = 'Prompt Injection (in metadata / tool description / user input)'
                elif 'tool-call injection' in description:
                    threat_data['msb_attack_type'] = 'Tool-Call Injection'
                elif 'schema' in description or 'constraint bypass' in description:
                    threat_data['msb_attack_type'] = 'Schema Constraint Bypass'
                elif 'type confusion' in description:
                    threat_data['msb_attack_type'] = 'Type Confusion'
                else:
                    threat_data['msb_attack_type'] = 'Parameter Abuse / Out-of-Scope Argument'
            elif 'tool definition' in phase_lower or 'registration' in phase_lower:
                if 'tool poisoning' in description or 'malicious tool' in description:
                    threat_data['msb_attack_type'] = 'Tool Poisoning / Malicious Tool'
                elif 'name collision' in description or 'tool spoofing' in description:
                    threat_data['msb_attack_type'] = 'Name-Collision / Tool Spoofing'
                elif 'metadata poisoning' in description or 'description poisoning' in description:
                    threat_data['msb_attack_type'] = 'Metadata / Description Poisoning'
                elif 'code signing' in description:
                    threat_data['msb_attack_type'] = 'Code Signing Bypass'
                else:
                    threat_data['msb_attack_type'] = 'Schema Inconsistencies'
            elif 'tool catalog' in phase_lower or 'discovery' in phase_lower:
                if 'metadata poisoning' in description:
                    threat_data['msb_attack_type'] = 'Metadata Poisoning'
                elif 'catalog manipulation' in description:
                    threat_data['msb_attack_type'] = 'Catalog Manipulation'
                elif 'information disclosure' in description:
                    threat_data['msb_attack_type'] = 'Information Disclosure'
                else:
                    threat_data['msb_attack_type'] = 'Catalog Injection'
            elif 'tool-chain' in phase_lower or 'orchestration' in phase_lower:
                if 'parasitic chain' in description:
                    threat_data['msb_attack_type'] = 'Tool-to-Tool Parasitic Chaining'
                elif 'orchestration' in description:
                    threat_data['msb_attack_type'] = 'Orchestration Abuse'
                elif 'workflow manipulation' in description:
                    threat_data['msb_attack_type'] = 'Workflow Manipulation'
                else:
                    threat_data['msb_attack_type'] = 'Multi-Tool Attack'
            elif 'supply chain' in phase_lower or 'dependency' in phase_lower:
                threat_data['msb_attack_type'] = 'Supply-Chain / Dependency Attack / Rogue Update'
            elif 'infrastructure' in phase_lower or 'configuration' in phase_lower:
                threat_data['msb_attack_type'] = 'Configuration / Misconfiguration / Exposure'
            else:
                threat_data['msb_attack_type'] = 'Mixed Attack'
            
            print(f"[EnhancedThreatGen] ⚠️  msb_attack_type was missing, inferred as: {threat_data['msb_attack_type']}")
        
        # Map threat vector
        threat_vector_str = threat_data.get('threat_vector', 'Prompt-based Attacks / Injection')
        try:
            threat_vector = ThreatVector(threat_vector_str)
        except ValueError:
            threat_vector = ThreatVector.PROMPT_BASED_ATTACKS
        
        # Map severity
        severity_str = threat_data.get('severity', 'medium').lower()
        try:
            severity = RiskLevel(severity_str)
        except ValueError:
            severity = RiskLevel.MEDIUM
        
        # Map workflow phase
        workflow_phase = None
        if 'mcp_workflow_phase' in threat_data:
            try:
                workflow_phase = MCPWorkflowPhase(threat_data['mcp_workflow_phase'])
            except ValueError:
                pass
        
        # Map MSB attack type
        msb_attack_type = None
        if 'msb_attack_type' in threat_data:
            try:
                msb_attack_type = MSBAttackType(threat_data['msb_attack_type'])
            except ValueError:
                pass
        
        # Validate raw MCP-UPD data involved in parsing
        if 'mcp_upd_phase' in threat_data:
            print(f"[EnhancedThreatGen] Raw mcp_upd_phase: {threat_data['mcp_upd_phase']}")
        if 'mcp_upd_tools' in threat_data:
            print(f"[EnhancedThreatGen] Raw mcp_upd_tools: {threat_data['mcp_upd_tools']}")

        # Map MCP-UPD phase
        mcp_upd_phase = None
        if 'mcp_upd_phase' in threat_data and threat_data['mcp_upd_phase']:
            try:
                mcp_upd_phase = MCPUPDAttackPhase(threat_data['mcp_upd_phase'])
            except ValueError:
                pass
        
        # Map MCP-UPD tools
        mcp_upd_tools = []
        if 'mcp_upd_tools' in threat_data and threat_data['mcp_upd_tools']:
            for tool_str in threat_data['mcp_upd_tools']:
                try:
                    mcp_upd_tools.append(MCPUPDAttackTool(tool_str))
                except ValueError:
                    pass
        
        # Map MPMA type
        mpma_type = None
        if 'mpma_attack_type' in threat_data and threat_data['mpma_attack_type']:
            try:
                mpma_type = MPMAAttackType(threat_data['mpma_attack_type'])
            except ValueError:
                pass
        
        # Map GAPMA strategy
        gapma_strategy = None
        if 'gapma_strategy' in threat_data and threat_data['gapma_strategy']:
            try:
                gapma_strategy = GAPMAStrategy(threat_data['gapma_strategy'])
            except ValueError:
                pass
        
        # Extract MCPSecBench classification
        mcp_surface = threat_data.get('mcp_surface')
        mcpsecbench_attack_type = threat_data.get('mcpsecbench_attack_type')
        mcpsecbench_severity = threat_data.get('mcpsecbench_severity')
        
        # If MCPSecBench fields are missing, try to infer from other classifications
        # Use config-based keyword matching (business logic for intel matching)
        if not mcp_surface:
            phase = threat_data.get('mcp_workflow_phase', '')
            description = threat_data.get('description', '') or ''
            
            # Try to infer from description first
            inferred_surface = self.mcpsecbench_config.get_surface_by_keyword(description)
            if not inferred_surface:
                # Try from workflow phase
                inferred_surface = self.mcpsecbench_config.get_surface_by_keyword(phase)
            
            mcp_surface = inferred_surface or self.mcpsecbench_config.get_default_surface()
        
        if not mcpsecbench_attack_type:
            msb_type = threat_data.get('msb_attack_type', '')
            description = threat_data.get('description', '') or ''
            
            # Use config-based keyword matching (business logic for intel matching)
            combined_text = f"{msb_type} {description}".lower()
            inferred_attack_type = self.mcpsecbench_config.get_attack_type_by_keyword(combined_text)
            
            mcpsecbench_attack_type = inferred_attack_type or self.mcpsecbench_config.get_default_attack_type()
        
        if not mcpsecbench_severity:
            # Infer severity from risk_score
            risk_score = threat_data.get('risk_score', 5.0)
            if risk_score >= 9.0:
                mcpsecbench_severity = 10
            elif risk_score >= 7.0:
                mcpsecbench_severity = 8
            elif risk_score >= 5.0:
                mcpsecbench_severity = 6
            else:
                mcpsecbench_severity = 4
        
        # Create attack steps
        attack_steps = []
        if 'attack_steps' in threat_data:
            for step_data in threat_data['attack_steps']:
                if isinstance(step_data, dict):
                    attack_steps.append(AttackStep(**step_data))
        
        # Create detection methods
        detection_methods = []
        if 'detection_methods' in threat_data:
            for method_data in threat_data['detection_methods']:
                if isinstance(method_data, dict):
                    detection_methods.append(DetectionMethod(**method_data))
        
        # Create mitigation controls
        recommended_controls = []
        if 'recommended_controls' in threat_data:
            for control_data in threat_data['recommended_controls']:
                if isinstance(control_data, dict):
                    recommended_controls.append(MitigationControl(**control_data))
        
        # Create references
        references = []
        if 'references' in threat_data:
            for ref_data in threat_data['references']:
                if isinstance(ref_data, dict):
                    references.append(Reference(**ref_data))
        
        # Create threat
        threat = EnhancedMCPThreat(
            name=threat_data.get('name', 'Unknown Threat'),
            title=threat_data.get('title', threat_data.get('name', 'Unknown Threat')),
            description=threat_data.get('description', ''),
            threat_vector=threat_vector,
            stride_category=threat_data.get('stride_category', 'Tampering'),
            mcp_workflow_phase=workflow_phase,
            msb_attack_type=msb_attack_type,
            mcp_upd_phase=mcp_upd_phase,
            mcp_upd_tools=mcp_upd_tools,
            mpma_attack_type=mpma_type,
            gapma_strategy=gapma_strategy,
            preconditions=threat_data.get('preconditions', []),
            assets_at_risk=threat_data.get('assets_at_risk', []),
            impact=threat_data.get('impact', []),
            attack_steps=attack_steps,
            exploit_steps=threat_data.get('exploit_steps', []),
            detection_methods=detection_methods,
            warning_signs=threat_data.get('warning_signs', []),
            mitigations=threat_data.get('mitigations', []),
            recommended_controls=recommended_controls,
            severity=severity,
            risk_score=float(threat_data.get('risk_score', 7.0)),
            cvss_score=threat_data.get('cvss_score'),
            asr_score=threat_data.get('asr_score'),  # Attack Success Rate
            nrp_score=threat_data.get('nrp_score'),  # Net Resilient Performance
            likelihood=threat_data.get('likelihood', 'medium'),
            status=ThreatStatus.UNEVALUATED,
            references=references,
            source="ai_generated",
            source_intel_ids=threat_data.get('source_intel_ids', intel_ids),
            tags=threat_data.get('tags', [])
        )
        
        # Add MCPSecBench fields to threat metadata for database saving
        threat.metadata['mcp_surface'] = mcp_surface
        threat.metadata['mcpsecbench_attack_type'] = mcpsecbench_attack_type
        threat.metadata['mcpsecbench_severity'] = mcpsecbench_severity
        
        # Classify threat to MCP Threat IDs (MCP-01 to MCP-38)
        mcp_threat_ids = MCPThreatClassifier.classify_threat(
            threat_name=threat.name,
            threat_description=threat.description,
            attack_vector=threat_data.get('threat_vector') or (threat_vector.value if threat_vector else None),
            stride_category=threat.stride_category,
            msb_attack_type=threat_data.get('msb_attack_type') or (msb_attack_type.value if msb_attack_type else None),
            mcp_workflow_phase=threat_data.get('mcp_workflow_phase') or (workflow_phase.value if workflow_phase else None)
        )
        threat.metadata['mcp_threat_ids'] = mcp_threat_ids
        
        return threat
    
    def _save_threats_to_db(self, threats: List[EnhancedMCPThreat], project_id: Optional[str]) -> int:
        """Save threats to database with full MCP classification"""
        if not self.db_manager:
            return 0
        
        saved_count = 0
        
        for threat in threats:
            try:
                # Convert EnhancedMCPThreat to database format
                threat_dict = threat.to_dict()
                
                # Store all enhanced fields in schema_data
                schema_data = {
                    # MCP Workflow Classification
                    'mcp_workflow_phase': threat_dict.get('mcp_workflow_phase'),
                    'msb_attack_type': threat_dict.get('msb_attack_type'),
                    
                    # MCPSecBench Classification (4×17 matrix)
                    'mcp_surface': threat_dict.get('mcp_surface'),
                    'mcpsecbench_attack_type': threat_dict.get('mcpsecbench_attack_type'),
                    'mcpsecbench_severity': threat_dict.get('mcpsecbench_severity'),
                    
                    # MCP Threat ID Classification (MCP-01 to MCP-38)
                    'mcp_threat_ids': threat_dict.get('mcp_threat_ids', []),
                    
                    # MCP-UPD Classification
                    'mcp_upd_phase': threat_dict.get('mcp_upd_phase'),
                    'mcp_upd_tools': threat_dict.get('mcp_upd_tools', []),
                    
                    # MPMA Classification
                    'mpma_attack_type': threat_dict.get('mpma_attack_type'),
                    'gapma_strategy': threat_dict.get('gapma_strategy'),
                    
                    # Enhanced fields
                    'threat_vector': threat_dict.get('threat_vector'),
                    'attack_steps': threat_dict.get('attack_steps', []),
                    'detection_methods': threat_dict.get('detection_methods', []),
                    'recommended_controls': threat_dict.get('recommended_controls', []),
                    'references': threat_dict.get('references', []),
                    'preconditions': threat_dict.get('preconditions', []),
                    'assets_at_risk': threat_dict.get('assets_at_risk', []),
                    'affected_components': threat_dict.get('affected_components', []),
                    'warning_signs': threat_dict.get('warning_signs', []),
                    'exploit_steps': threat_dict.get('exploit_steps', []),
                    
                    # Metrics
                    'asr_score': threat_dict.get('asr_score'),
                    'nrp_score': threat_dict.get('nrp_score'),
                    'pua_score': threat_dict.get('pua_score'),
                    
                    # Source tracking
                    'source_intel_ids': threat_dict.get('source_intel_ids', []),
                }
                
                # Prepare threat data for database
                # Note: threat_dict was already created above
                threat_data_dict = {
                    'name': threat.name,
                    'description': threat.description,
                    'stride_category': threat.stride_category,
                    'attack_vector': json.dumps(threat_dict.get('attack_steps', [])),
                    'impact': json.dumps(threat.impact),
                    'likelihood': threat.likelihood,
                    'risk_level': threat.severity.value,
                    'risk_score': threat.risk_score,
                    'source': "ai_generated",
                    'status': threat.status.value,
                    'is_mitigated': threat.is_mitigated,
                    'tags': threat.tags,
                    'schema_data': schema_data,  # Store full enhanced schema with MCP classifications
                    # MCP Workflow Phase Classification
                    'mcp_workflow_phase': threat.mcp_workflow_phase.value if threat.mcp_workflow_phase else None,
                    'msb_attack_type': threat.msb_attack_type.value if threat.msb_attack_type else None,
                    # MCPSecBench Classification (4×17 matrix)
                    'mcp_surface': threat_dict.get('mcp_surface'),
                    'mcpsecbench_attack_type': threat_dict.get('mcpsecbench_attack_type'),
                    'mcpsecbench_severity': threat_dict.get('mcpsecbench_severity'),
                    # MCP Threat ID Classification (MCP-01 to MCP-38)
                    'mcp_threat_ids': threat_dict.get('mcp_threat_ids', []),
                    # MCP-UPD Classification
                    'mcp_upd_phase': threat.mcp_upd_phase.value if threat.mcp_upd_phase else None,
                    'mcp_upd_tools': [t.value for t in threat.mcp_upd_tools] if threat.mcp_upd_tools else [],
                    # MPMA Classification
                    'mpma_attack_type': threat.mpma_attack_type.value if threat.mpma_attack_type else None,
                    'gapma_strategy': threat.gapma_strategy.value if threat.gapma_strategy else None,
                    # NRP Metrics
                    'asr_score': threat.asr_score,
                    'pua_score': threat.pua_score,
                    'nrp_score': threat.nrp_score,
                }
                
                # Create threat in database
                db_threat = self.db_manager.create_threat(threat_data_dict, project_id=project_id or 'default-project')
                
                if db_threat:
                    saved_count += 1
                    
                    # Mark intel items as processed (optional, for tracking)
                    # This helps avoid reprocessing in future runs
                    if threat.source_intel_ids and self.db_manager:
                        try:
                            from database.models import IntelItem
                            session = self.db_manager.get_session()
                            try:
                                for intel_id in threat.source_intel_ids:
                                    intel_item = session.query(IntelItem).filter(IntelItem.id == str(intel_id)).first()
                                    if intel_item:
                                        intel_item.is_converted = True
                                        intel_item.converted_threat_id = db_threat.id
                                session.commit()
                            except Exception as e:
                                session.rollback()
                                print(f"[EnhancedThreatGen] Warning: Could not mark intel items as processed: {e}")
                            finally:
                                session.close()
                        except ImportError:
                            pass  # IntelItem model not available
                    
                    # Auto-bind intelligence (CVE, IOC, Jailbreak history)
                    try:
                        from core.intelligence_binder import IntelligenceBinder, ComponentInfo
                        binder = IntelligenceBinder(db_manager=self.db_manager)
                        
                        # Extract component info from threat
                        components = []
                        affected_components = threat_dict.get('affected_components', [])
                        for comp_name in affected_components:
                            components.append(ComponentInfo(
                                name=comp_name,
                                type='unknown',
                                capabilities=threat_dict.get('assets_at_risk', [])
                            ))
                        
                        # Bind intelligence to threat
                        intel_matches = binder.bind_intelligence_to_threat(
                            threat=threat_dict,
                            components=components if components else None
                        )
                        
                        # Save bindings to database
                        if intel_matches:
                            binder.bind_to_threat_in_db(db_threat.id, intel_matches)
                            print(f"[EnhancedThreatGen] ✅ Bound {len(intel_matches)} intelligence items to threat {db_threat.id}")
                    except ImportError:
                        pass  # IntelligenceBinder not available
                    except Exception as e:
                        print(f"[EnhancedThreatGen] Warning: Could not bind intelligence: {e}")
                    
            except Exception as e:
                print(f"[EnhancedThreatGen] Error saving threat to DB: {e}")
                continue
        
        return saved_count

