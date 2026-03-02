"""
Intelligence-Driven Threat Modeling

Automatically generates threat models from collected intelligence items.
Uses AI to analyze intelligence and create structured threat, asset, and control entries.
"""

from __future__ import annotations

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

from config.llm_config import get_llm_config
from config.model_selector import get_model_selector, ModelProvider
from database.db_manager import DatabaseManager


@dataclass
class GeneratedThreat:
    """Generated threat from intelligence"""
    name: str
    description: str
    stride_category: str
    attack_vector: str
    impact: str
    likelihood: str
    risk_level: str
    risk_score: float
    source_intel_ids: List[str]
    affected_assets: List[str]
    recommended_controls: List[str]
    metadata: Dict[str, Any]


@dataclass
class GeneratedAsset:
    """Generated asset from intelligence"""
    name: str
    asset_type: str
    description: str
    criticality: str
    source_intel_ids: List[str]
    metadata: Dict[str, Any]


class IntelThreatGenerator:
    """
    Generates threat models from intelligence items.
    
    Uses AI to:
    1. Extract threats from intelligence content
    2. Identify affected assets
    3. Recommend security controls
    4. Map to STRIDE categories
    5. Assess risk levels
    """
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None, llm_config=None, model_selection=None):
        """Initialize the threat generator"""
        self.db_manager = db_manager
        self.llm_config = llm_config or get_llm_config()
        # Get model selection from global selector if not provided
        if model_selection is None:
            try:
                selector = get_model_selector()
                self.model_selection = selector.get_selection() or selector.load_config()
            except:
                self.model_selection = None
        else:
            self.model_selection = model_selection
    
    def generate_threats_from_intel(
        self,
        intel_items: List[Dict[str, Any]],
        project_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate threats from intelligence items.
        
        Args:
            intel_items: List of intelligence item dictionaries
            project_id: Optional project ID to associate threats with
        
        Returns:
            Dictionary with generated threats, assets, and controls
        """
        if not intel_items:
            return {
                "threats": [],
                "assets": [],
                "controls": [],
                "message": "No intelligence items provided"
            }
        
        print(f"[IntelThreatGen] Generating threats from {len(intel_items)} intel items...")
        
        # Group intel items by topic/theme
        grouped_intel = self._group_intel_by_topic(intel_items)
        
        generated_threats = []
        generated_assets = []
        generated_controls = []
        
        # Process each group
        print(f"[IntelThreatGen] Processing {len(grouped_intel)} topic groups...")
        for topic, items in grouped_intel.items():
            print(f"[IntelThreatGen] Processing topic '{topic}' with {len(items)} items...")
            # Combine content from related items
            combined_content = self._combine_intel_content(items)
            
            # Generate threats from this topic
            threats = self._extract_threats_from_content(combined_content, items)
            print(f"[IntelThreatGen] Extracted {len(threats)} threats from topic '{topic}'")
            generated_threats.extend(threats)
            
            # Extract assets
            assets = self._extract_assets_from_content(combined_content, items)
            generated_assets.extend(assets)
            
            # Generate controls
            controls = self._generate_controls_for_threats(threats, combined_content)
            generated_controls.extend(controls)
        
        print(f"[IntelThreatGen] Total extracted: {len(generated_threats)} threats, {len(generated_assets)} assets, {len(generated_controls)} controls")
        
        # Deduplicate and merge
        merged_threats = self._merge_threats(generated_threats)
        merged_assets = self._merge_assets(generated_assets)
        merged_controls = self._merge_controls(generated_controls)
        
        return {
            "threats": [self._threat_to_dict(t) for t in merged_threats],
            "assets": [self._asset_to_dict(a) for a in merged_assets],
            "controls": merged_controls,
            "stats": {
                "threats_count": len(merged_threats),
                "assets_count": len(merged_assets),
                "controls_count": len(merged_controls),
                "intel_items_processed": len(intel_items)
            }
        }
    
    def _group_intel_by_topic(self, intel_items: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group intelligence items by topic/theme"""
        # Simple grouping by keywords
        groups = {}
        
        for item in intel_items:
            content = (item.get('ai_summary') or item.get('content') or '').lower()
            title = (item.get('title') or '').lower()
            
            # Determine topic
            topic = "general"
            if any(kw in content or kw in title for kw in ['injection', 'prompt injection']):
                topic = "prompt_injection"
            elif any(kw in content or kw in title for kw in ['tool', 'poisoning', 'tool poisoning']):
                topic = "tool_poisoning"
            elif any(kw in content or kw in title for kw in ['authentication', 'auth', 'credential']):
                topic = "authentication"
            elif any(kw in content or kw in title for kw in ['authorization', 'permission', 'access']):
                topic = "authorization"
            elif any(kw in content or kw in title for kw in ['data', 'leak', 'exposure', 'disclosure']):
                topic = "data_disclosure"
            elif any(kw in content or kw in title for kw in ['dos', 'denial', 'service', 'flooding']):
                topic = "denial_of_service"
            elif any(kw in content or kw in title for kw in ['server', 'mcp server']):
                topic = "mcp_server"
            elif any(kw in content or kw in title for kw in ['client', 'mcp client']):
                topic = "mcp_client"
            
            if topic not in groups:
                groups[topic] = []
            groups[topic].append(item)
        
        return groups
    
    def _combine_intel_content(self, items: List[Dict[str, Any]]) -> str:
        """Combine content from multiple intelligence items"""
        combined = []
        for item in items:
            title = item.get('title', '')
            summary = item.get('ai_summary', '')
            content = item.get('content', '')
            
            text = f"Title: {title}\n"
            if summary:
                text += f"Summary: {summary}\n"
            if content:
                text += f"Content: {content[:500]}\n"
            
            combined.append(text)
        
        return "\n---\n".join(combined)
    
    def _extract_threats_from_content(
        self,
        content: str,
        source_items: List[Dict[str, Any]]
    ) -> List[GeneratedThreat]:
        """Extract threats from content using AI"""
        threats = []
        
        try:
            # No content truncation - let LLM process full content for complete threat extraction
            # Build prompt for threat extraction with MCPSecBench classification
            prompt = f"""Analyze the following MCP security intelligence and extract security threats.

Intelligence Content:
{content}

For each threat identified, provide:
1. Threat name (concise, specific)
2. Description (detailed explanation)
3. STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
4. MCPSecBench Attack Surface (User Interaction, MCP Client, MCP Transport, MCP Server)
5. MCPSecBench Attack Type (one of: Prompt Injection, Tool Poisoning, Tool Shadowing, Data Exfiltration, Jailbreak, Schema Inconsistencies, Slash Command Overlap, MCP Rebinding, Man-in-the-Middle, Sandbox Escape, Unauthorized Access, Privilege Escalation, Denial of Service, Context Injection, Supply Chain Attack, Configuration Weakness, Vulnerability Exploitation)
6. Attack vector (how the attack is executed)
7. Impact (what happens if the attack succeeds)
8. Likelihood (Rare, Unlikely, Possible, Likely, Certain)
9. Risk level (Critical, High, Medium, Low, Info)
10. Risk score (0-10, where 10 is most critical)
11. Affected assets (MCP Server, MCP Client, Tools, Data, etc.)
12. Recommended controls (security measures to mitigate)

Return ONLY a JSON array with this structure:
[
    {{
        "name": "Threat Name",
        "description": "Detailed description",
        "stride_category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
        "attack_surface": "User Interaction|MCP Client|MCP Transport|MCP Server",
        "attack_type": "Prompt Injection|Tool Poisoning|Tool Shadowing|Data Exfiltration|Jailbreak|Schema Inconsistencies|Slash Command Overlap|MCP Rebinding|Man-in-the-Middle|Sandbox Escape|Unauthorized Access|Privilege Escalation|Denial of Service|Context Injection|Supply Chain Attack|Configuration Weakness|Vulnerability Exploitation",
        "attack_vector": "How attack is executed",
        "impact": "Impact description",
        "likelihood": "Rare|Unlikely|Possible|Likely|Certain",
        "risk_level": "Critical|High|Medium|Low|Info",
        "risk_score": 7.5,
        "affected_assets": ["MCP Server", "Tools"],
        "recommended_controls": ["Input validation", "Access control"]
    }}
]"""

            # Call LLM
            print(f"[IntelThreatGen] Calling LLM for threat extraction from {len(content)} chars of content...")
            response = self._call_llm(prompt)
            
            if not response:
                print(f"[IntelThreatGen] ⚠️ LLM returned None/empty response. All providers may have failed.")
                print(f"[IntelThreatGen] Check model configuration and API connectivity.")
                # Return empty list - let caller handle the error
                return []
            
            print(f"[IntelThreatGen] ✅ LLM response received ({len(response)} chars), parsing JSON...")
            
            if response:
                # Parse JSON response
                try:
                    # Clean response
                    response = response.strip()
                    if response.startswith("```"):
                        response = response.split("```")[1]
                        if response.startswith("json"):
                            response = response[4:]
                    response = response.strip()
                    
                    data = json.loads(response)
                    print(f"[IntelThreatGen] ✅ Successfully parsed {len(data)} threats from JSON")
                    
                    # Convert to GeneratedThreat objects
                    source_ids = [item.get('id', '') for item in source_items]
                    for threat_data in data:
                        # Extract MCPSecBench classification
                        attack_surface = threat_data.get('attack_surface', 'MCP Server')
                        attack_type = threat_data.get('attack_type', 'Vulnerability Exploitation')
                        
                        threat = GeneratedThreat(
                            name=threat_data.get('name', 'Unknown Threat'),
                            description=threat_data.get('description', ''),
                            stride_category=threat_data.get('stride_category', 'Information Disclosure'),
                            attack_vector=threat_data.get('attack_vector', ''),
                            impact=threat_data.get('impact', ''),
                            likelihood=threat_data.get('likelihood', 'Possible'),
                            risk_level=threat_data.get('risk_level', 'Medium'),
                            risk_score=float(threat_data.get('risk_score', 5.0)),
                            source_intel_ids=source_ids,
                            affected_assets=threat_data.get('affected_assets', []),
                            recommended_controls=threat_data.get('recommended_controls', []),
                            metadata={
                                'attack_surface': attack_surface,
                                'attack_type': attack_type
                            }
                        )
                        threats.append(threat)
                        
                except json.JSONDecodeError as e:
                    print(f"[IntelThreatGen] Failed to parse AI response: {e}")
                    print(f"[IntelThreatGen] Response: {response[:500]}")
                    
                    # Try to fix common JSON issues (unterminated strings, incomplete arrays)
                    try:
                        # Try to fix unterminated strings by closing them
                        if "Unterminated string" in str(e):
                            # Find the last complete object and try to parse it
                            last_complete = response.rfind('}')
                            if last_complete > 0:
                                # Try to extract complete objects
                                fixed_response = response[:last_complete + 1]
                                # Ensure it's a valid array
                                if not fixed_response.strip().startswith('['):
                                    fixed_response = '[' + fixed_response + ']'
                                else:
                                    # Close the array if needed
                                    if fixed_response.count('[') > fixed_response.count(']'):
                                        fixed_response = fixed_response.rstrip() + ']'
                                
                                data = json.loads(fixed_response)
                                print(f"[IntelThreatGen] ✅ Fixed JSON and parsed {len(data)} threats")
                                
                                # Convert to GeneratedThreat objects
                                source_ids = [item.get('id', '') for item in source_items]
                                for threat_data in data:
                                    attack_surface = threat_data.get('attack_surface', 'MCP Server')
                                    attack_type = threat_data.get('attack_type', 'Vulnerability Exploitation')
                                    
                                    threat = GeneratedThreat(
                                        name=threat_data.get('name', 'Unknown Threat'),
                                        description=threat_data.get('description', ''),
                                        stride_category=threat_data.get('stride_category', 'Information Disclosure'),
                                        attack_vector=threat_data.get('attack_vector', ''),
                                        impact=threat_data.get('impact', ''),
                                        likelihood=threat_data.get('likelihood', 'Possible'),
                                        risk_level=threat_data.get('risk_level', 'Medium'),
                                        risk_score=float(threat_data.get('risk_score', 5.0)),
                                        source_intel_ids=source_ids,
                                        affected_assets=threat_data.get('affected_assets', []),
                                        recommended_controls=threat_data.get('recommended_controls', []),
                                        metadata={
                                            'attack_surface': attack_surface,
                                            'attack_type': attack_type
                                        }
                                    )
                                    threats.append(threat)
                    except Exception as fix_error:
                        print(f"[IntelThreatGen] Could not fix JSON: {fix_error}")
        
        except Exception as e:
            print(f"[IntelThreatGen] Threat extraction error: {e}")
        
        return threats
    
    def _extract_assets_from_content(
        self,
        content: str,
        source_items: List[Dict[str, Any]]
    ) -> List[GeneratedAsset]:
        """Extract assets from content"""
        assets = []
        
        # Simple asset extraction based on keywords
        asset_keywords = {
            "MCP Server": ["mcp server", "server", "backend"],
            "MCP Client": ["mcp client", "client", "frontend"],
            "Tools": ["tool", "mcp tool", "function"],
            "Data": ["data", "information", "content"],
            "Credentials": ["credential", "key", "token", "password"],
            "Network": ["network", "transport", "connection"]
        }
        
        content_lower = content.lower()
        source_ids = [item.get('id', '') for item in source_items]
        
        for asset_type, keywords in asset_keywords.items():
            if any(kw in content_lower for kw in keywords):
                asset = GeneratedAsset(
                    name=asset_type,
                    asset_type=asset_type,
                    description=f"{asset_type} identified in intelligence",
                    criticality="High",
                    source_intel_ids=source_ids,
                    metadata={}
                )
                assets.append(asset)
        
        return assets
    
    def _generate_controls_for_threats(
        self,
        threats: List[GeneratedThreat],
        content: str
    ) -> List[Dict[str, Any]]:
        """Generate security controls for threats"""
        controls = []
        control_set = set()
        
        for threat in threats:
            for control_name in threat.recommended_controls:
                if control_name not in control_set:
                    control_set.add(control_name)
                    controls.append({
                        "name": control_name,
                        "description": f"Mitigates {threat.name}",
                        "category": "Security Control",
                        "mitigates_threats": [threat.name]
                    })
        
        return controls
    
    def _merge_threats(self, threats: List[GeneratedThreat]) -> List[GeneratedThreat]:
        """Merge duplicate threats"""
        merged = {}
        
        for threat in threats:
            key = threat.name.lower()
            if key in merged:
                # Merge with existing
                existing = merged[key]
                existing.description = existing.description or threat.description
                existing.source_intel_ids.extend(threat.source_intel_ids)
                existing.affected_assets = list(set(existing.affected_assets + threat.affected_assets))
                existing.recommended_controls = list(set(existing.recommended_controls + threat.recommended_controls))
                # Use higher risk score
                if threat.risk_score > existing.risk_score:
                    existing.risk_score = threat.risk_score
                    existing.risk_level = threat.risk_level
            else:
                merged[key] = threat
        
        return list(merged.values())
    
    def _merge_assets(self, assets: List[GeneratedAsset]) -> List[GeneratedAsset]:
        """Merge duplicate assets"""
        merged = {}
        
        for asset in assets:
            key = asset.name.lower()
            if key in merged:
                existing = merged[key]
                existing.source_intel_ids.extend(asset.source_intel_ids)
            else:
                merged[key] = asset
        
        return list(merged.values())
    
    def _merge_controls(self, controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge duplicate controls"""
        merged = {}
        
        for control in controls:
            key = control['name'].lower()
            if key in merged:
                existing = merged[key]
                existing['mitigates_threats'] = list(set(
                    existing['mitigates_threats'] + control['mitigates_threats']
                ))
            else:
                merged[key] = control.copy()
        
        return list(merged.values())
    
    def _threat_to_dict(self, threat: GeneratedThreat) -> Dict[str, Any]:
        """Convert GeneratedThreat to dictionary"""
        return {
            "name": threat.name,
            "description": threat.description,
            "stride_category": threat.stride_category,
            "attack_vector": threat.attack_vector,
            "impact": threat.impact,
            "likelihood": threat.likelihood,
            "risk_level": threat.risk_level,
            "risk_score": threat.risk_score,
            "source_intel_ids": threat.source_intel_ids,
            "affected_assets": threat.affected_assets,
            "recommended_controls": threat.recommended_controls,
            "metadata": threat.metadata
        }
    
    def _asset_to_dict(self, asset: GeneratedAsset) -> Dict[str, Any]:
        """Convert GeneratedAsset to dictionary"""
        return {
            "name": asset.name,
            "asset_type": asset.asset_type,
            "description": asset.description,
            "criticality": asset.criticality,
            "source_intel_ids": asset.source_intel_ids,
            "metadata": asset.metadata
        }
    
    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call LLM for threat extraction using user-selected models"""
        system_prompt = "You are an expert security analyst specializing in MCP (Model Context Protocol) security. Extract threats accurately and return only valid JSON."
        full_prompt = f"{system_prompt}\n\n{prompt}"
        
        # Use model selection if available
        if self.model_selection and self.model_selection.providers:
            # Try providers in priority order
            providers_tried = []
            for provider in self.model_selection.providers:
                try:
                    providers_tried.append(provider.value)
                    print(f"[IntelThreatGen] Trying {provider.value}...")
                    
                    if provider == ModelProvider.OLLAMA:
                        response = self._call_ollama(full_prompt)
                        if response:
                            print(f"[IntelThreatGen] ✅ Successfully used {provider.value}")
                            return response
                        else:
                            print(f"[IntelThreatGen] ⚠️ {provider.value} returned no response, trying next provider...")
                    elif provider == ModelProvider.LITELLM:
                        response = self._call_litellm(full_prompt)
                        if response:
                            print(f"[IntelThreatGen] ✅ Successfully used {provider.value}")
                            return response
                        else:
                            print(f"[IntelThreatGen] ⚠️ {provider.value} returned no response, trying next provider...")
                except Exception as e:
                    print(f"[IntelThreatGen] ❌ {provider.value} call failed: {e}")
                    print(f"[IntelThreatGen] Continuing to next provider...")
                    continue
            
            # If we tried all providers but none succeeded
            if providers_tried:
                print(f"[IntelThreatGen] ⚠️ All configured providers failed: {', '.join(providers_tried)}")
                print(f"[IntelThreatGen] Attempting fallback to llm_config.completion...")
        
        # Fallback: try llm_config.completion if available
        if hasattr(self.llm_config, 'completion'):
            try:
                result = self.llm_config.completion(
                    role="THREAT_ANALYZER",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=1,
                    max_tokens=3000
                )
                if result:
                    if isinstance(result, str):
                        return result
                    elif isinstance(result, dict):
                        if 'error' in result:
                            print(f"[IntelThreatGen] LLM error: {result.get('error')}")
                        elif 'content' in result:
                            return result['content']
                        elif 'choices' in result and result['choices']:
                            return result['choices'][0].get('message', {}).get('content', '')
            except Exception as e:
                print(f"[IntelThreatGen] llm_config.completion failed: {e}")
        
        print("[IntelThreatGen] All LLM providers failed, returning None")
        return None
    
    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call Ollama API directly using user-selected model configuration"""
        base_url = None
        model_name = None
        try:
            import httpx
            
            # Get Ollama config from model_selection (user's choice at startup)
            if not self.model_selection:
                return None
            
            config = self.model_selection.configs.get(ModelProvider.OLLAMA.value)
            if not config or not config.enabled:
                return None
            
            # Get configuration from user's selection (not hardcoded)
            base_url = config.base_url if config.base_url else "http://localhost:11434"
            model_name = config.model_name
            if not model_name:
                print("[IntelThreatGen] No Ollama model name in config")
                return None
            
            print(f"[IntelThreatGen] Using Ollama model: {model_name} at {base_url} (from user config)")
            
            # Get settings from config - use full capacity, no reduction
            temperature = config.config.get("temperature", 0.1) if config.config else 0.1
            num_ctx = config.config.get("num_ctx", 4096) if config.config else 4096  # Use full context from config
            num_predict = config.config.get("num_predict", 2000) if config.config else 2000  # Use full token limit from config
            
            # Parse prompt to extract system message if present
            # Format: "System message\n\nUser prompt"
            system_prompt = "You are an expert security analyst specializing in MCP (Model Context Protocol) security. Extract threats accurately and return only valid JSON."
            user_prompt = prompt
            
            # Check if prompt already contains system message
            if "\n\n" in prompt:
                parts = prompt.split("\n\n", 1)
                if len(parts) == 2 and parts[0].startswith("You are"):
                    system_prompt = parts[0]
                    user_prompt = parts[1]
            
            # No prompt truncation - let Ollama process full content
            # Use original context and token settings from config
            # Don't reduce num_ctx or num_predict - use full capacity
            
            # Use /api/chat endpoint for better system message support
            try:
                response = httpx.post(
                    f"{base_url}/api/chat",
                    json={
                        "model": model_name,
                        "messages": [
                            {
                                "role": "system",
                                "content": system_prompt
                            },
                            {
                                "role": "user",
                                "content": user_prompt
                            }
                        ],
                        "stream": False,
                        "options": {
                            "temperature": temperature,
                            "num_ctx": num_ctx,  # Use full context from config
                            "num_predict": num_predict  # Use full token limit from config
                        }
                    },
                    timeout=None  # No timeout - let it run as long as needed
                )
            except httpx.TimeoutException:
                # This should not happen with timeout=None, but keep for safety
                print(f"[IntelThreatGen] Ollama call timed out")
                print(f"[IntelThreatGen] Model: {model_name}, Base URL: {base_url}")
                print(f"[IntelThreatGen] This is unexpected as timeout is disabled. Check network or Ollama server.")
                return None
            
            if response.status_code == 200:
                result = response.json()
                # /api/chat returns message.content
                if "message" in result and "content" in result["message"]:
                    return result["message"]["content"]
                # Fallback to direct response field
                elif "response" in result:
                    return result["response"]
                else:
                    print(f"[IntelThreatGen] Unexpected Ollama response format: {result.keys()}")
            else:
                error_text = response.text if hasattr(response, 'text') else ""
                print(f"[IntelThreatGen] Ollama API returned status {response.status_code}: {error_text}")
        except httpx.TimeoutException:
            # This should not happen with timeout=None, but keep as fallback
            print(f"[IntelThreatGen] Ollama call timed out (unexpected)")
            if model_name and base_url:
                print(f"[IntelThreatGen] Model: {model_name}, Base URL: {base_url}")
            print(f"[IntelThreatGen] This is unexpected as timeout is disabled. Check network or Ollama server.")
            return None
        except httpx.RequestError as e:
            print(f"[IntelThreatGen] Ollama request error: {e}")
            if model_name and base_url:
                print(f"[IntelThreatGen] Model: {model_name}, Base URL: {base_url}")
                print(f"[IntelThreatGen] Check if Ollama is running: curl {base_url}/api/tags")
        except Exception as e:
            print(f"[IntelThreatGen] Ollama call failed: {e}")
            if model_name and base_url:
                print(f"[IntelThreatGen] Model: {model_name}, Base URL: {base_url}")
            import traceback
            traceback.print_exc()
        return None
    
    def _call_litellm(self, prompt: str) -> Optional[str]:
        """Call LiteLLM using user-selected model configuration"""
        try:
            import litellm
            
            # Only use LiteLLM if it's explicitly in the model selection
            if not self.model_selection or not self.model_selection.can_use_litellm():
                return None
            
            config = self.model_selection.configs.get(ModelProvider.LITELLM.value)
            if not config or not config.enabled:
                return None
            
            # Get model name from user's configuration (not hardcoded)
            model = config.model_name
            if not model:
                print("[IntelThreatGen] No LiteLLM model name in config")
                return None
            
            print(f"[IntelThreatGen] Using LiteLLM model: {model} (from user config)")
            
            # Get API key and base URL from config
            api_key = config.api_key
            api_base = config.base_url
            
            # Get temperature and max_tokens from config
            temperature = config.config.get("temperature", 0.1) if config.config else 0.1
            max_tokens = config.config.get("max_tokens", 3000) if config.config else 3000
            
            # Use HTTP proxy instead of litellm SDK (model prefixes like research/ only work via proxy)
            import requests as http_requests
            
            base_url = api_base.rstrip('/')
            # Ensure we have the correct chat completions endpoint
            if '/v1/chat/completions' not in base_url:
                endpoint_url = f"{base_url}/v1/chat/completions"
            else:
                endpoint_url = base_url
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "x-litellm-api-key": api_key,
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are an expert security analyst specializing in MCP (Model Context Protocol) security. Extract threats accurately and return only valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": max_tokens,
                "drop_params": True
            }
            
            print(f"[IntelThreatGen] Calling LiteLLM via HTTP: {endpoint_url}, model={model}")
            
            resp = http_requests.post(endpoint_url, headers=headers, json=payload, timeout=120)
            
            if resp.status_code == 200:
                data = resp.json()
                if "choices" in data and len(data["choices"]) > 0:
                    return data["choices"][0]["message"]["content"]
            else:
                error_text = resp.text[:500] if resp.text else "Unknown error"
                print(f"[IntelThreatGen] LiteLLM HTTP error {resp.status_code}: {error_text}")
        except Exception as e:
            print(f"[IntelThreatGen] LiteLLM call failed: {e}")
        return None

