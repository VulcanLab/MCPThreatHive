"""
Intelligence Classifier for MCP Threats

Classifies intelligence items by MCP workflow phases, MSB attack types,
MCP-UPD phases, and MPMA attack types.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from schemas.mcp_enhanced_threat_schema import (
    MCPWorkflowPhase, MSBAttackType, MCPUPDAttackPhase,
    MCPUPDAttackTool, MPMAAttackType, GAPMAStrategy
)


@dataclass
class IntelClassification:
    """Classification result for an intelligence item"""
    # MSB Taxonomy
    workflow_phase: Optional[MCPWorkflowPhase] = None
    msb_attack_type: Optional[MSBAttackType] = None
    
    # MCP-UPD
    mcp_upd_phase: Optional[MCPUPDAttackPhase] = None
    mcp_upd_tools: List[MCPUPDAttackTool] = None
    
    # MPMA
    mpma_type: Optional[MPMAAttackType] = None
    gapma_strategy: Optional[GAPMAStrategy] = None
    
    # Confidence scores
    confidence: float = 0.0
    
    def __post_init__(self):
        if self.mcp_upd_tools is None:
            self.mcp_upd_tools = []


class IntelClassifier:
    """
    Classifies intelligence items by MCP taxonomy.
    
    Uses keyword matching and pattern detection to classify intelligence
    items into MCP workflow phases, attack types, and attack chains.
    """
    
    # Keywords for MSB Attack Types
    MSB_KEYWORDS = {
        MSBAttackType.PROMPT_INJECTION: [
        "prompt injection", "prompt hijacking", "instruction injection",
        "jailbreak", "system prompt", "adversarial prompt"
        ],
        MSBAttackType.PREFERENCE_MANIPULATION: [
            "preference manipulation", "tool selection", "advertising",
            "economic incentive", "revenue", "best tool"
        ],
        MSBAttackType.NAME_COLLISION: [
            "name collision", "tool name", "shadow tool", "tool hijacking"
        ],
        MSBAttackType.OUT_OF_SCOPE_PARAMETER: [
            "out of scope", "parameter injection", "unauthorized parameter",
            "parameter manipulation", "extra parameter"
        ],
        MSBAttackType.USER_IMPERSONATION: [
            "user impersonation", "identity spoofing", "user context",
            "emergency instruction", "urgent request"
        ],
        MSBAttackType.FAKE_ERROR: [
            "fake error", "false error", "error injection", "error message",
            "error handling", "error manipulation"
        ],
        MSBAttackType.RETRIEVAL_INJECTION: [
            "retrieval injection", "RAG injection", "context injection",
            "document injection", "knowledge base injection"
        ]
    }
    
    # Keywords for MCP-UPD phases (5-stage model)
    MCP_UPD_KEYWORDS = {
        MCPUPDAttackPhase.TOOL_SURFACE_DISCOVERY: [
            "tool scanning", "tool surface", "schema analysis", "attack surface",
            "tool definition", "input schema", "output schema", "parasitic tool",
            "UPD surface", "deserialization", "insecure resource access",
            "over-broad file access", "broken auth", "broken authorization"
        ],
        MCPUPDAttackPhase.PARAMETER_INJECTION: [
            "parameter injection", "prompt injection", "tool-call injection",
            "schema bypass", "constraint evasion", "validator bypass",
            "type confusion", "parameter manipulation", "malicious parameter"
        ],
        MCPUPDAttackPhase.PARASITIC_CHAINING: [
            "tool chaining", "parasitic chain", "tool-to-tool", "tool output chaining",
            "indirect execution", "hidden attack path", "tool dependency",
            "tool A output", "tool B input", "parasitic tool chain"
        ],
        MCPUPDAttackPhase.UPD_EXPLOITATION: [
            "untrusted parameter", "UPD exploitation", "file read", "file write",
            "network pivoting", "SSRF via tool", "code injection via tool",
            "command injection via tool", "data exfiltration via tool",
            "external ingestion", "privacy access", "network access",
            "EIT", "PAT", "NAT"
        ],
        MCPUPDAttackPhase.POST_TOOL_IMPACT: [
            "data exfiltration", "integrity compromise", "availability impact",
            "privilege escalation", "privacy leak", "supply chain propagation",
            "sandbox escape", "sensitive data", "unauthorized access",
            "security impact", "attack impact", "post-exploitation"
        ]
    }
    
    # Keywords for MPMA
    MPMA_KEYWORDS = {
        MPMAAttackType.DIRECT_PREFERENCE_MANIPULATION: [
            "direct manipulation", "explicit advertising", "best tool",
            "recommended", "preferred"
        ],
        MPMAAttackType.GENETIC_ALGORITHM_PREFERENCE: [
            "genetic algorithm", "GA optimization", "stealthy",
            "optimized description", "advertising strategy"
        ]
    }
    
    # GAPMA strategy keywords
    GAPMA_KEYWORDS = {
        GAPMAStrategy.AUTHORITATIVE: [
            "authoritative", "expert", "official", "certified", "verified"
        ],
        GAPMAStrategy.EMOTIONAL: [
            "emotional", "feel", "experience", "satisfaction", "happiness"
        ],
        GAPMAStrategy.EXAGGERATED: [
            "exaggerated", "amazing", "incredible", "revolutionary", "breakthrough"
        ],
        GAPMAStrategy.SUBLIMINAL: [
            "subliminal", "subtle", "hidden", "implicit", "unconscious"
        ]
    }
    
    def classify(self, intel_item: Dict[str, Any]) -> IntelClassification:
        """
        Classify an intelligence item using pattern matching and LLM.
        Returns an IntelClassification object with detailed analysis.
        """
        classification = IntelClassification()
        
        # Extract text content
        text = self._extract_text(intel_item).lower()
        
        # 1. MSB Attack Type
        msb_matches = self._match_msb_keywords(text)
        if msb_matches:
            classification.msb_attack_type = msb_matches[0]
            # Infer workflow phase from attack type
            classification.workflow_phase = self._get_workflow_phase(classification.msb_attack_type)
        
        # 2. MCP-UPD Phase & Tools
        upd_matches = self._match_mcp_upd_keywords(text)
        if upd_matches:
            classification.mcp_upd_phase = upd_matches[0]
        
        upd_tools = self._detect_upd_tools(text)
        if upd_tools:
            classification.mcp_upd_tools = upd_tools
        
        # 3. MPMA Type
        mpma_matches = self._match_mpma_keywords(text)
        if mpma_matches:
            classification.mpma_type = mpma_matches[0]
        
        # 4. GAPMA Strategy
        gapma_strategy = self._detect_gapma_strategy(text)
        if gapma_strategy:
            classification.gapma_strategy = gapma_strategy
        
        # Calculate confidence
        score = 0.0
        if classification.msb_attack_type: score += 0.3
        if classification.mcp_upd_phase: score += 0.3
        if classification.mcp_upd_tools: score += 0.2
        if classification.mpma_type: score += 0.2
        classification.confidence = min(score, 1.0)
        
        return classification

    def _extract_text(self, intel_item: Dict[str, Any]) -> str:
        """Extract all text content from intelligence item"""
        parts = []
        
        if intel_item.get('title'):
            parts.append(intel_item['title'])
        if intel_item.get('content'):
            parts.append(intel_item['content'])
        if intel_item.get('ai_summary'):
            parts.append(intel_item['ai_summary'])
        if intel_item.get('description'):
            parts.append(intel_item['description'])
        
        return ' '.join(parts)
    
    def _classify_with_llm(self, intel_item: Dict[str, Any]) -> str:
        """Use LiteLLM to classify the item via direct HTTP"""
        import os
        import requests
        
        # Build prompt
        text = self._extract_text(intel_item)[:2000] # Truncate to avoid context limits
        
        prompt = f"""
        Analyze the following text and classify it into exactly ONE of these categories:
        
        - 'v': Vulnerability (CVE, exploit, weakness, PoC, security bug)
        - 't': Threat (Attack vector, risk scenario, theoretical attack)
        - 'a': Attack (Active exploitation, hacking technique, offensive security)
        - 'nw': News/Warning (Security alert, patch notice, critical update)
        - 's': Safe/Tool (Tutorial, "how to install", "getting started", general documentation, non-security tool demo)
        - 'o': Other (Irrelevant, spam, marketing, non-technical)
        
        CRITICAL: 
        1. If the text describes an EXPLOIT DEMO, PoC, or ATTACK SIMULATION, classify as 'v' or 'a'.
        2. If the text is a general "How to use MCP" guide, classify as 's'.
        3. If unsure, default to 'u'.
        
        DOUBLE CHECK:
        - Is this actually a vulnerability or just a tutorial on how to use a feature?
        - Does it describe a security risk or just standard functionality?
        - If it's a "How-to" guide without security implications -> 's'.
        
        Text to classify:
        {text}
        
        Reply with ONLY the code (v, t, a, nw, s, o, or u). Do not add any explanation.
        """
        
        # Get config from env (standardized)
        model = os.getenv("LITELLM_MODEL", "gpt-4o")
        api_key = os.getenv("LITELLM_API_KEY", "sk-dummy")
        base_url = os.getenv("LITELLM_API_BASE", "http://localhost:4000")
        
        # Construct URL
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
                {"role": "system", "content": "You are a security intelligence classifier."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.0,
            "max_tokens": 10
        }
        
        try:
            response = requests.post(
                api_url, 
                headers=headers, 
                json=payload, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                content = ""
                # Handle standard OpenAI format
                if "choices" in data and len(data["choices"]) > 0:
                    content = data["choices"][0]["message"]["content"]
                # Fallback for other formats
                elif "message" in data:
                    content = data["message"]["content"]
                elif "response" in data:
                    content = data["response"]
                else:
                    print(f"[IntelClassifier] Unexpected response: {data.keys()}")
                    return 'u'
                    
                code = content.strip().lower()
                if len(code) > 2:
                    code = code[0]
                    
                valid_codes = ['v', 't', 'i', 'a', 'nw', 's', 'o', 'u']
                if code not in valid_codes:
                    return 'u'
                return code
            else:
                print(f"[IntelClassifier] HTTP request failed {response.status_code}: {response.text[:200]}")
                return 'u'
                
        except Exception as e:
            print(f"[IntelClassifier] Direct HTTP call failed: {e}")
            raise e # Relies on caller's try/except to fallback to keywords

    def _classify_with_keywords(self, intel_item: Dict[str, Any]) -> str:
        """Fallback keyword classification"""
        # Combine all text content
        text_content = self._extract_text(intel_item)
        text_lower = text_content.lower()
        
        # Existing logic... reusing parts of original classify method
        # (This is a simplified fallback for now)
        
        # Classify by MSB Attack Type
        msb_matches = self._match_msb_keywords(text_lower)
        if msb_matches:
            return 't' # Threat
            
        # Classify by MCP-UPD
        upd_matches = self._match_mcp_upd_keywords(text_lower)
        if upd_matches:
            return 'v' # Vulnerability
            
        if "exploit" in text_lower or "cve" in text_lower:
            return 'v'
            
        if "tutorial" in text_lower or "guide" in text_lower:
            return 's'
            
        return 's' # Default to safe if no specific threat keywords found
    
    def _match_msb_keywords(self, text: str) -> List[MSBAttackType]:
        """Match MSB attack type keywords"""
        matches = []
        
        for attack_type, keywords in self.MSB_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    matches.append(attack_type)
                    break
        
        return matches
    
    def _match_mcp_upd_keywords(self, text: str) -> List[MCPUPDAttackPhase]:
        """Match MCP-UPD phase keywords"""
        matches = []
        
        for phase, keywords in self.MCP_UPD_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    matches.append(phase)
                    break
        
        return matches
    
    def _match_mpma_keywords(self, text: str) -> List[MPMAAttackType]:
        """Match MPMA attack type keywords"""
        matches = []
        
        for mpma_type, keywords in self.MPMA_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    matches.append(mpma_type)
                    break
        
        return matches
    
    def _detect_upd_tools(self, text: str) -> List[MCPUPDAttackTool]:
        """Detect MCP-UPD tool types from text"""
        tools = []
        
        # EIT indicators
        if any(kw in text for kw in ['external', 'ingestion', 'scraping', 'web', 'social media']):
            tools.append(MCPUPDAttackTool.EXTERNAL_INGESTION_TOOL)
        
        # PAT indicators
        if any(kw in text for kw in ['privacy', 'file read', 'history', 'access', 'sensitive']):
            tools.append(MCPUPDAttackTool.PRIVACY_ACCESS_TOOL)
        
        # NAT indicators
        if any(kw in text for kw in ['network', 'email', 'send', 'exfiltration', 'disclosure']):
            tools.append(MCPUPDAttackTool.NETWORK_ACCESS_TOOL)
        
        return tools
    
    def _detect_gapma_strategy(self, text: str) -> Optional[GAPMAStrategy]:
        """Detect GAPMA strategy from text"""
        for strategy, keywords in self.GAPMA_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    return strategy
        return None
    
    def _get_workflow_phase(self, attack_type: MSBAttackType) -> Optional[MCPWorkflowPhase]:
        """Get workflow phase from attack type"""
        phase_mapping = {
            MSBAttackType.PROMPT_INJECTION: MCPWorkflowPhase.TASK_PLANNING,
            MSBAttackType.PREFERENCE_MANIPULATION: MCPWorkflowPhase.TASK_PLANNING,
            MSBAttackType.NAME_COLLISION: MCPWorkflowPhase.TASK_PLANNING,
            MSBAttackType.OUT_OF_SCOPE_PARAMETER: MCPWorkflowPhase.TOOL_INVOCATION,
            MSBAttackType.USER_IMPERSONATION: MCPWorkflowPhase.RESPONSE_HANDLING,
            MSBAttackType.FAKE_ERROR: MCPWorkflowPhase.RESPONSE_HANDLING,
            MSBAttackType.RETRIEVAL_INJECTION: MCPWorkflowPhase.RESPONSE_HANDLING,
            MSBAttackType.MIXED_ATTACK: MCPWorkflowPhase.CROSS_PHASE,
        }
        return phase_mapping.get(attack_type)


# Global classifier instance
_classifier: Optional[IntelClassifier] = None


def get_classifier() -> IntelClassifier:
    """Get global classifier instance"""
    global _classifier
    if _classifier is None:
        _classifier = IntelClassifier()
    return _classifier
