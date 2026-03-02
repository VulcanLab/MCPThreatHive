"""
MCP Threat Platform - AI Intelligence Processor

AI-powered processing pipeline for threat intelligence:
1. Content cleaning and sanitization
2. MCP relevance analysis
3. Threat schema extraction
4. STRIDE classification
5. Risk scoring
"""

from __future__ import annotations

import os
import json
import asyncio
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import Counter

from .data_sources.base import IntelItem
from .document_chunker import DynamicChunker, ChunkingStrategy
from .ensemble_retriever import EnsembleRetriever, RetrievalStrategy

# Try to import Gemini config
try:
    from config.gemini_config import get_gemini_config, GeminiConfig
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    GeminiConfig = None

# Import rate limiter
try:
    from core.gemini_rate_limiter import get_rate_limiter
    RATE_LIMITER_AVAILABLE = True
except ImportError:
    RATE_LIMITER_AVAILABLE = False


@dataclass
class ProcessedIntel:
    """Processed intelligence item ready for threat conversion"""
    original: IntelItem
    
    # AI processing results
    is_relevant: bool = False
    relevance_score: float = 0.0
    relevance_reason: str = ""
    
    # Extracted threat info
    threat_title: str = ""
    threat_description: str = ""
    attack_vector: str = ""
    impact: str = ""
    
    # Classification
    stride_category: str = ""
    aatmf_mapping: Dict[str, str] = field(default_factory=dict)
    owasp_mapping: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_score: float = 0.0
    likelihood: str = "medium"
    
    # Recommended controls
    recommended_controls: List[str] = field(default_factory=list)
    
    # AI-generated summary
    ai_summary: str = ""
    
    @property
    def summary(self) -> str:
        """Alias for ai_summary for compatibility"""
        return self.ai_summary
    
    def to_threat_dict(self) -> Dict[str, Any]:
        """Convert to threat schema dictionary"""
        return {
            'name': self.threat_title,
            'description': self.threat_description,
            'category': self.stride_category,
            'attack_vector': self.attack_vector,
            'impact': self.impact,
            'risk_score': self.risk_score,
            'likelihood': self.likelihood,
            'source': self.original.source_type.value,
            'source_url': self.original.url,
            'source_date': self.original.published_at.isoformat() if self.original.published_at else None,
            'ai_summary': self.ai_summary,
            'ai_relevance_score': self.relevance_score,
            # 'aatmf_mapping': self.aatmf_mapping, # Removed as it causes TypeError in Threat model
            # 'owasp_mapping': self.owasp_mapping, # Removed as it causes TypeError in Threat model
            'schema_data': {
                'owasp_mapping': self.owasp_mapping,
                'aatmf_mapping': self.aatmf_mapping,
                'recommended_controls': self.recommended_controls
            },
            'tags': self.original.tags,
            'tags': self.original.tags,
            'threat_type': 'ai_generated',
            'status': 'active'
        }


class AIIntelProcessor:
    """
    AI-powered intelligence processor.
    
    Uses LLM to analyze, classify, and extract threat information.
    """
    
    def __init__(
        self,
        llm_client=None,
        config: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        provider: Optional[str] = None
    ):
        """
        Initialize AI processor.
        
        Args:
            llm_client: LLM client for AI analysis (LiteLLM or compatible)
            config: Processor configuration
            model: LLM model name
            api_base: LLM API base URL
            api_key: LLM API key
            provider: LLM provider name
        """
        self.llm_client = llm_client
        self.config = config or {}
        
        # Merge LLM config
        if model:
            self.config['model'] = model
        if api_base:
            self.config['api_base'] = api_base
        if api_key:
            self.config['api_key'] = api_key
        if provider:
            self.config['provider'] = provider
            
        # If no client provided, try to use litellm module
        if not self.llm_client:
            try:
                import litellm
                self.llm_client = litellm
                print("[AIProcessor] Using litellm module as fallback client")
            except ImportError:
                print("[AIProcessor] Warning: No LLM client and litellm not available")
        
        # Processing thresholds (configurable)
        self.relevance_threshold = self.config.get('relevance_threshold', 0.6)
        self.min_content_length = self.config.get('min_content_length', 100)
        
        # Dynamic chunking configuration
        self.chunk_size = self.config.get('chunk_size', 1000)
        self.chunk_overlap = self.config.get('chunk_overlap', 200)
        self.use_ensemble_retrieval = self.config.get('use_ensemble_retrieval', True)
        
        # Initialize chunker
        self.chunker = DynamicChunker(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
            strategy=ChunkingStrategy.SLIDING_WINDOW
        )
        
        # MCP-specific keywords for relevance scoring (focused on attacks, exploits, vulnerabilities)
        self.mcp_keywords = [
            "mcp", "model context protocol", "claude desktop",
            "mcp server", "mcp client", "mcp proxy", "mcp tool",
            "tool calling", "function calling",
            "prompt injection", "tool poisoning", "tool injection",
            "llm agent", "ai agent", "autonomous agent",
            "mcp exploit", "mcp vulnerability", "mcp attack",
            "mcp cve", "mcp security", "mcp bypass",
            "mcp server exploit", "mcp client exploit", "mcp proxy exploit"
        ]
        
        # Security keywords (focused on attacks, exploits, vulnerabilities, incidents)
        self.security_keywords = [
            "vulnerability", "exploit", "attack", "injection",
            "bypass", "escalation", "disclosure", "leak",
            "malicious", "adversarial", "jailbreak", "security",
            "cve", "poc", "proof of concept", "exploit code",
            "security incident", "breach", "compromise",
            "privilege escalation", "sandbox escape", "rce",
            "ssrf", "xss", "path traversal", "command injection",
            "code injection", "data exfiltration", "unauthorized access"
        ]
        
        # STRIDE mapping keywords
        self.stride_keywords = {
            "spoofing": ["impersonate", "spoof", "fake", "masquerade", "identity"],
            "tampering": ["tamper", "modify", "alter", "inject", "manipulate"],
            "repudiation": ["deny", "repudiate", "audit", "log", "trace"],
            "info_disclosure": ["leak", "expose", "disclose", "extract", "exfiltrate"],
            "denial_of_service": ["dos", "flood", "exhaust", "crash", "overload"],
            "elevation_of_privilege": ["privilege", "escalate", "permission", "bypass", "override"]
        }
    
    async def process_batch(
        self,
        items: List[IntelItem],
        use_ai: bool = True,
        use_gemini_filter: bool = True
    ) -> List[ProcessedIntel]:
        """
        Process a batch of intelligence items.
        
        Args:
            items: Raw intelligence items
            use_ai: Whether to use LLM for enhanced analysis
            use_gemini_filter: Whether to use Gemini for strict relevance filtering
            
        Returns:
            List of processed items
        """
        results = []
        
        # Check Gemini config once
        if use_gemini_filter and GEMINI_AVAILABLE:
            try:
                gemini_config = get_gemini_config()
                if not gemini_config.api_key:
                    print("   ⚠️ Gemini API key not configured, skipping Gemini filter for this batch")
                    use_gemini_filter = False
                
                # Get rate limiter status if available
                elif RATE_LIMITER_AVAILABLE:
                    rate_limiter = get_rate_limiter(gemini_config.default_model)
                    status = rate_limiter.get_status()
                    print(f"   📊 Gemini rate limit status: {status['rpm']['current']}/{status['rpm']['limit']} RPM, "
                          f"{status['tpm']['current']}/{status['tpm']['limit']} TPM, "
                          f"{status['rpd']['current']}/{status['rpd']['limit']} RPD")
            except Exception as e:
                print(f"   ⚠️ Could not check Gemini config: {e}")
                use_gemini_filter = False
        
        for idx, item in enumerate(items):
            try:
                # Clean content first
                cleaned_content = self._clean_content(item.content)
                item.content = cleaned_content
                
                # Quick relevance check (rule-based)
                quick_score = self._quick_relevance_score(item)
                
                if quick_score < 0.3:
                    # Skip clearly irrelevant items
                    continue
                
                # Use Gemini for strict relevance filtering if enabled
                if use_gemini_filter and GEMINI_AVAILABLE:
                    # Show progress for large batches
                    if len(items) > 10 and idx % 10 == 0:
                        print(f"   🔍 Processing item {idx + 1}/{len(items)} with Gemini filter...")
                    
                    gemini_relevant = await self._check_relevance_with_gemini(item)
                    if not gemini_relevant:
                        print(f"   ✗ Gemini filtered out: {item.title[:50]}...")
                    continue
                
                # Process with or without AI
                if use_ai and self.llm_client:
                    processed = await self._process_with_ai(item)
                else:
                    processed = self._process_rule_based(item)
                
                if processed.is_relevant:
                    results.append(processed)
                    
            except Exception as e:
                print(f"[AIProcessor] Error processing item: {e}")
        
        return results
    
    def _clean_content(self, content: str) -> str:
        """Clean and sanitize content"""
        if not content:
            return ""
        
        # Remove HTML tags
        content = re.sub(r'<[^>]+>', '', content)
        
        # Remove URLs (keep for reference but remove from main content)
        content = re.sub(r'http[s]?://\S+', '[URL]', content)
        
        # Remove excessive whitespace
        content = ' '.join(content.split())
        
        # Truncate very long content
        if len(content) > 10000:
            content = content[:10000] + "..."
        
        return content.strip()
    
    def _quick_relevance_score(self, item: IntelItem) -> float:
        """Quick rule-based relevance scoring"""
        text = f"{item.title} {item.content} {item.summary}".lower()
        
        score = 0.0
        
        # Check MCP keywords (high weight)
        mcp_matches = sum(1 for kw in self.mcp_keywords if kw.lower() in text)
        score += min(mcp_matches * 0.15, 0.5)
        
        # Check security keywords (medium weight)
        sec_matches = sum(1 for kw in self.security_keywords if kw.lower() in text)
        score += min(sec_matches * 0.1, 0.3)
        
        # Check content length
        if len(item.content) > self.min_content_length:
            score += 0.1
        
        # Boost for certain sources
        if item.source_type.value in ['cve', 'github']:
            score += 0.1
        
        return min(score, 1.0)
    
    def _process_rule_based(self, item: IntelItem) -> ProcessedIntel:
        """Process item using rule-based analysis (no AI)"""
        text = f"{item.title} {item.content}".lower()
        
        # Calculate relevance
        relevance_score = self._quick_relevance_score(item)
        is_relevant = relevance_score >= self.relevance_threshold
        
        # Determine STRIDE category
        stride_category = self._detect_stride_category(text)
        
        # Estimate risk score
        risk_score = self._estimate_risk_score(item, stride_category)
        
        # Generate title and description
        threat_title = self._generate_threat_title(item)
        threat_description = self._generate_threat_description(item)
        
        # Detect attack vector
        attack_vector = self._detect_attack_vector(text)
        
        # Suggest controls
        controls = self._suggest_controls(stride_category, attack_vector)
        
        return ProcessedIntel(
            original=item,
            is_relevant=is_relevant,
            relevance_score=relevance_score,
            relevance_reason="Rule-based analysis",
            threat_title=threat_title,
            threat_description=threat_description,
            attack_vector=attack_vector,
            impact=self._estimate_impact(stride_category),
            stride_category=stride_category,
            risk_score=risk_score,
            likelihood=self._estimate_likelihood(item),
            recommended_controls=controls,
            ai_summary=item.summary or item.content[:300]
        )
    
    async def _process_with_ai(self, item: IntelItem) -> ProcessedIntel:
        """Process item with AI enhancement using ensemble retrieval"""
        # Start with rule-based as fallback
        processed = self._process_rule_based(item)
        
        if not self.llm_client:
            return processed
        
        try:
            # Use ensemble retrieval for long content
            retrieved_chunks = None
            if self.use_ensemble_retrieval and len(item.content) > self.chunk_size:
                # Chunk the content
                chunks = self.chunker.chunk_text(
                    item.content,
                    metadata={'title': item.title, 'url': item.url, 'source': item.source_type.value}
                )
                
                if chunks:
                    # Create retriever
                    retriever = EnsembleRetriever(
                        chunks,
                        use_semantic=True,
                        use_bm25=True,
                        top_k=5
                    )
                    
                    # Build query from title and key terms
                    query = f"{item.title} {self._extract_key_terms(item.content)}"
                    
                    # Retrieve relevant chunks
                    retrieved_chunks = retriever.retrieve(query, RetrievalStrategy.HYBRID)
            
            # Build prompt with retrieved context
            prompt = self._build_analysis_prompt(item, retrieved_chunks)
            
            # Call LLM
            response = await self._call_llm(prompt)
            
            # Parse response
            ai_result = self._parse_ai_response(response)
            
            # Update processed intel with AI results
            if ai_result:
                processed.is_relevant = ai_result.get('is_relevant', processed.is_relevant)
                processed.relevance_score = ai_result.get('relevance_score', processed.relevance_score)
                processed.relevance_reason = ai_result.get('relevance_reason', "AI analysis")
                processed.threat_title = ai_result.get('threat_title', processed.threat_title)
                processed.threat_description = ai_result.get('threat_description', processed.threat_description)
                processed.attack_vector = ai_result.get('attack_vector', processed.attack_vector)
                processed.impact = ai_result.get('impact', processed.impact)
                processed.stride_category = ai_result.get('stride_category', processed.stride_category)
                processed.risk_score = ai_result.get('risk_score', processed.risk_score)
                processed.likelihood = ai_result.get('likelihood', processed.likelihood)
                processed.recommended_controls = ai_result.get('recommended_controls', processed.recommended_controls)
                processed.ai_summary = ai_result.get('summary', processed.ai_summary)
                processed.aatmf_mapping = ai_result.get('aatmf_mapping', {})
                processed.owasp_mapping = ai_result.get('owasp_mapping', [])
                
        except Exception as e:
            print(f"[AIProcessor] AI processing error: {e}")
            import traceback
            traceback.print_exc()
        
        return processed
    
    async def _check_relevance_with_gemini(self, item: IntelItem) -> bool:
        """
        Use Gemini to strictly check if content is relevant to MCP security.
        
        This is a strict filter that only allows MCP/LLM agent security related content.
        Includes rate limiting to avoid exceeding Gemini API limits.
        
        Args:
            item: Intelligence item to check
            
        Returns:
            True if relevant to MCP security, False otherwise
        """
        if not GEMINI_AVAILABLE:
            return True  # Fallback to allow if Gemini not available
        
        try:
            gemini_config = get_gemini_config()
            if not gemini_config.api_key:
                print("   ⚠️ Gemini API key not configured, skipping Gemini filter")
                return True
            
            # Initialize rate limiter and estimate tokens
            rate_limiter = None
            estimated_tokens = 1000  # Default estimate
            
            if RATE_LIMITER_AVAILABLE:
                rate_limiter = get_rate_limiter(gemini_config.default_model)
                
                # Estimate tokens (rough: 1 token ≈ 4 characters)
                content_length = len(item.title) + len(item.content[:2000])
                estimated_tokens = content_length // 4 + 500  # Add buffer for prompt
                
                # Wait if needed to respect rate limits
                await rate_limiter.wait_if_needed(estimated_tokens=estimated_tokens)
            else:
                # Fallback: simple delay
                await asyncio.sleep(6.0)  # Conservative 6s delay
            
            # Prepare content for Gemini
            content_text = f"{item.title}\n\n{item.content[:2000]}"  # Limit content length
            
            # Use Gemini API directly via requests
            import requests
            
            model = gemini_config.default_model
            api_key = gemini_config.api_key
            
            # Use Google AI Studio API
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            
            # Get safety settings from config
            safety_settings = gemini_config.get_safety_settings(block_all=False)
            
            prompt = f"""You are a security intelligence filter for MCP (Model Context Protocol) threat analysis.

Your task is to determine if the following content is STRICTLY related to MCP security attacks, exploits, vulnerabilities, or security incidents.

CRITICAL REQUIREMENTS:
- ONLY mark as relevant if the content is about: MCP server/client/proxy vulnerabilities, MCP exploits, MCP attack techniques, MCP security incidents, MCP CVEs, MCP proof-of-concept exploits, MCP tool injection attacks, MCP security research, or similar MCP security threats
- Focus on: attack methods, exploit techniques, vulnerability reports, security incidents, CVE reports, POC exploits, security research findings
- If the content is about general cybersecurity (not MCP/LLM agent related), mark as NOT relevant
- If the content is about MCP but NOT security-related (e.g., tutorials, introductions, general documentation), mark as NOT relevant
- If the content is about other AI topics (not MCP security), mark as NOT relevant
- Be STRICT - only allow content that is clearly about MCP security attacks, exploits, vulnerabilities, or security events

Content to analyze:
Title: {item.title}
Content: {content_text}

Respond with ONLY a JSON object:
{{
    "is_relevant": true or false,
    "reason": "brief explanation"
}}"""

            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }],
                "safetySettings": safety_settings,  # Use safety settings from config
                "generationConfig": {
                    "temperature": 0.1,  # Low temperature for consistent filtering
                    "maxOutputTokens": 5000,  # Increased from 200 to handle longer responses
                    "responseMimeType": "application/json"  # Request JSON response format
                }
            }
            
            response = requests.post(url, json=payload, timeout=30)
            
            # Record request for rate limiting
            if rate_limiter:
                rate_limiter.record_request(actual_tokens=estimated_tokens)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check for safety block
                candidates = data.get("candidates", [])
                if not candidates:
                    # Check if blocked by safety filters
                    prompt_feedback = data.get("promptFeedback", {})
                    if prompt_feedback.get("blockReason"):
                        print(f"   ⚠️ Gemini blocked by safety filters: {prompt_feedback.get('blockReason')}, defaulting to allow")
                        return True
                    print(f"   ⚠️ Gemini returned no candidates, defaulting to allow")
                    return True
                
                # Extract content safely
                candidate = candidates[0]
                finish_reason = candidate.get("finishReason", "")
                
                # Check finish reason first
                if finish_reason == "SAFETY":
                    print(f"   ⚠️ Gemini blocked by safety filters (finishReason: SAFETY), defaulting to allow")
                    return True
                elif finish_reason == "RECITATION":
                    print(f"   ⚠️ Gemini blocked due to recitation (finishReason: RECITATION), defaulting to allow")
                    return True
                elif finish_reason == "MAX_TOKENS":
                    # Response was truncated, but we can still try to parse what we got
                    print(f"   ⚠️ Gemini response truncated (MAX_TOKENS), attempting to parse partial response")
                    # Continue to try parsing - partial JSON might still be usable
                elif finish_reason and finish_reason != "STOP":
                    print(f"   ⚠️ Gemini finished with reason: {finish_reason}, defaulting to allow")
                    return True
                
                content_obj = candidate.get("content", {})
                parts = content_obj.get("parts", [])
                if not parts:
                    # Log the full candidate for debugging
                    print(f"   ⚠️ Gemini returned no content parts (finishReason: {finish_reason}), candidate keys: {list(candidate.keys())}, defaulting to allow")
                    return True
                
                content = parts[0].get("text", "")
                if not content:
                    print(f"   ⚠️ Gemini returned empty text (finishReason: {finish_reason}), parts: {len(parts)}, defaulting to allow")
                    return True
                
                # Parse JSON response
                try:
                    # Extract JSON from response (might have markdown code blocks)
                    import json as json_lib
                    content = content.strip()
                    if content.startswith("```"):
                        # Remove markdown code blocks
                        content = content.split("```")[1]
                        if content.startswith("json"):
                            content = content[4:]
                    content = content.strip()
                    
                    result = json_lib.loads(content)
                    is_relevant = result.get("is_relevant", False)
                    reason = result.get("reason", "")
                    
                    if is_relevant:
                        print(f"   ✓ Gemini approved: {item.title[:50]}... ({reason[:30]})")
                    else:
                        print(f"   ✗ Gemini rejected: {item.title[:50]}... ({reason[:30]})")
                    
                    return is_relevant
                except json_lib.JSONDecodeError:
                    # If JSON parsing fails (including truncated responses), try to extract partial info
                    content_lower = content.lower()
                    
                    # Try to find is_relevant value even in truncated JSON
                    if '"is_relevant":true' in content or '"is_relevant": true' in content:
                        print(f"   ✓ Gemini approved (from truncated response): {item.title[:50]}...")
                        return True
                    elif '"is_relevant":false' in content or '"is_relevant": false' in content:
                        print(f"   ✗ Gemini rejected (from truncated response): {item.title[:50]}...")
                        return False
                    
                    # Fallback: check for keywords
                    if "true" in content_lower and "relevant" in content_lower:
                        return True
                    elif "false" in content_lower and ("not relevant" in content_lower or "irrelevant" in content_lower):
                        return False
                    
                    # Default to False if unclear (be strict)
                    print(f"   ⚠️ Gemini response unclear/truncated, defaulting to reject: {content[:100]}")
                    return False
            elif response.status_code == 429:
                # Rate limit exceeded
                print(f"   ⚠️ Gemini rate limit exceeded (429). Waiting and retrying...")
                if rate_limiter:
                    # Wait longer and retry once
                    await asyncio.sleep(60.0)  # Wait 1 minute
                    await rate_limiter.wait_if_needed(estimated_tokens=estimated_tokens)
                    # Retry once
                    retry_response = requests.post(url, json=payload, timeout=30)
                    if retry_response.status_code == 200:
                        rate_limiter.record_request(actual_tokens=estimated_tokens)
                        # Parse retry response
                        retry_data = retry_response.json()
                        retry_content = retry_data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        try:
                            import json as json_lib
                            retry_content = retry_content.strip()
                            if retry_content.startswith("```"):
                                retry_content = retry_content.split("```")[1]
                                if retry_content.startswith("json"):
                                    retry_content = retry_content[4:]
                            retry_content = retry_content.strip()
                            retry_result = json_lib.loads(retry_content)
                            is_relevant = retry_result.get("is_relevant", False)
                            reason = retry_result.get("reason", "")
                            if is_relevant:
                                print(f"   ✓ Gemini approved (retry): {item.title[:50]}... ({reason[:30]})")
                            else:
                                print(f"   ✗ Gemini rejected (retry): {item.title[:50]}... ({reason[:30]})")
                            return is_relevant
                        except Exception as e:
                            print(f"   ⚠️ Retry parse error: {e}, defaulting to allow")
                            return True
                    else:
                        print(f"   ⚠️ Retry failed: {retry_response.status_code}, defaulting to allow")
                        return True
                else:
                    # No rate limiter, just wait and skip
                    await asyncio.sleep(60.0)
                    return True  # Default to allow if rate limited
            else:
                print(f"   ⚠️ Gemini API error: {response.status_code}, defaulting to allow")
                return True  # Default to allow if API fails
                
        except Exception as e:
            print(f"   ⚠️ Gemini filter error: {e}, defaulting to allow")
            return True  # Default to allow if error occurs
    
    def _extract_key_terms(self, text: str, max_terms: int = 10) -> str:
        """Extract key terms from text for query building"""
        
        # Extract words (excluding common stop words)
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'should', 'could', 'may', 'might', 'must', 'can'}
        
        words = re.findall(r'\b[a-z]{3,}\b', text.lower())
        words = [w for w in words if w not in stop_words]
        
        # Count frequency
        word_freq = Counter(words)
        
        # Get top terms
        top_terms = [word for word, _ in word_freq.most_common(max_terms)]
        
        return ' '.join(top_terms)
    
    def _build_analysis_prompt(self, item: IntelItem, retrieved_chunks: Optional[List] = None) -> str:
        """Build prompt for AI analysis with retrieved context"""
        # Use ensemble retrieval if enabled and content is long
        if self.use_ensemble_retrieval and len(item.content) > self.chunk_size:
            if retrieved_chunks:
                # Build context from retrieved chunks
                context_parts = []
                for chunk_result in retrieved_chunks[:3]:  # Top 3 chunks
                    context_parts.append(f"[Context Chunk {chunk_result.chunk.chunk_index}]:\n{chunk_result.chunk.content[:500]}")
                
                context = "\n\n".join(context_parts)
                content_section = f"Relevant Context:\n{context}\n\nOriginal Title: {item.title}"
            else:
                # Fallback: use dynamic chunking
                chunks = self.chunker.chunk_text(item.content, metadata={'title': item.title, 'url': item.url})
                if chunks:
                    context = "\n\n".join([c.content[:500] for c in chunks[:3]])
                    content_section = f"Relevant Context:\n{context}\n\nOriginal Title: {item.title}"
                else:
                    content_section = f"Title: {item.title}\nContent: {item.content[:2000]}"
        else:
            # Short content, use directly
            content_section = f"Title: {item.title}\nContent: {item.content[:2000]}"
        
        return f"""Analyze this security intelligence for MCP (Model Context Protocol) security threats, attacks, exploits, and vulnerabilities.

{content_section}

CRITICAL RELEVANCE REQUIREMENTS:
- This MUST be related to MCP (Model Context Protocol) security: attacks, exploits, vulnerabilities, security incidents, CVEs, or security research
- Focus on: MCP server/client/proxy vulnerabilities, MCP attack techniques, MCP exploits, MCP security incidents, MCP tool injection attacks, MCP security research
- If the content is about general security (not MCP/LLM agent related), mark is_relevant as FALSE
- If the content is about MCP but NOT security-related (e.g., tutorials, introductions, general documentation), mark is_relevant as FALSE
- Only mark as relevant if it relates to: MCP security attacks, MCP exploits, MCP vulnerabilities, MCP CVEs, MCP security incidents, MCP tool injection attacks, MCP server/client/proxy security issues, or similar MCP security threats
- General cybersecurity topics (not MCP/LLM related) should be marked as NOT relevant
- MCP tutorials, introductions, or non-security documentation should be marked as NOT relevant

IMPORTANT INSTRUCTIONS:
1. Synthesize the information naturally - do not copy text verbatim
2. Rewrite concepts in your own words
3. Do not mention specific sources, URLs, or authors
4. Focus on the security attack implications, exploit techniques, and threat patterns
5. Generate original analysis based on the information
6. STRICTLY filter: Only mark as relevant if it's about MCP security attacks, exploits, vulnerabilities, or security incidents

Analyze and return a JSON object with:
{{
    "is_relevant": true/false (ONLY true if related to MCP/LLM agent/AI tool security, false for general security),
    "relevance_score": 0.0-1.0,
    "relevance_reason": "explanation in your own words",
    "threat_title": "original threat name (not copied from source)",
    "threat_description": "detailed description in your own words, synthesized from context",
    "attack_vector": "how the attack works (rewritten, not copied)",
    "impact": "potential impact (original analysis)",
    "stride_category": "spoofing|tampering|repudiation|info_disclosure|denial_of_service|elevation_of_privilege",
    "risk_score": 1.0-10.0,
    "likelihood": "low|medium|high",
    "recommended_controls": ["control1", "control2"],
    "summary": "brief synthesized summary (original writing)",
    "aatmf_mapping": {{"tactic": "T1-T14", "technique": "AT-xxx"}},
    "owasp_mapping": ["LLM01", "LLM02", etc]
}}

Return only valid JSON. Ensure all text is original synthesis, not copied."""
    
    async def _call_llm(self, prompt: str) -> str:
        """Call LLM API"""
        model = self.config.get('model') or os.getenv('LITELLM_MODEL')
        provider = self.config.get('provider')
        api_base = self.config.get('api_base')
        api_key = self.config.get('api_key')
        
        # Ensure model has correct provider prefix based on configuration
        model_to_use = model
        
        if model:
            # Check if model already has a known provider prefix
            known_providers = ["openai", "anthropic", "azure", "gemini", "ollama", "vertex_ai", "bedrock"]
            has_provider = any(model.startswith(p + "/") for p in known_providers)
            
            if provider:
                # If provider is explicitly given, ensure it's used
                if provider == "ollama" and not model.startswith("ollama/"):
                    model_to_use = f"ollama/{model}"
                elif provider == "gemini" and not model.startswith("gemini/"):
                    model_to_use = f"gemini/{model}"
                elif provider == "litellm":
                    # For generic LiteLLM, we need a provider prefix.
                    if api_base and not has_provider:
                        # Check if it starts with any known provider distinct from model
                        model_to_use = f"openai/{model}"
            elif api_base and not has_provider:
                # If using a custom API base without explicit provider, default default logic
                if not model.startswith("openai/"):
                    model_to_use = f"openai/{model}"

        # Prepare kwargs
        kwargs = {
            "model": model_to_use,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        }
        
        if api_base:
            kwargs["api_base"] = api_base
        if api_key:
            kwargs["api_key"] = api_key
            
        # Call based on client type
        if hasattr(self.llm_client, 'completion'):
            # LiteLLM module style
            response = await asyncio.to_thread(
                self.llm_client.completion,
                **kwargs
            )
            return response.choices[0].message.content
        elif hasattr(self.llm_client, 'chat'):
            # OpenAI client style
            response = await asyncio.to_thread(
                self.llm_client.chat.completions.create,
                **kwargs
            )
            return response.choices[0].message.content
        else:
            raise ValueError("Unknown LLM client type")
    
    def _parse_ai_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse AI response JSON"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group())
            return None
        except json.JSONDecodeError:
            print(f"[AIProcessor] Failed to parse AI response")
            return None
    
    def _detect_stride_category(self, text: str) -> str:
        """Detect STRIDE category from text"""
        scores = {}
        
        for category, keywords in self.stride_keywords.items():
            score = sum(1 for kw in keywords if kw in text)
            scores[category] = score
        
        if not any(scores.values()):
            return "tampering"  # Default for most injection attacks
        
        return max(scores, key=scores.get)
    
    def _estimate_risk_score(self, item: IntelItem, stride_category: str) -> float:
        """Estimate risk score"""
        base_score = 5.0
        
        # Adjust by STRIDE category
        category_weights = {
            "elevation_of_privilege": 2.0,
            "info_disclosure": 1.5,
            "tampering": 1.5,
            "spoofing": 1.0,
            "denial_of_service": 0.5,
            "repudiation": 0.5
        }
        base_score += category_weights.get(stride_category, 0)
        
        # Adjust by source
        if item.source_type.value == 'cve':
            cvss = item.raw_data.get('cvss_score')
            if cvss:
                base_score = cvss
        
        # Boost for certain keywords
        text = f"{item.title} {item.content}".lower()
        if "critical" in text or "severe" in text:
            base_score += 1.0
        if "remote" in text and "execution" in text:
            base_score += 1.5
        
        return min(max(base_score, 1.0), 10.0)
    
    def _generate_threat_title(self, item: IntelItem) -> str:
        """Generate a concise threat title"""
        title = item.title
        
        # Clean up title
        title = re.sub(r'^CVE-\d{4}-\d+:\s*', '', title)  # Remove CVE prefix
        title = re.sub(r'\s+', ' ', title).strip()
        
        if len(title) > 100:
            title = title[:97] + "..."
        
        return title if title else "Unspecified Threat"
    
    def _generate_threat_description(self, item: IntelItem) -> str:
        """Generate threat description"""
        desc = item.content or item.summary or item.title
        
        if len(desc) > 1000:
            desc = desc[:997] + "..."
        
        return desc
    
    def _detect_attack_vector(self, text: str) -> str:
        """Detect attack vector from text"""
        vectors = {
            "prompt injection": ["prompt injection", "inject prompt", "malicious prompt"],
            "tool manipulation": ["tool poisoning", "tool abuse", "malicious tool"],
            "file access": ["file access", "path traversal", "file read", "file write"],
            "network attack": ["ssrf", "network access", "external fetch"],
            "context manipulation": ["context window", "context overflow", "token manipulation"]
        }
        
        for vector, keywords in vectors.items():
            if any(kw in text for kw in keywords):
                return vector
        
        return "unspecified"
    
    def _estimate_impact(self, stride_category: str) -> str:
        """Estimate impact based on STRIDE category"""
        impacts = {
            "spoofing": "Identity compromise, unauthorized access",
            "tampering": "Data manipulation, unauthorized modifications",
            "repudiation": "Inability to trace actions, compliance issues",
            "info_disclosure": "Sensitive data exposure, credential theft",
            "denial_of_service": "Service unavailability, resource exhaustion",
            "elevation_of_privilege": "System compromise, unauthorized control"
        }
        return impacts.get(stride_category, "Unspecified impact")
    
    def _estimate_likelihood(self, item: IntelItem) -> str:
        """Estimate likelihood"""
        # CVEs with public exploits are more likely
        if item.source_type.value == 'cve':
            severity = item.raw_data.get('severity', '').lower()
            if severity in ['critical', 'high']:
                return 'high'
            elif severity == 'medium':
                return 'medium'
            return 'low'
        
        # Default based on source
        if item.source_type.value in ['github', 'web_search']:
            return 'medium'
        
        return 'medium'
    
    def _suggest_controls(self, stride_category: str, attack_vector: str) -> List[str]:
        """Suggest security controls"""
        controls = []
        
        # STRIDE-based controls
        stride_controls = {
            "spoofing": ["server_authentication", "tls_encryption", "certificate_pinning"],
            "tampering": ["input_sanitization", "output_validation", "content_sanitization"],
            "repudiation": ["comprehensive_logging", "audit_trail"],
            "info_disclosure": ["secret_redaction", "path_whitelist", "output_filtering"],
            "denial_of_service": ["rate_limiting", "timeout_enforcement", "resource_limits"],
            "elevation_of_privilege": ["input_sanitization", "tool_sandbox", "least_privilege"]
        }
        controls.extend(stride_controls.get(stride_category, []))
        
        # Attack vector specific controls
        vector_controls = {
            "prompt injection": ["content_sanitization", "context_isolation"],
            "tool manipulation": ["tool_allowlist", "tool_permission"],
            "file access": ["path_whitelist", "tool_sandbox"],
            "network attack": ["url_whitelist", "network_isolation"],
            "context manipulation": ["context_isolation", "rate_limiting"]
        }
        controls.extend(vector_controls.get(attack_vector, []))
        
        return list(set(controls))  # Remove duplicates

