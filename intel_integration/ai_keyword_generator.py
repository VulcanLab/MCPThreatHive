#!/usr/bin/env python3
"""
AI Keyword Generator for MCP Threat Intelligence

Dynamically generates search keywords using LLM for MCP security intelligence gathering.
No hardcoded keywords - all terms are AI-generated based on context and requirements.

Features:
- MCP-specific keyword generation
- STRIDE-based threat keyword generation
- Attack technique keyword generation
- Dynamic adaptation based on previous results
"""

from __future__ import annotations

import os
import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime

# LiteLLM import for AI calls
try:
    import litellm
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False


class AIKeywordGenerator:
    """
    AI-powered keyword generator for MCP threat intelligence.
    
    Generates search queries dynamically based on:
    - MCP security context
    - STRIDE threat categories
    - Current intelligence requirements
    - Learning from previous successful queries
    """
    
    def __init__(
        self,
        model: Optional[str] = None,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        provider: Optional[str] = None
    ):
        """
        Initialize AI keyword generator.
        
        Args:
            model: LLM model to use (default from env)
            api_base: API base URL (default from env)
            api_key: API key (default from env)
            provider: LLM provider name (e.g. 'ollama', 'gemini', 'litellm')
        """
        # Get model from environment - no hardcoded default to avoid model access issues
        self.model = model or os.getenv("LITELLM_MODEL")
        if not self.model:
            print("[AIKeywordGen] Warning: LITELLM_MODEL not set, LLM calls may fail")
        self.api_base = api_base or os.getenv("LITELLM_API_BASE")
        self.api_key = api_key or os.getenv("LITELLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.api_key = api_key or os.getenv("LITELLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.provider = provider
        
        # Get temperature from environment (default to 0.7 if not set)
        try:
            self.temperature = float(os.getenv("LITELLM_TEMPERATURE", "0.7"))
            print(f"[AIKeywordGen] Loaded temperature: {self.temperature} from env")
        except ValueError:
            print(f"[AIKeywordGen] Warning: Invalid LITELLM_TEMPERATURE, defaulting to 0.7")
            self.temperature = 0.7
        
        # Cache for generated keywords (avoid repeated LLM calls)
        self._keyword_cache: Dict[str, List[str]] = {}
        
        # Learning from previous queries
        self.successful_queries: List[Dict[str, Any]] = []
        self.failed_queries: List[str] = []
        
        print(f"[AIKeywordGen] Initialized with model: {self.model}, api_base: {self.api_base}, provider: {self.provider}")
    
    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """
        Call LLM to generate response via LiteLLM.
        
        Args:
            system_prompt: System instruction
            user_prompt: User query
            
        Returns:
            LLM response text
        """
        if not LITELLM_AVAILABLE:
            print("[AIKeywordGen] LiteLLM not available, returning empty response")
            return ""
        
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
            
            # Ensure model has correct provider prefix based on configuration
            model_to_use = self.model
            
            # Check if model already has a known provider prefix
            known_providers = ["openai", "anthropic", "azure", "gemini", "ollama", "vertex_ai", "bedrock"]
            has_provider = any(self.model.startswith(p + "/") for p in known_providers)
            
            if self.provider:
                # If provider is explicitly given, ensure it's used
                if self.provider == "ollama" and not self.model.startswith("ollama/"):
                    model_to_use = f"ollama/{self.model}"
                elif self.provider == "gemini" and not self.model.startswith("gemini/"):
                    model_to_use = f"gemini/{self.model}"
                elif self.provider == "litellm":
                    # For generic LiteLLM, we need a provider prefix.
                    # If the model doesn't start with a known provider, default to 'openai/' 
                    # which handles most custom compatible endpoints (vLLM, etc.)
                    if self.api_base and not has_provider:
                        # Check if it starts with any known provider distinct from self.model
                        # (The previous check 'has_provider' covers standard ones)
                        model_to_use = f"openai/{self.model}"
                        print(f"[AIKeywordGen] Added 'openai/' prefix for custom endpoint: {model_to_use}")
            elif self.api_base and not has_provider:
                # If using a custom API base without explicit provider, default logic
                if not self.model.startswith("openai/"):
                    model_to_use = f"openai/{self.model}"
                    print(f"[AIKeywordGen] Added 'openai/' prefix for custom endpoint: {model_to_use}")

            kwargs = {
                "model": model_to_use,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": 1000
            }
            
            if self.api_base:
                kwargs["api_base"] = self.api_base
            if self.api_key:
                kwargs["api_key"] = self.api_key
            
            print(f"[AIKeywordGen] Calling LiteLLM with model: {model_to_use}")
            response = litellm.completion(**kwargs)
            
            # Handle response safely
            if response and response.choices and len(response.choices) > 0:
                content = response.choices[0].message.content
                if content:
                    return content.strip()
            
            print("[AIKeywordGen] LiteLLM returned empty response")
            return ""
            
        except Exception as e:
            print(f"[AIKeywordGen] LLM call failed: {e}")
            return ""
    
    def generate_mcp_search_queries(
        self,
        focus: str = "MCP security threats and vulnerabilities",
        num_queries: int = 20,
        include_advanced: bool = True
    ) -> List[str]:
        """
        Generate search queries for MCP security intelligence.
        
        Args:
            focus: Focus area for query generation
            num_queries: Number of queries to generate
            include_advanced: Include advanced search operators
            
        Returns:
            List of search query strings
        """
        cache_key = f"mcp_queries_{focus}_{num_queries}_{include_advanced}"
        if cache_key in self._keyword_cache:
            return self._keyword_cache[cache_key]
        
        # Build context from successful queries
        context_section = ""
        if self.successful_queries:
            recent = self.successful_queries[-5:]
            context_section = f"""
Previous successful queries (generate similar but different):
{json.dumps([q['query'] for q in recent], indent=2)}
"""
        
        system_prompt = """You are an expert security researcher specializing in Model Context Protocol (MCP) security threats, attacks, exploits, and vulnerabilities.

Your task is to generate effective search queries to discover MCP-related security intelligence focusing on:
- Attack techniques and exploit methods
- Security vulnerabilities and CVEs
- Real-world security incidents and breaches
- Proof-of-concept exploits and POCs
- Security research findings

MCP Security Focus Areas (Attack & Vulnerability Focus):
- MCP server vulnerabilities, exploits, and attack techniques
- MCP client security flaws, exploits, and bypass methods
- MCP proxy vulnerabilities, SSRF attacks, and security issues
- Tool injection attacks (prompt injection, tool-call injection, parameter injection)
- Tool poisoning and malicious tool attacks
- Sandbox escape and privilege escalation in MCP
- Data exfiltration attacks via MCP tools
- Authentication/authorization bypass in MCP servers/clients
- MCP configuration vulnerabilities and misconfigurations
- MCP protocol-level exploits and attacks
- MCP security incidents and breach reports
- CVE reports for MCP-related vulnerabilities
- GitHub security advisories for MCP projects
- Security research papers on MCP attacks

OUTPUT FORMAT: Return ONLY a JSON array of query strings.
Example: ["MCP server vulnerability CVE", "MCP client exploit POC", "MCP proxy SSRF attack", "MCP tool injection exploit", "MCP security incident report"]

CONSTRAINTS:
- Generate diverse, specific queries focused on attacks, exploits, and vulnerabilities
- Prioritize queries that find: CVEs, exploit POCs, security advisories, attack techniques, vulnerability reports
- Include queries for: MCP server attacks, MCP client exploits, MCP proxy vulnerabilities
- Target different source types (CVE databases, GitHub security, exploit databases, security blogs, research papers)
- DO NOT include year restrictions (e.g., avoid "2024", "2025") unless specifically needed for recent CVE searches
- Focus on timeless security attack concepts that remain relevant
- NO explanations, ONLY the JSON array"""

        advanced_section = ""
        if include_advanced:
            advanced_section = """
Include some queries with search operators:
- site:github.com for code repositories
- site:arxiv.org for academic papers
- filetype:pdf for research documents
- intitle: for specific page titles"""

        user_prompt = f"""Generate {num_queries} search queries for: {focus}
{advanced_section}
{context_section}

Requirements:
1. Focus on MCP (Model Context Protocol) security
2. Include queries for different threat types (injection, bypass, exfiltration, etc.)
3. Include queries for different components (server, client, tools, transport)
4. Generate timeless queries without year restrictions - let search engines return both recent and historical results
5. Include queries targeting: CVEs, exploits, research papers, blog posts, GitHub issues
6. Avoid adding years (2024, 2025) unless absolutely necessary for specific CVE searches

Return ONLY a JSON array of {num_queries} query strings."""

        response = self._call_llm(system_prompt, user_prompt)
        
        if not response:
            print(f"[AIKeywordGen] ❌ LLM returned empty response for focus: {focus[:50]}")
            return []
        
        queries = self._parse_json_array(response)
        
        if not queries:
            print(f"[AIKeywordGen] ❌ Failed to parse queries from response.")
            print(f"[AIKeywordGen] Response length: {len(response)}, First 300 chars: {response[:300]}")
        else:
            print(f"[AIKeywordGen] ✓ Generated {len(queries)} queries for: {focus[:50]}")
        
        if queries:
            self._keyword_cache[cache_key] = queries
        
        return queries
    
    def generate_stride_queries(
        self,
        stride_category: str,
        num_queries: int = 10
    ) -> List[str]:
        """
        Generate queries for a specific STRIDE threat category in MCP context.
        
        Args:
            stride_category: One of: Spoofing, Tampering, Repudiation, 
                           Information Disclosure, Denial of Service, Elevation of Privilege
            num_queries: Number of queries to generate
            
        Returns:
            List of search query strings
        """
        cache_key = f"stride_{stride_category}_{num_queries}"
        if cache_key in self._keyword_cache:
            return self._keyword_cache[cache_key]
        
        system_prompt = """You are a security expert generating search queries for STRIDE threat modeling in MCP context.

STRIDE Categories Applied to MCP:
- Spoofing: MCP server impersonation, tool identity spoofing, model provider spoofing
- Tampering: Tool response modification, context manipulation, MCP message tampering
- Repudiation: MCP audit bypass, logging evasion, action deniability
- Information Disclosure: Data exfiltration via tools, context leakage, secret exposure
- Denial of Service: MCP server overload, tool exhaustion, resource depletion
- Elevation of Privilege: Tool permission bypass, sandbox escape, capability escalation

OUTPUT FORMAT: Return ONLY a JSON array of query strings.

CONSTRAINTS:
- Generate queries specific to the STRIDE category
- Apply to MCP/AI agent context
- Include technical attack techniques
- NO explanations, ONLY the JSON array"""

        user_prompt = f"""Generate {num_queries} search queries for STRIDE category: {stride_category}

Apply this threat category specifically to MCP (Model Context Protocol) security.
Focus on how this threat type manifests in:
- MCP servers and clients
- AI tools and capabilities
- Model-to-tool interactions
- Data flows and resources

Return ONLY a JSON array of {num_queries} query strings."""

        response = self._call_llm(system_prompt, user_prompt)
        queries = self._parse_json_array(response)
        
        if queries:
            self._keyword_cache[cache_key] = queries
        
        return queries
    
    def generate_attack_technique_queries(
        self,
        technique: str,
        num_queries: int = 10
    ) -> List[str]:
        """
        Generate queries for a specific attack technique.
        
        Args:
            technique: Attack technique name (e.g., "prompt injection", "tool misuse")
            num_queries: Number of queries to generate
            
        Returns:
            List of search query strings
        """
        cache_key = f"attack_{technique}_{num_queries}"
        if cache_key in self._keyword_cache:
            return self._keyword_cache[cache_key]
        
        system_prompt = """You are a security researcher generating search queries for AI/MCP attack techniques.

Your task is to generate queries that will find:
- Research papers describing the attack
- Proof of concept code
- Real-world examples and case studies
- Defensive measures and mitigations
- Related attack variations

OUTPUT FORMAT: Return ONLY a JSON array of query strings.

CONSTRAINTS:
- Generate diverse queries for the attack technique
- Include academic, practical, and defensive perspectives
- Target multiple source types
- NO explanations, ONLY the JSON array"""

        user_prompt = f"""Generate {num_queries} search queries for attack technique: {technique}

Find information about:
1. How the attack works (technical details)
2. Examples and proof of concepts
3. CVEs and vulnerability reports
4. Defenses and mitigations
5. Variations and evolved versions

Return ONLY a JSON array of {num_queries} query strings."""

        response = self._call_llm(system_prompt, user_prompt)
        queries = self._parse_json_array(response)
        
        if queries:
            self._keyword_cache[cache_key] = queries
        
        return queries
    
    def generate_discovery_queries(
        self,
        goal: str,
        previous_results: Optional[List[Dict[str, Any]]] = None,
        num_queries: int = 15
    ) -> List[str]:
        """
        Generate discovery queries based on a high-level goal.
        
        This is the main entry point for flexible, AI-driven query generation.
        
        Args:
            goal: High-level intelligence gathering goal
            previous_results: Previous results to learn from
            num_queries: Number of queries to generate
            
        Returns:
            List of search query strings
        """
        # Build context from previous results
        context_section = ""
        if previous_results:
            # Extract successful patterns
            titles = [r.get("title", "")[:100] for r in previous_results[:10] if r.get("title")]
            if titles:
                context_section = f"""
Previous successful results (find more like these):
{json.dumps(titles, indent=2)}

Analyze these and generate queries that would find similar high-quality content.
"""
        
        system_prompt = """You are an autonomous intelligence gathering system specializing in MCP and AI security.

Your task is to generate effective search queries based on the user's goal.
Think strategically about what sources would have relevant information.

Source Types to Target:
- Academic papers (arxiv.org, semanticscholar.org)
- Code repositories (github.com, gitlab.com)
- Security advisories (CVE, NIST NVD)
- Technical blogs (medium.com, dev.to)
- Security research (exploit-db.com, hackerone.com)
- News sites (thehackernews.com, bleepingcomputer.com)
- Forums (reddit.com/r/netsec, stackoverflow.com)

OUTPUT FORMAT: Return ONLY a JSON array of query strings.

CONSTRAINTS:
- Generate diverse, actionable queries
- Mix breadth (general discovery) with depth (specific topics)
- Focus on timeless security concepts (avoid year restrictions)
- NO explanations, ONLY the JSON array"""

        user_prompt = f"""Goal: {goal}

Generate {num_queries} search queries to discover relevant security intelligence.
{context_section}

Consider:
1. What types of sources would have this information?
2. What technical terms and keywords are relevant?
3. What variations and related topics should be explored?
4. What are the most important security concerns (avoid year restrictions)?

Return ONLY a JSON array of {num_queries} diverse query strings."""

        response = self._call_llm(system_prompt, user_prompt)
        queries = self._parse_json_array(response)
        
        return queries
    
    def refine_queries(
        self,
        original_queries: List[str],
        results: List[Dict[str, Any]],
        goal: str
    ) -> List[str]:
        """
        Refine queries based on search results.
        
        Args:
            original_queries: Original queries that were used
            results: Search results obtained
            goal: Original goal
            
        Returns:
            List of refined query strings
        """
        if not results:
            return original_queries
        
        # Analyze what worked
        successful_titles = [r.get("title", "") for r in results[:10]]
        successful_urls = [r.get("url", "") for r in results[:10]]
        
        system_prompt = """You are a query refinement system for security intelligence gathering.

Analyze the results and generate improved queries that:
1. Build on successful patterns
2. Explore new angles not yet covered
3. Target similar high-quality sources
4. Avoid patterns from unsuccessful queries

OUTPUT FORMAT: Return ONLY a JSON array of query strings."""

        user_prompt = f"""Goal: {goal}

Original queries:
{json.dumps(original_queries[:5], indent=2)}

Results found (titles):
{json.dumps(successful_titles[:5], indent=2)}

Generate 10 improved queries that would find more relevant content.
Learn from what worked and explore related areas.

Return ONLY a JSON array of query strings."""

        response = self._call_llm(system_prompt, user_prompt)
        refined = self._parse_json_array(response)
        
        # Track successful patterns
        if results:
            for query in original_queries[:5]:
                self.successful_queries.append({
                    "query": query,
                    "results_count": len(results),
                    "timestamp": datetime.now().isoformat()
                })
        
        return refined if refined else original_queries
    
    def _parse_json_array(self, response: str) -> List[str]:
        """
        Parse JSON array from LLM response.
        
        Args:
            response: LLM response string
            
        Returns:
            List of parsed strings (filtered and cleaned)
        """
        if not response:
            return []
        
        try:
            # Remove markdown code blocks
            response = re.sub(r'```json\s*', '', response)
            response = re.sub(r'```\s*', '', response)
            response = response.strip()
            
            # Try to find JSON array
            json_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if json_match:
                items = json.loads(json_match.group())
                if isinstance(items, list):
                    # Clean and filter items
                    cleaned = []
                    for item in items:
                        if item is None:
                            continue
                        item_str = str(item).strip()
                        # Filter out invalid items
                        if (item_str and 
                            len(item_str) > 2 and  # Minimum length
                            not item_str.startswith('\\') and  # Not just escape char
                            item_str != ',' and  # Not just comma
                            not re.match(r'^[,\\s]+$', item_str)):  # Not just punctuation/whitespace
                            cleaned.append(item_str)
                    return cleaned
        except json.JSONDecodeError:
            pass
        
        # Fallback: extract quoted strings
        quoted = re.findall(r'"([^"]+)"', response)
        if quoted:
            # Clean and filter quoted strings
            cleaned = []
            for q in quoted:
                q = q.strip()
                if (q and 
                    len(q) > 2 and
                    not q.startswith('\\') and
                    q != ',' and
                    not re.match(r'^[,\\s]+$', q)):
                    cleaned.append(q)
            if cleaned:
                return cleaned
        
        # Last resort: split by lines
        lines = []
        for line in response.split('\n'):
            line = line.strip()
            # Remove list markers and quotes
            line = re.sub(r'^[-*\d.)\]]\s*', '', line)
            line = line.strip('"\'')
            # Remove escape characters at start
            line = re.sub(r'^\\+', '', line)
            # Filter valid lines
            if (line and 
                len(line) > 2 and
                not line.startswith('\\') and
                line != ',' and
                not re.match(r'^[,\\s]+$', line) and
                not line.startswith(',') and
                not line.endswith('\\')):
                lines.append(line)
        
        return lines[:20]
    
    def clear_cache(self):
        """Clear the keyword cache."""
        self._keyword_cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get generator statistics."""
        return {
            "cached_queries": len(self._keyword_cache),
            "successful_queries": len(self.successful_queries),
            "failed_queries": len(self.failed_queries)
        }

