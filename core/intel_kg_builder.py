"""
Intel-based Knowledge Graph Builder
Extracts entities and relationships from AI-summarized intel items.
"""

from __future__ import annotations

import json
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field

from config.llm_config import get_llm_config
from config.model_selector import get_model_selector, ModelProvider
from core.kg_manager import MCPKnowledgeGraph


@dataclass
class Entity:
    """Knowledge graph entity"""
    id: str
    name: str
    entity_type: str  # Threat, Asset, Technique, Vulnerability, etc.
    description: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    source_ids: List[str] = field(default_factory=list)  # Intel item IDs that mention this entity


@dataclass
class Relation:
    """Knowledge graph relation"""
    source_id: str
    target_id: str
    relation_type: str  # AFFECTS, EXPLOITS, MITIGATES, RELATED_TO, etc.
    description: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    source_ids: List[str] = field(default_factory=list)  # Intel item IDs that mention this relation


# Canonical name mapping: map synonyms/variations → canonical name
# This ensures 'MCP' and 'Model Context Protocol' become the same node
CANONICAL_NAMES = {
    'model context protocol': 'MCP',
    'model context protocol (mcp)': 'MCP',
    'mcp protocol': 'MCP',
    'mcp server': 'MCP Server',
    'mcp servers': 'MCP Server',
    'mcp client': 'MCP Client',
    'mcp clients': 'MCP Client',
    'mcp tool': 'MCP Tool',
    'mcp tools': 'MCP Tool',
    'mcp transport': 'MCP Transport',
    'large language model': 'LLM',
    'large language models': 'LLM',
    'llm model': 'LLM',
    'prompt injection attack': 'Prompt Injection',
    'prompt injection attacks': 'Prompt Injection',
    'direct prompt injection': 'Prompt Injection',
    'indirect prompt injection': 'Indirect Prompt Injection',
    'tool poisoning attack': 'Tool Poisoning',
    'tool poisoning attacks': 'Tool Poisoning',
    'supply chain attacks': 'Supply Chain Attack',
    'supply-chain attack': 'Supply Chain Attack',
    'data exfiltration attack': 'Data Exfiltration',
    'data leak': 'Data Exfiltration',
    'data leakage': 'Data Exfiltration',
    'privilege escalation attack': 'Privilege Escalation',
    'denial of service': 'DoS Attack',
    'denial-of-service': 'DoS Attack',
    'dos': 'DoS Attack',
    'ddos': 'DoS Attack',
    'ddos attack': 'DoS Attack',
    'api key': 'API Key',
    'api keys': 'API Key',
    'api token': 'API Key',
    'credential': 'Credentials',
    'credentials': 'Credentials',
    'sensitive data': 'Sensitive Information',
    'sensitive information': 'Sensitive Information',
    'user data': 'Sensitive Information',
    'personal data': 'Sensitive Information',
    'vulnerabilities': 'Vulnerability',
    'security vulnerability': 'Vulnerability',
    'cve': 'CVE',
    'cves': 'CVE',
    'exploit': 'Exploit',
    'exploits': 'Exploit',
    'unauthorized access': 'Unauthorized Access',
    'unauthorised access': 'Unauthorized Access',
    'jailbreak attack': 'Jailbreak',
    'jailbreak attacks': 'Jailbreak',
    'jailbreaking': 'Jailbreak',
}


# --- Entity similarity pipeline (updated: token overlap replaces Jaccard as primary) ---

# Noise words that add length but carry no discriminative meaning in threat names.
_NOISE_WORDS = frozenset([
    'attack', 'attacks', 'technique', 'techniques', 'method', 'methods',
    'via', 'using', 'based', 'related', 'type', 'types', 'vector', 'vectors',
    'issue', 'issues', 'risk', 'risks', 'threat', 'threats',
])

def _normalize_for_fuzzy(name: str) -> str:
    """Lowercase, strip non-alphanumeric, collapse whitespace."""
    normalized = re.sub(r"[^a-z0-9' ]", ' ', name.lower())
    return re.sub(r'\s+', ' ', normalized).strip()

def _normalize_semantic(name: str) -> str:
    """Semantic normalization: lowercase, remove noise words, collapse whitespace.
    
    Example:
        'MCP Tool Poisoning Attack' -> 'mcp tool poisoning'
        'Tool Poisoning'            -> 'tool poisoning'
    Both then compare well under token overlap.
    """
    tokens = _normalize_for_fuzzy(name).split()
    tokens = [t for t in tokens if t not in _NOISE_WORDS and len(t) > 1]
    return ' '.join(tokens)

def _token_overlap(a: str, b: str) -> float:
    """Token overlap ratio: |A∩B| / min(|A|, |B|).
    
    Much better than Jaccard for length-mismatched but semantically equal names:
        'MCP Tool Poisoning Attack' vs 'Tool Poisoning' -> 1.0
    """
    ta = set(_normalize_semantic(a).split())
    tb = set(_normalize_semantic(b).split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / min(len(ta), len(tb))

def _shingles(name: str, n: int = 3) -> set:
    """Create n-gram character shingles (kept as lightweight fallback)."""
    cleaned = _normalize_for_fuzzy(name).replace(' ', '')
    if len(cleaned) < n:
        return {cleaned} if cleaned else set()
    return {cleaned[i:i+n] for i in range(len(cleaned) - n + 1)}

def _jaccard_similarity(a: set, b: set) -> float:
    """Jaccard similarity between two shingle sets (fallback for short names)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)

# Semantic modifiers that signal a subtype relationship rather than a synonym.
# If the LONGER name has one of these tokens, it's a child concept, not a duplicate.
_SEMANTIC_MODIFIERS = frozenset([
    'indirect', 'direct', 'stored', 'reflected', 'blind',
    'persistent', 'transient', 'client', 'server', 'cross',
    'remote', 'local', 'authenticated', 'unauthenticated',
    'internal', 'external', 'multi', 'chained',
])

def _substring_match_type(a: str, b: str) -> str:
    """Classify a substring match as 'merge', 'subtype', or 'none'.
    
    Returns:
        'merge'   — genuine synonyms, safe to merge
        'subtype' — longer name has a semantic modifier; create hierarchy instead
        'none'    — not a substring match at all
    
    Examples:
        'MCP Tool Poisoning Attack' vs 'Tool Poisoning'  -> 'merge'  (no modifier)
        'Indirect Prompt Injection' vs 'Prompt Injection' -> 'subtype' ('indirect' is a modifier)
    """
    a_lower = a.lower().strip()
    b_lower = b.lower().strip()
    if not (a_lower in b_lower or b_lower in a_lower):
        return 'none'
    longer_str  = a_lower if len(a_lower) >= len(b_lower) else b_lower
    shorter_str = b_lower if len(a_lower) >= len(b_lower) else a_lower
    if len(shorter_str) <= 3:
        return 'none'
    longer_tokens = set(longer_str.split())
    if longer_tokens & _SEMANTIC_MODIFIERS:
        return 'subtype'  # child concept — build hierarchy, do NOT merge
    return 'merge'

def _is_substring_match(a: str, b: str, max_len_ratio: float = 1.6) -> bool:
    """Backwards-compat wrapper. Returns True only for safe merge (no modifier)."""
    a_lower = a.lower().strip()
    b_lower = b.lower().strip()
    if a_lower in b_lower or b_lower in a_lower:
        longer = max(len(a_lower), len(b_lower))
        shorter = min(len(a_lower), len(b_lower))
        if shorter > 3 and longer / shorter <= max_len_ratio:
            return _substring_match_type(a, b) == 'merge'
    return False

# ── Multi-signal scoring system ─────────────────────────────────────────────
# Each signal contributes a float weight; the sum determines the decision.
# No single rule can override the decision alone.

@dataclass
class SimilaritySignals:
    """Collected signals for a candidate entity pair."""
    token_overlap: float       # 0.0–1.0, from _token_overlap()
    jaccard: float             # 0.0–1.0, from _jaccard_similarity() on shingles
    is_same_type: bool         # entity_type == candidate.entity_type
    is_substring: bool         # one name is contained in the other
    has_modifier: bool         # longer name carries a semantic modifier
    name_len_ratio: float      # min_len / max_len (0.0–1.0)

    def total_score(self) -> float:
        """Weighted sum of all signals."""
        score = 0.0
        if self.token_overlap >= 0.70:
            score += 2.0
        elif self.token_overlap >= 0.50:
            score += 1.0
        if self.is_same_type:
            score += 1.0
        if self.is_substring:
            score += 0.5
        if self.has_modifier:
            score -= 1.5
        return score


# Decision thresholds (tunable after observing logs)
_MERGE_THRESHOLD = 3.0      # score >= 3.0 → merge
_SUBCLASS_THRESHOLD = 2.0   # 2.0 <= score < 3.0 → subclass
# score < 2.0 → new node

# Patterns that identify concrete instances (not abstract threat classes).
_INSTANCE_PATTERNS = [
    re.compile(r'^cve-\d{4}-\d+$', re.IGNORECASE),
    re.compile(r'^cwe-\d+$', re.IGNORECASE),
    re.compile(r'^ghsa-[a-z0-9-]+$', re.IGNORECASE),
    re.compile(r'^ms\d{2}-\d{3}$', re.IGNORECASE),
    re.compile(r'^edb-\d+$', re.IGNORECASE),
    re.compile(r'^\d{4}-\d{4,}$'),
]

# Class-level entity types that instances can be linked to.
_CLASS_ENTITY_TYPES = frozenset(['Threat', 'Technique', 'Vulnerability'])

_INSTANCE_LINK_THRESHOLD = 0.40

# Regex that detects whether the name contains a version/ID-like numeric fragment.
_HAS_NUMERIC_ID = re.compile(r'\d{2,}')


def _instance_score(name: str, entity_type: str) -> float:
    """Multi-signal instance detection.

    Returns a float score; >= 2.0 means this is a concrete instance.
    """
    score = 0.0
    stripped = name.strip()
    # Signal 1: regex pattern match (strong)
    if any(p.match(stripped) for p in _INSTANCE_PATTERNS):
        score += 2.0
    # Signal 2: name contains numeric ID fragment (weak)
    if _HAS_NUMERIC_ID.search(stripped):
        score += 1.0
    # Signal 3: entity_type already labelled as Vulnerability (weak)
    if entity_type == 'Vulnerability':
        score += 0.5
    return score


def _compute_signals(entity_name: str, entity_type: str,
                     candidate_name: str, candidate_type: str) -> SimilaritySignals:
    """Compute all similarity signals between two entity names."""
    overlap = _token_overlap(entity_name, candidate_name)
    jacc = _jaccard_similarity(_shingles(entity_name), _shingles(candidate_name))
    same_type = (entity_type == candidate_type)
    substr_type = _substring_match_type(entity_name, candidate_name)
    is_substr = (substr_type != 'none')
    has_mod = (substr_type == 'subtype')

    a_len = len(entity_name.strip())
    b_len = len(candidate_name.strip())
    ratio = min(a_len, b_len) / max(a_len, b_len) if max(a_len, b_len) > 0 else 0.0

    return SimilaritySignals(
        token_overlap=overlap,
        jaccard=jacc,
        is_same_type=same_type,
        is_substring=is_substr,
        has_modifier=has_mod,
        name_len_ratio=ratio,
    )




class IntelKnowledgeGraphBuilder:
    """
    Builds knowledge graphs from intelligence items.
    
    Features:
    - Entity extraction from summaries
    - Relationship extraction
    - Entity disambiguation with canonical name mapping
    - Graph construction
    """
    
    def __init__(self, llm_config=None, db_manager=None, provider=None):
        """Initialize the builder"""
        self.llm_config = llm_config or get_llm_config()
        self.db_manager = db_manager
        self.provider = provider
        self.entities: Dict[str, Entity] = {}  # entity_id -> Entity
        self.relations: List[Relation] = []
        self.entity_name_to_id: Dict[str, str] = {}  # For disambiguation
        self.intel_items_map: Dict[str, Dict[str, Any]] = {}  # item_id -> {url, title, source_type}
        
        # Get model selection
        self.model_selector = get_model_selector()
        self.model_selection = self.model_selector.get_selection()
    
    def build_from_intel_items_generator(
        self,
        intel_items: List[Dict[str, Any]],
        use_ai: bool = True
    ):
        """
        Generator for build_from_intel_items.
        Yields: (graph_object, update_dict)
        """
        print(f"[IntelKG] Building knowledge graph (stream) from {len(intel_items)} intel items...")
        
        if self.entities is None: self.entities = {}
        if self.relations is None: self.relations = []
        if self.entity_name_to_id is None: self.entity_name_to_id = {}
        if self.intel_items_map is None: self.intel_items_map = {}

        # Initial yield
        yield self._build_mcp_graph(), {
            "status": "start",
            "total": len(intel_items),
            "current": 0,
            "graph": None
        }
        
        processed_count = 0
        skipped_count = 0
        
        # Pre-filter items with valid text — use content FIRST, then ai_summary, then title
        valid_items = []
        for item in intel_items:
            text = item.get('content') or item.get('ai_summary') or item.get('title', '')
            if not text or len(text.strip()) < 10:
                skipped_count += 1
                continue
            item_id = item.get('id', '') or f"item-{len(valid_items)}"
            self.intel_items_map[item_id] = {
                'url': item.get('url', ''),
                'title': item.get('title', 'Unknown'),
                'source_type': item.get('source_type', 'unknown')
            }
            valid_items.append((item, item_id, text[:2000]))
        
        print(f"[IntelKG] Valid items: {len(valid_items)} (skipped {skipped_count} items with no text)")
        
        if use_ai:
            BATCH_SIZE = 5
            for batch_start in range(0, len(valid_items), BATCH_SIZE):
                batch = valid_items[batch_start:batch_start + BATCH_SIZE]
                batch_end = min(batch_start + BATCH_SIZE, len(valid_items))
                print(f"[IntelKG] Batch extracting items {batch_start+1}-{batch_end}/{len(valid_items)}...")
                
                # Try batch AI extraction
                batch_results = self._extract_batch_with_ai(batch)
                
                for idx, (item, item_id, text) in enumerate(batch):
                    processed_count += 1
                    if batch_results and idx in batch_results:
                        entities, relations = batch_results[idx]
                        print(f"[IntelKG] AI extracted: {len(entities)} entities, {len(relations)} relations from item {item_id[:16]}")
                    else:
                        # Fallback to simple extraction for this item
                        entities, relations = self._extract_simple(text, item_id)
                        print(f"[IntelKG] Simple extracted: {len(entities)} entities, {len(relations)} relations from item {item_id[:16]}")
                    
                    # If AI returned nothing, also fallback
                    if not entities and not relations:
                        entities, relations = self._extract_simple(text, item_id)
                    
                    for entity in entities:
                        self._add_entity(entity)
                    for relation in relations:
                        self._add_relation(relation)
                
                # Yield update after each batch
                current_graph = self._build_mcp_graph()
                yield current_graph, {
                    "status": "progress",
                    "total": len(valid_items),
                    "current": processed_count,
                    "item_title": f"Batch {batch_start+1}-{batch_end}",
                    "graph": current_graph.to_vis_format()
                }
        else:
            # Non-AI path: simple extraction per item
            for item, item_id, text in valid_items:
                processed_count += 1
                entities, relations = self._extract_simple(text, item_id)
                for entity in entities:
                    self._add_entity(entity)
                for relation in relations:
                    self._add_relation(relation)
                
                if processed_count % 10 == 0 or processed_count == len(valid_items):
                    current_graph = self._build_mcp_graph()
                    yield current_graph, {
                        "status": "progress",
                        "total": len(valid_items),
                        "current": processed_count,
                        "item_title": item.get('title', 'Unknown'),
                        "graph": current_graph.to_vis_format()
                    }
            
        # Final yield
        final_graph = self._build_mcp_graph()
        print(f"[IntelKG] ✓ Complete: {len(self.entities)} entities, {len(self.relations)} relations from {processed_count} items")
        yield final_graph, {
            "status": "complete",
            "total": len(valid_items),
            "current": len(valid_items),
            "graph": final_graph.to_vis_format()
        }

    def load_from_mcp_graph(self, graph: MCPKnowledgeGraph):
        """
        Load internal state from existing MCPKnowledgeGraph.
        This enables incremental updates without losing existing data.
        """
        print(f"[IntelKG] Loading existing graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        
        # Load entities
        count_entities = 0
        for node_id, node_data in graph.nodes.items():
            # Skip if already loaded
            if node_id in self.entities:
                continue
                
            entity_name = node_data.get('label', node_id)
            entity = Entity(
                id=node_id,
                name=entity_name,
                entity_type=node_data.get('type', 'Unknown'),
                description=node_data.get('properties', {}).get('description', ''),
                properties=node_data.get('properties', {}),
                source_ids=node_data.get('properties', {}).get('source_ids', [])
            )
            self.entities[node_id] = entity
            self.entity_name_to_id[entity_name.lower()] = node_id
            count_entities += 1
            
        # Load relations (with dedup check)
        count_relations = 0
        existing_rel_keys = set()
        for rel in self.relations:
            existing_rel_keys.add((rel.source_id, rel.target_id, rel.relation_type))
        
        for edge in graph.edges:
            rel_key = (edge.get('source'), edge.get('target'), edge.get('relationship'))
            if rel_key in existing_rel_keys:
                continue
            
            relation = Relation(
                source_id=edge.get('source'),
                target_id=edge.get('target'),
                relation_type=edge.get('relationship'),
                properties=edge.get('properties', {}),
                source_ids=edge.get('properties', {}).get('source_ids', [])
            )
            self.relations.append(relation)
            existing_rel_keys.add(rel_key)
            count_relations += 1
            
        print(f"[IntelKG] Loaded {count_entities} entities and {count_relations} relations from existing graph")

    def build_from_intel_items(
        self,
        intel_items: List[Dict[str, Any]],
        use_ai: bool = True
    ) -> MCPKnowledgeGraph:
        """
        Build knowledge graph from intelligence items.
        Delegates to build_from_intel_items_generator and returns final graph.
        """
        final_graph = None
        for graph, update in self.build_from_intel_items_generator(intel_items, use_ai=use_ai):
            final_graph = graph
        return final_graph or self._build_mcp_graph()
    
    def build_knowledge_graph(
        self,
        intel_items: List[Any],
        use_ai: bool = True
    ) -> MCPKnowledgeGraph:
        """
        Build knowledge graph from IntelItem dataclass objects (alternative interface).
        
        Args:
            intel_items: List of IntelItem dataclass objects
            use_ai: Whether to use AI for entity/relation extraction
        
        Returns:
            MCPKnowledgeGraph
        """
        # Convert dataclass to dict
        intel_dicts = []
        for item in intel_items:
            if hasattr(item, 'to_dict'):
                intel_dicts.append(item.to_dict())
            elif hasattr(item, '__dict__'):
                intel_dicts.append(item.__dict__)
            else:
                intel_dicts.append({
                    'id': getattr(item, 'id', ''),
                    'title': getattr(item, 'title', ''),
                    'content': getattr(item, 'content', ''),
                    'ai_summary': getattr(item, 'ai_summary', None) or getattr(item, 'summary', None),
                    'url': getattr(item, 'url', ''),
                    'source_type': getattr(item, 'source_type', 'unknown').value if hasattr(getattr(item, 'source_type', ''), 'value') else str(getattr(item, 'source_type', 'unknown'))
                })
        
        return self.build_from_intel_items(intel_dicts, use_ai=use_ai)
    
    def _extract_batch_with_ai(self, batch: List[Tuple]) -> Optional[Dict[int, Tuple[List[Entity], List[Relation]]]]:
        """
        Extract entities and relations from a batch of items in a single LLM call.
        
        Args:
            batch: List of (item_dict, item_id, summary_text) tuples
            
        Returns:
            Dict mapping batch index -> (entities, relations), or None if failed
        """
        import os
        import requests
        
        # Build batch prompt — keep it SMALL to avoid hitting token limits
        items_text = ""
        for idx, (item, item_id, summary) in enumerate(batch):
            title = (item.get('title') or 'Unknown')[:80]
            # Truncate text aggressively — 300 chars is enough for entity extraction
            items_text += f"\n{idx+1}. [{title}]: {summary[:300]}\n"
        
        # Build existing entity names list for LLM to reuse
        existing_names = list(self.entity_name_to_id.keys())[:50]  # Top 50 known entities
        existing_names_str = ', '.join(n.title() for n in existing_names) if existing_names else 'None yet'
        
        prompt = f"""Extract security entities and relationships from these MCP security items.

Entity types: Threat, Vulnerability, Technique, Component, Asset, Mitigation
Relation types: AFFECTS, EXPLOITS, MITIGATES, TARGETS, RELATED_TO

IMPORTANT DEDUPLICATION RULES:
- If an entity matches one of the EXISTING ENTITIES below, you MUST use the EXACT same name.
- Do NOT create slight variations like "Prompt Injection Attack" if "Prompt Injection" already exists.
- Only create a new entity if it is genuinely different from all existing ones.
- Keep entity names short (1-3 words). Merge similar concepts into one entity.

EXISTING ENTITIES (reuse these names exactly): {existing_names_str}

{items_text}

Return COMPACT JSON (no extra whitespace):
{{"items":[{{"id":1,"entities":[{{"name":"...","type":"...","description":"..."}}],"relations":[{{"source":"...","target":"...","type":"...","description":"..."}}]}}]}}"""

        # Call LLM
        model = os.getenv("LITELLM_MODEL")
        if hasattr(self.llm_config, 'get_model_for_role'):
            model = self.llm_config.get_model_for_role("INTEL_SUMMARIZER") or model
        if not model:
            print("[IntelKG] Warning: LITELLM_MODEL not configured for batch extraction")
            return None
        
        api_base = os.getenv("LITELLM_API_BASE", "http://localhost:4000")
        api_key = os.getenv("LITELLM_API_KEY", "sk-1234")
        temperature = float(os.getenv("LITELLM_TEMPERATURE", "0.1"))
        
        api_url = api_base
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
                {"role": "system", "content": "Extract security entities and relationships. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": temperature,
            "max_tokens": 8000
        }
        
        try:
            response = requests.post(api_url, headers=headers, json=payload, timeout=150)
            if not response.ok:
                # One retry on transient server errors
                print(f"[IntelKG] LLM call returned {response.status_code}, retrying once...")
                response = requests.post(api_url, headers=headers, json=payload, timeout=150)
            
            if response.status_code != 200:
                print(f"[IntelKG] Batch LLM HTTP {response.status_code}: {response.text[:200]}")
                return None
            
            data = response.json()
            content = ""
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0].get("message", {}).get("content", "")
            elif "message" in data:
                content = data["message"].get("content", "")
            else:
                print(f"[IntelKG] Unexpected batch response format: {list(data.keys())}")
                return None
            
            if not content or not content.strip():
                print(f"[IntelKG] Batch LLM returned empty content. Response keys: {list(data.keys())}")
                if "choices" in data:
                    print(f"[IntelKG]   choices[0]: {str(data['choices'][0])[:200]}")
                return None
            
            # Parse JSON response - strip markdown code fences
            content = content.strip()
            # Remove ```json ... ``` wrapper
            if content.startswith("```"):
                # Find the closing ```
                lines = content.split("\n")
                json_lines = []
                inside = False
                for line in lines:
                    if line.strip().startswith("```") and not inside:
                        inside = True
                        continue
                    elif line.strip() == "```" and inside:
                        break
                    elif inside:
                        json_lines.append(line)
                if json_lines:
                    content = "\n".join(json_lines)
            
            content = content.strip()
            if not content:
                print(f"[IntelKG] Batch content empty after stripping markdown")
                return None
            
            print(f"[IntelKG] Batch LLM raw content (first 100 chars): {content[:100]}...")
            
            parsed = json.loads(content)
            
            # Build results dict
            results = {}
            for item_data in parsed.get("items", []):
                item_idx = item_data.get("id", 0) - 1  # Convert 1-indexed to 0-indexed
                if item_idx < 0 or item_idx >= len(batch):
                    continue
                
                _, item_id, _ = batch[item_idx]
                entities = []
                relations = []
                
                for ent_data in item_data.get("entities", []):
                    entity = Entity(
                        id=self._generate_entity_id(ent_data.get("name", "unknown")),
                        name=ent_data.get("name", "Unknown"),
                        entity_type=ent_data.get("type", "Entity"),
                        description=ent_data.get("description", ""),
                        source_ids=[item_id]
                    )
                    entities.append(entity)
                
                for rel_data in item_data.get("relations", []):
                    relation = Relation(
                        source_id=self._generate_entity_id(rel_data.get("source", "")),
                        target_id=self._generate_entity_id(rel_data.get("target", "")),
                        relation_type=rel_data.get("type", "RELATED_TO"),
                        description=rel_data.get("description", ""),
                        source_ids=[item_id]
                    )
                    relations.append(relation)
                
                results[item_idx] = (entities, relations)
            
            total_ent = sum(len(e) for e, r in results.values())
            total_rel = sum(len(r) for e, r in results.values())
            print(f"[IntelKG] Batch extracted: {total_ent} entities, {total_rel} relations from {len(results)}/{len(batch)} items")
            return results
            
        except json.JSONDecodeError as e:
            print(f"[IntelKG] Batch JSON parse error: {e}")
            return None
        except Exception as e:
            print(f"[IntelKG] Batch LLM call failed: {e}")
            return None
    
    def _extract_with_ai(self, text: str, source_id: str) -> Tuple[List[Entity], List[Relation]]:
        """
        Extract entities and relations using AI.
        
        Uses iterative approach:
        1. Extract entities and relations from text
        2. Consider existing graph context
        3. Refine extraction based on relationships
        
        Args:
            text: Text to extract from
            source_id: Source intel item ID
        
        Returns:
            Tuple of (entities, relations)
        """
        entities = []
        relations = []
        
        try:
            # Get existing graph context for better extraction
            existing_context = self._get_existing_graph_context()
            
            # Build prompt using iterative approach
            prompt = f"""You are extracting security knowledge from MCP (Model Context Protocol) security intelligence.

Your task is to extract entities (threats, vulnerabilities, techniques, components) and their relationships.

Existing Knowledge Graph Context:
{existing_context}

New Intelligence Text:
{text[:2000]}

Instructions:
1. Extract ALL relevant entities from the text:
   - Threats: Security threats, attacks, exploits (PRIORITY)
   - Vulnerabilities: Security weaknesses, CVEs, CWEs (PRIORITY)
   - Techniques: Attack techniques (prompt injection, tool poisoning, etc.) (PRIORITY)
   - Components: MCP Server, MCP Client, Tools, Protocols
   - Assets: Data, Credentials, Network resources
   
   IMPORTANT: Do NOT extract AI vendors (e.g. OpenAI, Anthropic, Google, Microsoft, Meta) as entities unless they are the specific TARGET of an attack. Focus on the technology, risks, and components, not the companies.

2. Extract relationships between entities:
   - AFFECTS: Threat affects component/asset
   - EXPLOITS: Technique exploits vulnerability
   - MITIGATES: Control mitigates threat
   - RELATED_TO: General relationship
   - DEPENDS_ON: Component depends on another
   - TARGETS: Attack targets asset

3. Consider the existing graph context - avoid duplicating entities that already exist, but add new relationships.

4. Be specific and accurate - only extract information that is clearly stated in the text.Group unknown or general entities under a generic 'MCP Ecosystem' node if they don't fit specific categories.

Return ONLY a JSON object with this exact structure:
{{
    "entities": [
        {{
            "name": "specific entity name",
            "type": "Threat|Vulnerability|Technique|Component|Tool|Asset",
            "description": "brief description from the text"
        }}
    ],
    "relations": [
        {{
            "source": "source entity name",
            "target": "target entity name",
            "type": "AFFECTS|EXPLOITS|MITIGATES|RELATED_TO|DEPENDS_ON|TARGETS",
            "description": "how they relate"
        }}
    ]
}}"""

            # Call LLM
            response = self._call_llm(prompt)
            
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
                    
                    # Convert to Entity objects
                    for ent_data in data.get("entities", []):
                        entity = Entity(
                            id=self._generate_entity_id(ent_data["name"]),
                            name=ent_data["name"],
                            entity_type=ent_data.get("type", "Entity"),
                            description=ent_data.get("description", ""),
                            source_ids=[source_id]
                        )
                        entities.append(entity)
                    
                    # Convert to Relation objects
                    for rel_data in data.get("relations", []):
                        relation = Relation(
                            source_id=self._generate_entity_id(rel_data["source"]),
                            target_id=self._generate_entity_id(rel_data["target"]),
                            relation_type=rel_data.get("type", "RELATED_TO"),
                            description=rel_data.get("description", ""),
                            source_ids=[source_id]
                        )
                        relations.append(relation)
                        
                except json.JSONDecodeError as e:
                    print(f"[IntelKG] Failed to parse AI response: {e}")
                    print(f"[IntelKG] Response: {response[:500]}")
        
        except Exception as e:
            print(f"[IntelKG] AI extraction error: {e}")
        
        return entities, relations
    
    def _extract_simple(self, text: str, source_id: str) -> Tuple[List[Entity], List[Relation]]:
        """
        Improved rule-based extraction.
                
        Args:
            text: Text to extract from
            source_id: Source intel item ID
        
        Returns:
            Tuple of (entities, relations)
        """
        entities = []
        relations = []
        
        # Patterns are deduplicated: each term appears in exactly one type.
        # Technique = attack methods; Threat = vulnerability/risk categories;
        # Component = MCP architecture parts; Asset = protected resources.
        mcp_patterns = {
            "Technique": [
                r"prompt\s+injection",
                r"indirect\s+prompt\s+injection",
                r"tool\s+poisoning",
                r"tool\s+shadowing",
                r"context\s+injection",
                r"supply\s+chain\s+attack",
                r"jailbreak",
                r"data\s+exfiltration",
            ],
            "Threat": [
                r"unauthorized\s+access",
                r"privilege\s+escalation",
                r"denial\s+of\s+service",
                r"security\s+breach",
            ],
            "Vulnerability": [
                r"vulnerability",
                r"exploit",
            ],
            "Component": [
                r"mcp\s+server",
                r"mcp\s+client",
                r"model\s+context\s+protocol",
                r"mcp\s+tool",
                r"mcp\s+transport",
            ],
            "Asset": [
                r"credential",
                r"api\s+key",
                r"user\s+data",
                r"sensitive\s+information"
            ]
        }
        
        text_lower = text.lower()
        extracted_patterns = {}
        
        # Extract entities using patterns
        for entity_type, patterns in mcp_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text_lower, re.IGNORECASE)
                for match in matches:
                    entity_name = match.group(0).title()
                    entity_id = self._generate_entity_id(entity_name)
                    
                    if entity_id not in extracted_patterns:
                        # Get context around the match
                        start = max(0, match.start() - 50)
                        end = min(len(text), match.end() + 50)
                        context = text[start:end].strip()
                        
                        entity = Entity(
                            id=entity_id,
                            name=entity_name,
                            entity_type=entity_type,
                            description=context[:200] if len(context) > 200 else context,
                            source_ids=[source_id]
                        )
                        entities.append(entity)
                        extracted_patterns[entity_id] = entity
        
        # NOTE: Bare acronym extraction (MCP, API, LLM, AI, etc.) removed.
        # These are too generic and create massive duplication without meaningful
        # graph structure. Specific MCP component patterns above are sufficient.
        
        # Create relations based on co-occurrence and patterns
        threat_entities = [e for e in entities if e.entity_type in ["Threat", "Technique"]]
        component_entities = [e for e in entities if e.entity_type == "Component"]
        asset_entities = [e for e in entities if e.entity_type == "Asset"]
        all_entities = entities
        
        # Threat -> Component relations (more aggressive matching)
        for threat in threat_entities:
            for component in component_entities:
                # Check if they appear close together in text
                threat_pos = text_lower.find(threat.name.lower())
                component_pos = text_lower.find(component.name.lower())
                if threat_pos >= 0 and component_pos >= 0 and abs(threat_pos - component_pos) < 500:
                    relation = Relation(
                        source_id=threat.id,
                        target_id=component.id,
                        relation_type="AFFECTS",
                        description=f"{threat.name} affects {component.name}",
                        source_ids=[source_id]
                    )
                    relations.append(relation)
        
        # Threat -> Asset relations
        for threat in threat_entities:
            for asset in asset_entities:
                threat_pos = text_lower.find(threat.name.lower())
                asset_pos = text_lower.find(asset.name.lower())
                if threat_pos >= 0 and asset_pos >= 0 and abs(threat_pos - asset_pos) < 500:
                    relation = Relation(
                        source_id=threat.id,
                        target_id=asset.id,
                        relation_type="TARGETS",
                        description=f"{threat.name} targets {asset.name}",
                        source_ids=[source_id]
                    )
                    relations.append(relation)
        
        # Component -> Component relations (dependencies and connections)
        for i, comp1 in enumerate(component_entities):
            for comp2 in component_entities[i+1:]:
                comp1_pos = text_lower.find(comp1.name.lower())
                comp2_pos = text_lower.find(comp2.name.lower())
                if comp1_pos >= 0 and comp2_pos >= 0 and abs(comp1_pos - comp2_pos) < 500:
                    relation = Relation(
                        source_id=comp1.id,
                        target_id=comp2.id,
                        relation_type="RELATED_TO",
                        description=f"{comp1.name} related to {comp2.name}",
                        source_ids=[source_id]
                    )
                    relations.append(relation)
        
        
        # Technique -> Threat relations
        technique_entities = [e for e in entities if e.entity_type == "Technique"]
        for technique in technique_entities:
            for threat in threat_entities:
                if technique.name.lower() in threat.name.lower() or threat.name.lower() in technique.name.lower():
                    relation = Relation(
                        source_id=technique.id,
                        target_id=threat.id,
                        relation_type="EXPLOITS",
                        description=f"{technique.name} exploits {threat.name}",
                        source_ids=[source_id]
                    )
                    relations.append(relation)
        
        print(f"[IntelKG] Simple extraction: {len(entities)} entities, {len(relations)} relations")
        return entities, relations
    
    def _add_entity(self, entity: Entity):
        """Add entity with multi-signal scoring for disambiguation.

        Pipeline:
          Stage 0: Instance detection (multi-signal) — route to _add_instance_entity
          Stage 1: Exact canonical match — fast path
          Stage 2: Score all existing candidates — single pass, multi-signal
          Stage 3: Act on best candidate score:
                     >= 3.0 → merge
                     >= 2.0 → subclass (SUBCLASS_OF relation)
                     <  2.0 → new node
        """
        # Normalize entity name using canonical mapping
        entity.name = self._normalize_entity_name(entity.name)
        entity.id = self._generate_entity_id(entity.name)

        # ── Quality guard: reject structurally-weak names ──────────────────────
        # These patterns produce meaningless KG nodes (e.g. "Update 0.11.1",
        # "v2.3", "Release 1.0.0") that describe software releases, not threats.
        _name_stripped = entity.name.strip()
        _name_lower    = _name_stripped.lower()

        # 1. Too short to be meaningful
        if len(_name_stripped) < 4:
            print(f"[IntelKG] decision=skip reason=too_short entity=\"{entity.name}\"")
            return

        # 2. Pure version string  e.g. "0.11.1", "v2.3.1", "1.0"
        if re.match(r'^v?\d+(\.\d+){1,3}$', _name_stripped):
            print(f"[IntelKG] decision=skip reason=version_only entity=\"{entity.name}\"")
            return

        # 3. "Update/Release/Patch/Fix + version"  e.g. "Update 0.11.1", "Release 2.0"
        if re.match(
            r'^(update|release|patch|fix|hotfix|version)\s+v?\d+(\.\d+)*$',
            _name_lower
        ):
            print(f"[IntelKG] decision=skip reason=release_label entity=\"{entity.name}\"")
            return

        # 4. Purely numeric names  e.g. "12345"
        if _name_stripped.isdigit():
            print(f"[IntelKG] decision=skip reason=numeric_only entity=\"{entity.name}\"")
            return

        # ── Stage 0: Instance routing (multi-signal) ──────────────────────────

        inst_score = _instance_score(entity.name, entity.entity_type)
        if inst_score >= 2.0:
            print(f"[IntelKG] decision=instance score={inst_score:.1f} entity=\"{entity.name}\"")
            self._add_instance_entity(entity)
            return

        # ── Stage 1: Exact canonical match (fast path) ────────────────────────
        existing_id = self.entity_name_to_id.get(entity.name.lower())
        if existing_id and existing_id in self.entities:
            print(f"[IntelKG] decision=merge score=exact entity=\"{entity.name}\" -> \"{self.entities[existing_id].name}\"")
            self._merge_into_existing(existing_id, entity)
            return

        # ── Stage 2: Score all candidates in a single pass ────────────────────
        if len(entity.name) > 3:
            best_id = None
            best_signals = None
            best_score = -1.0

            for cand_name, cand_id in self.entity_name_to_id.items():
                if cand_id not in self.entities:
                    continue
                signals = _compute_signals(
                    entity.name, entity.entity_type,
                    cand_name, self.entities[cand_id].entity_type,
                )
                s = signals.total_score()
                if s > best_score:
                    best_score = s
                    best_id = cand_id
                    best_signals = signals

            # ── Stage 3: Act on best score ────────────────────────────────────
            if best_id and best_id in self.entities and best_signals:
                candidate = self.entities[best_id]
                sig = best_signals  # shorthand for logging

                if best_score >= _MERGE_THRESHOLD:
                    print(
                        f"[IntelKG] decision=merge score={best_score:.1f} "
                        f"entity=\"{entity.name}\" -> \"{candidate.name}\" "
                        f"[overlap={sig.token_overlap:.2f} same_type={sig.is_same_type} "
                        f"substr={sig.is_substring} modifier={sig.has_modifier}]"
                    )
                    self._merge_into_existing(best_id, entity)
                    return

                if best_score >= _SUBCLASS_THRESHOLD:
                    # Determine child/parent: the entity with the modifier is the child
                    entity_tokens = set(entity.name.lower().split())
                    if entity_tokens & _SEMANTIC_MODIFIERS:
                        child_name, parent_name = entity.name, candidate.name
                    else:
                        child_name, parent_name = candidate.name, entity.name
                    print(
                        f"[IntelKG] decision=subclass score={best_score:.1f} "
                        f"child=\"{child_name}\" parent=\"{parent_name}\" "
                        f"[overlap={sig.token_overlap:.2f} same_type={sig.is_same_type} "
                        f"substr={sig.is_substring} modifier={sig.has_modifier}]"
                    )
                    # Fall through to Stage 4 — register as new node, then add relation

        # ── Stage 4: Register new node ────────────────────────────────────────
        self.entities[entity.id] = entity
        self.entity_name_to_id[entity.name.lower()] = entity.id
        print(f"[IntelKG] decision=new entity=\"{entity.name}\" type={entity.entity_type}")

        # If this entity carries a semantic modifier, try to link it as a subclass
        # to an existing parent node (the one without the modifier).
        entity_tokens = set(entity.name.lower().split())
        if entity_tokens & _SEMANTIC_MODIFIERS:
            for existing_name, existing_id in self.entity_name_to_id.items():
                if existing_id == entity.id or existing_id not in self.entities:
                    continue
                if _substring_match_type(entity.name, existing_name) == 'subtype':
                    subclass_rel = Relation(
                        source_id=entity.id,
                        target_id=existing_id,
                        relation_type="SUBCLASS_OF",
                        description=f"{entity.name} is a subtype of {self.entities[existing_id].name}",
                        source_ids=list(entity.source_ids)
                    )
                    self._add_relation(subclass_rel)
                    break  # one parent is enough


    def _add_instance_entity(self, entity: Entity):
        """Add a concrete instance entity and link it to the best matching class node."""
        self.entities[entity.id] = entity
        self.entity_name_to_id[entity.name.lower()] = entity.id

        best_match_id = None
        best_score = 0.0

        # Match instance description against existing class node names.
        instance_text = f"{entity.name} {entity.description}"

        for existing_id, existing in self.entities.items():
            if existing.id == entity.id:
                continue
            if existing.entity_type not in _CLASS_ENTITY_TYPES:
                continue
            score = _token_overlap(instance_text, existing.name)
            if score > best_score:
                best_score = score
                best_match_id = existing.id

        if best_score >= _INSTANCE_LINK_THRESHOLD and best_match_id:
            parent = self.entities[best_match_id]
            print(
                f"[IntelKG] decision=instance_link entity=\"{entity.name}\" "
                f"INSTANCE_OF \"{parent.name}\" overlap={best_score:.2f}"
            )
            rel = Relation(
                source_id=entity.id,
                target_id=parent.id,
                relation_type="INSTANCE_OF",
                description=f"{entity.name} is an instance of {parent.name}",
                source_ids=list(entity.source_ids)
            )
            self._add_relation(rel)
        else:
            print(
                f"[IntelKG] decision=instance_orphan entity=\"{entity.name}\" "
                f"best_overlap={best_score:.2f} (no class match)"
            )


    def _merge_into_existing(self, existing_id: str, entity: Entity):
        """Merge entity into an existing entity by ID."""
        existing = self.entities[existing_id]
        # Keep longer/better description
        if len(entity.description) > len(existing.description):
            existing.description = entity.description
        # Dedup source_ids
        existing_sources = set(existing.source_ids)
        for sid in entity.source_ids:
            if sid not in existing_sources:
                existing.source_ids.append(sid)
                existing_sources.add(sid)
        # Update entity_id for relations
        entity.id = existing_id
    
    def _add_relation(self, relation: Relation):
        """Add relation (skip if entities don't exist — no ghost nodes)"""
        # Skip relations with missing entities instead of creating placeholder ghosts
        if relation.source_id not in self.entities:
            print(f"[IntelKG] Skipping relation: source entity '{relation.source_id}' not found")
            return
        
        if relation.target_id not in self.entities:
            print(f"[IntelKG] Skipping relation: target entity '{relation.target_id}' not found")
            return
        
        # Check for duplicate relations
        existing = next(
            (r for r in self.relations 
             if r.source_id == relation.source_id 
             and r.target_id == relation.target_id 
             and r.relation_type == relation.relation_type),
            None
        )
        
        if existing:
            # Merge relation
            existing.description = existing.description or relation.description
            existing.source_ids.extend(relation.source_ids)
        else:
            # Add new relation
            self.relations.append(relation)
    
    def _build_mcp_graph(self) -> MCPKnowledgeGraph:
        """Build MCPKnowledgeGraph from extracted entities and relations"""
        graph = MCPKnowledgeGraph()
        graph.metadata["name"] = "MCP Intelligence Knowledge Graph"
        graph.metadata["entities_count"] = len(self.entities)
        graph.metadata["relations_count"] = len(self.relations)
        
        # Collect all source URLs for each entity
        entity_source_urls = {}
        for entity in self.entities.values():
            urls = []
            for source_id in entity.source_ids:
                if source_id in self.intel_items_map:
                    url = self.intel_items_map[source_id].get('url', '')
                    if url:
                        urls.append(url)
            entity_source_urls[entity.id] = list(set(urls))  # Remove duplicates
        
        # Add entities as nodes
        for entity in self.entities.values():
            source_urls = entity_source_urls.get(entity.id, [])
            graph.add_node(
                node_id=entity.id,
                label=entity.name,
                node_type=entity.entity_type,
                properties={
                    "description": entity.description,
                    "source_count": len(entity.source_ids),
                    "sources": entity.source_ids,  # All source IDs
                    "source_urls": source_urls,  # All URLs (no limit)
                    "primary_url": source_urls[0] if source_urls else None  # First URL for quick access
                }
            )
        
        # Add relations as edges
        for relation in self.relations:
            # Collect source URLs for this relation
            relation_urls = []
            for source_id in relation.source_ids:
                if source_id in self.intel_items_map:
                    url = self.intel_items_map[source_id].get('url', '')
                    if url:
                        relation_urls.append(url)
            
            graph.add_edge(
                source_id=relation.source_id,
                target_id=relation.target_id,
                relationship=relation.relation_type,
                properties={
                    "description": relation.description,
                    "source_count": len(relation.source_ids),
                    "sources": relation.source_ids,  # All source IDs
                    "source_urls": list(set(relation_urls))  # All URLs (no limit)
                }
            )
        
        # --- Post-processing: Ensure Graph Connectivity ---
        # Find connected components and link isolated ones to the Hub
        if len(graph.nodes) > 0:
            # 1. Build adjacency list for traversal
            adj = {node_id: [] for node_id in graph.nodes}
            for edge in graph.edges:
                if edge['source'] in adj: adj[edge['source']].append(edge['target'])
                if edge['target'] in adj: adj[edge['target']].append(edge['source']) # Treat as undirected for connectivity
            
            # 2. Find connected components (BFS)
            visited = set()
            components = []
            
            for node_id in graph.nodes:
                if node_id not in visited:
                    component = []
                    queue = [node_id]
                    visited.add(node_id)
                    while queue:
                        curr = queue.pop(0)
                        component.append(curr)
                        for neighbor in adj.get(curr, []):
                            if neighbor not in visited:
                                visited.add(neighbor)
                                queue.append(neighbor)
                                component.append(neighbor) # Append early to avoid duplicates in queue, though set handles it
                    components.append(list(set(component))) # Ensure unique
            
            # 3. Identify Main Hub (MCP Security)
            hub_node_id = None
            # Try to find existing "MCP Security" node
            for node_id, node in graph.nodes.items():
                if "MCP Security" in node['label'] or node['label'] == "MCP":
                    hub_node_id = node_id
                    break
            
            # If no hub exists, create one
            if not hub_node_id:
                hub_node_id = self._generate_entity_id("MCP Security")
                if hub_node_id not in graph.nodes:
                    graph.add_node(
                        node_id=hub_node_id,
                        label="MCP Security",
                        node_type="Component",
                        properties={"description": "System-generated Knowledge Hub"}
                    )
            
            # 4. Connect isolated components to Hub
            # Find which component contains the Hub
            hub_component_index = -1
            for i, comp in enumerate(components):
                if hub_node_id in comp:
                    hub_component_index = i
                    break
            
            # We want to link all OTHER components to this Hub.
            
            for i, comp in enumerate(components):
                if i == hub_component_index:
                    continue # Skip the main component itself
                
                # Priority: "Threat" > "Technique" > "Component" > Any
                best_node_id = comp[0]
                best_degree = -1
                
                for node_id in comp:
                    # Calculate local degree
                    degree = len(adj[node_id])
                    node_type = graph.nodes[node_id]['type']
                    
                    # Weight by type interest
                    weight = 0
                    if node_type == "Threat": weight = 10
                    elif node_type == "Technique": weight = 5
                    elif node_type == "Component": weight = 2
                    
                    score = degree + weight
                    if score > best_degree:
                        best_degree = score
                        best_node_id = node_id
                
                # Link it!
                print(f"[IntelKG] Connecting isolated component (size {len(comp)}) via '{graph.nodes.get(best_node_id, {}).get('label')}' to Hub")
                graph.add_edge(
                    source_id=best_node_id,
                    target_id=hub_node_id,
                    relationship="RELATED_TO",
                    properties={
                        "description": "Auto-connected isolated subgraph to Hub",
                        "auto_generated": True
                    }
                )
        
        return graph
    
    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call LLM for extraction using LiteLLM"""
        import time
        
        # Add rate limiting - wait between calls
        if not hasattr(self, '_last_llm_call_time'):
            self._last_llm_call_time = {}
        
        # Always use LiteLLM
        try:
            return self._call_litellm(prompt)
        except Exception as e:
            print(f"[IntelKG] LiteLLM call failed: {e}")
            return None
    

    
    def _call_litellm(self, prompt: str) -> Optional[str]:
        """Call LiteLLM for extraction using direct HTTP to avoid library provider checks"""
        import os
        import requests
        import json
        
        # Get config
        model = os.getenv("LITELLM_MODEL")
        if hasattr(self.llm_config, 'get_model_for_role'):
            model = self.llm_config.get_model_for_role("INTEL_SUMMARIZER") or model
            
        if not model:
            print("[IntelKG] Warning: LITELLM_MODEL not configured")
            return None

        # Get API base and key
        api_base = os.getenv("LITELLM_API_BASE", "http://localhost:4000")
        api_key = os.getenv("LITELLM_API_KEY", "sk-1234")
        
        # Construct URL
        api_url = api_base
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
                {"role": "system", "content": "You are an expert at extracting security entities and relationships from text. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": float(os.getenv("LITELLM_TEMPERATURE", 0.1)),
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(
                api_url, 
                headers=headers, 
                json=payload, 
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                # Handle standard OpenAI format
                if "choices" in data and len(data["choices"]) > 0:
                    return data["choices"][0]["message"]["content"]
                # Fallback for other formats
                if "message" in data:
                    return data["message"]["content"]
                if "response" in data:
                    return data["response"]
                    
                print(f"[IntelKG] Unexpected response format from LiteLLM: {data.keys()}")
                return None
            else:
                print(f"[IntelKG] LiteLLM/HTTP request failed {response.status_code}: {response.text[:200]}")
                return None
                
        except Exception as e:
            print(f"[IntelKG] LiteLLM call failed: {e}")
            return None
    
    def _normalize_entity_name(self, name: str) -> str:
        """Normalize entity name using canonical mapping."""
        name = name.strip()
        key = name.lower().strip()
        # Check canonical mapping
        if key in CANONICAL_NAMES:
            return CANONICAL_NAMES[key]
        # Strip trailing 's' for simple plural normalization (but not for short words)
        if len(key) > 4 and key.endswith('s') and not key.endswith('ss'):
            singular = key[:-1]
            if singular in CANONICAL_NAMES:
                return CANONICAL_NAMES[singular]
        return name

    def _generate_entity_id(self, name: str) -> str:
        """Generate entity ID from name with canonical normalization."""
        # Apply canonical name mapping first
        canonical = self._normalize_entity_name(name)
        # Generate ID from canonical name
        normalized = re.sub(r'[^a-zA-Z0-9\s]', '', canonical.lower())
        normalized = re.sub(r'\s+', '-', normalized.strip())
        return f"entity-{normalized[:50]}"
    
    def _get_existing_graph_context(self) -> str:
        """Get existing graph context for better extraction"""
        if not self.entities:
            return "No existing entities in the knowledge graph."
        
        # Get top entities by source count
        top_entities = sorted(
            self.entities.values(),
            key=lambda e: len(e.source_ids),
            reverse=True
        )[:10]
        
        context = "Existing Entities:\n"
        for entity in top_entities:
            context += f"  - {entity.name} ({entity.entity_type}): {entity.description[:100]}\n"
        
        # Get sample relations
        if self.relations:
            context += "\nExisting Relationships:\n"
            for rel in self.relations[:5]:
                source_name = self.entities.get(rel.source_id, Entity(id=rel.source_id, name="Unknown", entity_type="Entity")).name
                target_name = self.entities.get(rel.target_id, Entity(id=rel.target_id, name="Unknown", entity_type="Entity")).name
                context += f"  - {source_name} --[{rel.relation_type}]--> {target_name}\n"
        
        return context

