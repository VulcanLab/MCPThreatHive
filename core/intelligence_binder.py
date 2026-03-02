"""
Intelligence Binding Engine

Automatically binds intelligence items (CVE, IOC, Jailbreak history) to threats
based on component matching, attack pattern matching, and semantic similarity.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from database.db_manager import DatabaseManager


@dataclass
class IntelligenceMatch:
    """Represents a match between a threat and intelligence item"""
    intel_id: str
    intel_type: str  # 'cve', 'ioc', 'jailbreak', 'research'
    match_score: float  # 0.0 - 1.0
    match_reason: str
    intel_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComponentInfo:
    """Component information for matching"""
    name: str
    type: str
    version: Optional[str] = None
    libraries: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    llm_provider: Optional[str] = None  # For jailbreak matching


class IntelligenceBinder:
    """
    Automatically binds intelligence items to threats.
    
    Supports:
    - CVE matching: Match components/libraries to known CVEs
    - IOC matching: Match attack patterns to known IOCs
    - Jailbreak history: Match LLM providers to known jailbreak techniques
    - Research papers: Match attack types to relevant research
    """
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        """Initialize intelligence binder"""
        self.db_manager = db_manager
        
        # CVE pattern matching
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        
        # Common library patterns for CVE matching
        self.library_patterns = {
            'express': r'express',
            'node': r'node(?:\.js)?',
            'python': r'python',
            'flask': r'flask',
            'django': r'django',
            'fastapi': r'fastapi',
            'openai': r'openai',
            'anthropic': r'anthropic',
            'gemini': r'gemini',
        }
        
        # Jailbreak keywords for LLM providers
        self.jailbreak_keywords = {
            'openai': ['jailbreak', 'prompt injection', 'system prompt', 'adversarial prompt', 'gpt', 'chatgpt'],
            'anthropic': ['jailbreak', 'prompt injection', 'claude', 'anthropic', 'red team'],
            'gemini': ['jailbreak', 'prompt injection', 'gemini', 'google'],
            'qwen': ['jailbreak', 'prompt injection', 'qwen', 'alibaba'],
        }
        
        # IOC patterns (indicators of compromise)
        self.ioc_patterns = {
            'malicious_tool': ['malicious tool', 'rogue tool', 'compromised tool', 'trojan tool'],
            'data_exfiltration': ['data exfiltration', 'data leak', 'sensitive data', 'credential theft'],
            'privilege_escalation': ['privilege escalation', 'unauthorized access', 'elevation of privilege'],
            'supply_chain': ['supply chain', 'dependency attack', 'typosquatting', 'package hijacking'],
        }
    
    def bind_intelligence_to_threat(
        self,
        threat: Dict[str, Any],
        components: Optional[List[ComponentInfo]] = None
    ) -> List[IntelligenceMatch]:
        """
        Bind intelligence items to a threat.
        
        Args:
            threat: Threat dictionary with classification info
            components: Optional list of components related to the threat
        
        Returns:
            List of intelligence matches
        """
        matches = []
        
        # Get intelligence items from database
        intel_items = self._get_intelligence_items()
        
        # Match by attack type and surface
        matches.extend(self._match_by_attack_pattern(threat, intel_items))
        
        # Match by component (CVE matching)
        if components:
            matches.extend(self._match_by_component(components, intel_items))
        
        # Match by LLM provider (Jailbreak matching)
        if components:
            llm_providers = [c.llm_provider for c in components if c.llm_provider]
            if llm_providers:
                matches.extend(self._match_by_jailbreak(llm_providers, intel_items))
        
        # Match by IOC patterns
        matches.extend(self._match_by_ioc(threat, intel_items))
        
        # Deduplicate and sort by score
        matches = self._deduplicate_matches(matches)
        matches.sort(key=lambda m: m.match_score, reverse=True)
        
        return matches[:10]  # Return top 10 matches
    
    def _get_intelligence_items(self) -> List[Dict[str, Any]]:
        """Get intelligence items from database"""
        if not self.db_manager:
            return []
        
        try:
            session = self.db_manager.get_session()
            try:
                from database.models import IntelItem
                items = session.query(IntelItem).filter(
                    IntelItem.is_relevant == True
                ).all()
                
                return [item.to_dict() for item in items]
            finally:
                session.close()
        except Exception as e:
            print(f"[IntelligenceBinder] Error getting intelligence items: {e}")
            return []
    
    def _match_by_attack_pattern(
        self,
        threat: Dict[str, Any],
        intel_items: List[Dict[str, Any]]
    ) -> List[IntelligenceMatch]:
        """Match intelligence by attack pattern (MCP Threat IDs classification)"""
        matches = []
        
        # Get MCP Threat IDs from threat (primary classification method)
        threat_mcp_ids = threat.get('mcp_threat_ids', []) or []
        if isinstance(threat_mcp_ids, str):
            threat_mcp_ids = [threat_mcp_ids]
        
        # Fallback to attack classification if MCP Threat IDs not available
        attack_type = threat.get('mcpsecbench_attack_type') or threat.get('msb_attack_type') or ''
        surface = threat.get('mcp_surface') or ''
        description = threat.get('description', '') or ''
        
        # Import MCP Threat Mapper
        from core.mcp_threat_mapper import MCPThreatMapper
        
        for intel in intel_items:
            score = 0.0
            reasons = []
            
            # Primary: Match by MCP Threat IDs
            if threat_mcp_ids:
                # Map intel to MCP Threat IDs
                intel_mcp_ids = MCPThreatMapper.map_intel_to_threat_ids(intel)
                
                # Check for overlap
                overlap = set(threat_mcp_ids) & set(intel_mcp_ids)
                if overlap:
                    score += 0.6
                    reasons.append(f"MCP Threat ID match: {', '.join(overlap)}")
            
            # Secondary: Match by keywords and attack patterns
            title = (intel.get('title', '') or '').lower()
            content = (intel.get('content', '') or intel.get('ai_summary', '') or '').lower()
            
            # Keywords to match
            keywords = []
            if attack_type:
                keywords.append(attack_type.lower())
            if surface:
                keywords.append(surface.lower())
            
            # Extract keywords from description
            description_lower = description.lower()
            for keyword in ['poisoning', 'injection', 'escalation', 'exfiltration', 'chain', 'parasitic']:
                if keyword in description_lower:
                    keywords.append(keyword)
            
            for keyword in keywords:
                if keyword in title:
                    score += 0.2
                    reasons.append(f"Keyword '{keyword}' in title")
                elif keyword in content:
                    score += 0.1
                    reasons.append(f"Keyword '{keyword}' in content")
            
            # Match by attack type classification
            intel_attack_type = intel.get('ai_threat_type', '') or ''
            if attack_type and attack_type.lower() in intel_attack_type.lower():
                score += 0.3
                reasons.append("Attack type match")
            
            # Match by STRIDE category
            stride = threat.get('stride_category', '')
            intel_stride = intel.get('ai_stride_category', '') or ''
            if stride and stride.lower() == intel_stride.lower():
                score += 0.2
                reasons.append("STRIDE category match")
            
            if score > 0.3:  # Minimum threshold
                matches.append(IntelligenceMatch(
                    intel_id=intel.get('id', ''),
                    intel_type=self._classify_intel_type(intel),
                    match_score=min(score, 1.0),
                    match_reason='; '.join(reasons),
                    intel_data=intel
                ))
        
        return matches
    
    def _match_by_component(
        self,
        components: List[ComponentInfo],
        intel_items: List[Dict[str, Any]]
    ) -> List[IntelligenceMatch]:
        """Match intelligence by component (CVE matching)"""
        matches = []
        
        # Extract library names and versions
        component_libs = {}
        for comp in components:
            for lib in comp.libraries:
                lib_lower = lib.lower()
                component_libs[lib_lower] = {
                    'name': lib,
                    'version': comp.version,
                    'component': comp.name
                }
        
        for intel in intel_items:
            title = (intel.get('title', '') or '').lower()
            content = (intel.get('content', '') or intel.get('ai_summary', '') or '').lower()
            
            # Check for CVE references
            cve_matches = self.cve_pattern.findall(title + ' ' + content)
            if not cve_matches:
                continue
            
            # Match library names
            for lib_name, lib_info in component_libs.items():
                score = 0.0
                reasons = []
                
                # Check if library name appears in intel
                if lib_name in title or lib_name in content:
                    score += 0.5
                    reasons.append(f"Library '{lib_info['name']}' mentioned")
                    
                    # Check version match if available
                    version = lib_info.get('version')
                    if version and version in content:
                        score += 0.3
                        reasons.append(f"Version '{version}' match")
                    
                    # CVE match bonus
                    if cve_matches:
                        score += 0.2
                        reasons.append(f"CVE reference: {', '.join(cve_matches[:3])}")
                    
                    if score > 0.5:  # Higher threshold for CVE matches
                        matches.append(IntelligenceMatch(
                            intel_id=intel.get('id', ''),
                            intel_type='cve',
                            match_score=min(score, 1.0),
                            match_reason='; '.join(reasons),
                            intel_data=intel
                        ))
        
        return matches
    
    def _match_by_jailbreak(
        self,
        llm_providers: List[str],
        intel_items: List[Dict[str, Any]]
    ) -> List[IntelligenceMatch]:
        """Match intelligence by LLM provider (Jailbreak history)"""
        matches = []
        
        for provider in llm_providers:
            provider_lower = provider.lower()
            keywords = self.jailbreak_keywords.get(provider_lower, [])
            
            if not keywords:
                # Try to infer keywords from provider name
                keywords = [provider_lower, 'jailbreak', 'prompt injection']
            
            for intel in intel_items:
                title = (intel.get('title', '') or '').lower()
                content = (intel.get('content', '') or intel.get('ai_summary', '') or '').lower()
                
                score = 0.0
                reasons = []
                
                # Check for jailbreak keywords
                for keyword in keywords:
                    if keyword in title:
                        score += 0.4
                        reasons.append(f"Jailbreak keyword '{keyword}' in title")
                    elif keyword in content:
                        score += 0.2
                        reasons.append(f"Jailbreak keyword '{keyword}' in content")
                
                # Provider name match
                if provider_lower in title or provider_lower in content:
                    score += 0.3
                    reasons.append(f"Provider '{provider}' mentioned")
                
                if score > 0.4:  # Threshold for jailbreak matches
                    matches.append(IntelligenceMatch(
                        intel_id=intel.get('id', ''),
                        intel_type='jailbreak',
                        match_score=min(score, 1.0),
                        match_reason='; '.join(reasons),
                        intel_data=intel
                    ))
        
        return matches
    
    def _match_by_ioc(
        self,
        threat: Dict[str, Any],
        intel_items: List[Dict[str, Any]]
    ) -> List[IntelligenceMatch]:
        """Match intelligence by IOC (Indicators of Compromise) patterns"""
        matches = []
        
        description = (threat.get('description', '') or '').lower()
        attack_type = (threat.get('mcpsecbench_attack_type') or threat.get('msb_attack_type') or '').lower()
        
        # Determine IOC category from threat
        ioc_category = None
        for category, patterns in self.ioc_patterns.items():
            if any(pattern in description or pattern in attack_type for pattern in patterns):
                ioc_category = category
                break
        
        if not ioc_category:
            return matches
        
        # Match against intelligence items
        for intel in intel_items:
            title = (intel.get('title', '') or '').lower()
            content = (intel.get('content', '') or intel.get('ai_summary', '') or '').lower()
            
            score = 0.0
            reasons = []
            
            # Check for IOC patterns
            patterns = self.ioc_patterns.get(ioc_category, [])
            for pattern in patterns:
                if pattern in title:
                    score += 0.4
                    reasons.append(f"IOC pattern '{pattern}' in title")
                elif pattern in content:
                    score += 0.2
                    reasons.append(f"IOC pattern '{pattern}' in content")
            
            if score > 0.3:
                matches.append(IntelligenceMatch(
                    intel_id=intel.get('id', ''),
                    intel_type='ioc',
                    match_score=min(score, 1.0),
                    match_reason='; '.join(reasons),
                    intel_data=intel
                ))
        
        return matches
    
    def _classify_intel_type(self, intel: Dict[str, Any]) -> str:
        """Classify intelligence item type"""
        title = (intel.get('title', '') or '').lower()
        content = (intel.get('content', '') or intel.get('ai_summary', '') or '').lower()
        source_type = (intel.get('source_type', '') or '').lower()
        
        # Check for CVE
        if self.cve_pattern.search(title + ' ' + content):
            return 'cve'
        
        # Check for jailbreak
        if any(kw in title or kw in content for kw in ['jailbreak', 'prompt injection', 'adversarial prompt']):
            return 'jailbreak'
        
        # Check for IOC indicators
        if any(kw in title or kw in content for kw in ['malicious', 'compromised', 'attack', 'exploit']):
            return 'ioc'
        
        # Default to research
        return 'research'
    
    def _deduplicate_matches(self, matches: List[IntelligenceMatch]) -> List[IntelligenceMatch]:
        """Remove duplicate matches, keeping highest score"""
        seen = {}
        for match in matches:
            key = match.intel_id
            if key not in seen or seen[key].match_score < match.match_score:
                seen[key] = match
        return list(seen.values())
    
    def bind_to_threat_in_db(
        self,
        threat_id: str,
        matches: List[IntelligenceMatch]
    ) -> bool:
        """
        Save intelligence bindings to database.
        
        Args:
            threat_id: Threat ID
            matches: List of intelligence matches
        
        Returns:
            True if successful
        """
        if not self.db_manager:
            return False
        
        try:
            session = self.db_manager.get_session()
            try:
                from database.models import Threat
                
                threat = session.query(Threat).filter(Threat.id == threat_id).first()
                if not threat:
                    return False
                
                # Update schema_data with intelligence bindings
                schema_data = threat.schema_data or {}
                
                # Store intelligence matches
                intel_bindings = []
                for match in matches:
                    intel_bindings.append({
                        'intel_id': match.intel_id,
                        'intel_type': match.intel_type,
                        'match_score': match.match_score,
                        'match_reason': match.match_reason,
                        'intel_title': match.intel_data.get('title', ''),
                        'intel_url': match.intel_data.get('url', '')
                    })
                
                schema_data['intelligence_bindings'] = intel_bindings
                schema_data['intelligence_binding_count'] = len(intel_bindings)
                schema_data['intelligence_binding_updated_at'] = datetime.utcnow().isoformat()
                
                threat.schema_data = schema_data
                session.commit()
                
                return True
            finally:
                session.close()
        except Exception as e:
            print(f"[IntelligenceBinder] Error binding intelligence to threat: {e}")
            return False


