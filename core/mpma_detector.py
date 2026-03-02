"""
MPMA Attack Detector

Detects and classifies MPMA (Manipulating Preferences via Malicious Agents) attacks,
including DPMA (Direct Preference Manipulation) and GAPMA (Genetic Algorithm
Preference Manipulation) with different advertising strategies.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from schemas.mcp_enhanced_threat_schema import (
    MPMAAttackType, GAPMAStrategy, EnhancedMCPThreat
)


@dataclass
class MPMAAnalysis:
    """MPMA attack analysis results"""
    dpma_threats: List[EnhancedMCPThreat] = field(default_factory=list)
    gapma_threats: List[EnhancedMCPThreat] = field(default_factory=list)
    
    # GAPMA by strategy
    gapma_by_strategy: Dict[GAPMAStrategy, List[EnhancedMCPThreat]] = field(default_factory=dict)
    
    # Statistics
    dpma_count: int = 0
    gapma_count: int = 0
    authoritative_count: int = 0  # Highest risk strategy
    
    # ASR (Attack Success Rate) statistics
    avg_asr_dpma: float = 0.0
    avg_asr_gapma: float = 0.0
    avg_asr_authoritative: float = 0.0  # Highest ASR for authoritative
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'dpma_threats': [t.to_dict() for t in self.dpma_threats],
            'gapma_threats': [t.to_dict() for t in self.gapma_threats],
            'gapma_by_strategy': {
                strategy.value: [t.to_dict() for t in threats]
                for strategy, threats in self.gapma_by_strategy.items()
            },
            'dpma_count': self.dpma_count,
            'gapma_count': self.gapma_count,
            'authoritative_count': self.authoritative_count,
            'avg_asr_dpma': self.avg_asr_dpma,
            'avg_asr_gapma': self.avg_asr_gapma,
            'avg_asr_authoritative': self.avg_asr_authoritative
        }


class MPMADetector:
    """
    Detects and analyzes MPMA attacks.
    
    MPMA attacks involve manipulating LLM preferences to favor malicious tools:
    - DPMA: Direct insertion of manipulative words
    - GAPMA: Stealthy GA-optimized descriptions with advertising strategies
    """
    
    def analyze_threats(self, threats: List[Dict[str, Any]]) -> MPMAAnalysis:
        """
        Analyze threats to detect MPMA attacks.
        
        Args:
            threats: List of threat dictionaries
        
        Returns:
            MPMAAnalysis with detected MPMA attacks
        """
        analysis = MPMAAnalysis()
        
        # Initialize GAPMA strategy dict
        for strategy in GAPMAStrategy:
            analysis.gapma_by_strategy[strategy] = []
        
        # Convert threats to EnhancedMCPThreat objects
        enhanced_threats = []
        for threat_dict in threats:
            try:
                if isinstance(threat_dict, dict):
                    threat = EnhancedMCPThreat.from_dict(threat_dict)
                    enhanced_threats.append(threat)
            except Exception as e:
                print(f"[MPMA] Error converting threat: {e}")
                continue
        
        # Classify threats
        for threat in enhanced_threats:
            mpma_type = threat.mpma_attack_type
            gapma_strategy = threat.gapma_strategy
            
            if not mpma_type:
                continue
            
            # DPMA threats
            if mpma_type == MPMAAttackType.DIRECT_PREFERENCE_MANIPULATION:
                analysis.dpma_threats.append(threat)
                analysis.dpma_count += 1
                if threat.asr_score:
                    analysis.avg_asr_dpma += threat.asr_score
            
            # GAPMA threats
            elif mpma_type == MPMAAttackType.GENETIC_ALGORITHM_PREFERENCE:
                analysis.gapma_threats.append(threat)
                analysis.gapma_count += 1
                if threat.asr_score:
                    analysis.avg_asr_gapma += threat.asr_score
                
                # Group by strategy
                if gapma_strategy:
                    analysis.gapma_by_strategy[gapma_strategy].append(threat)
                    
                    # Track authoritative (highest risk)
                    if gapma_strategy == GAPMAStrategy.AUTHORITATIVE:
                        analysis.authoritative_count += 1
                        if threat.asr_score:
                            analysis.avg_asr_authoritative += threat.asr_score
        
        # Calculate averages
        if analysis.dpma_count > 0:
            analysis.avg_asr_dpma /= analysis.dpma_count
        if analysis.gapma_count > 0:
            analysis.avg_asr_gapma /= analysis.gapma_count
        if analysis.authoritative_count > 0:
            analysis.avg_asr_authoritative /= analysis.authoritative_count
        
        return analysis
    
    def get_priority_recommendations(self, analysis: MPMAAnalysis) -> List[str]:
        """
        Get priority recommendations based on MPMA analysis.
        
        Based on research:
        - Authoritative (Au) strategy has highest ASR and lowest TPR (most stealthy)
        - Should be prioritized for detection and mitigation
        """
        recommendations = []
        
        if analysis.authoritative_count > 0:
            recommendations.append(
                f"⚠️ HIGH PRIORITY: {analysis.authoritative_count} Authoritative (Au) GAPMA attacks detected. "
                "This strategy has the highest attack success rate and lowest detection rate. "
                "Implement enhanced detection for authoritative language patterns."
            )
        
        if analysis.gapma_count > analysis.dpma_count:
            recommendations.append(
                f"⚠️ GAPMA attacks ({analysis.gapma_count}) outnumber DPMA ({analysis.dpma_count}). "
                "GAPMA uses stealthy GA-optimized descriptions. Consider implementing "
                "behavioral detection and LLM-based analysis for tool descriptions."
            )
        
        if analysis.avg_asr_authoritative > 0.5:
            recommendations.append(
                f"⚠️ Authoritative strategy has {analysis.avg_asr_authoritative:.1%} average ASR. "
                "This is significantly higher than other strategies. Prioritize detection "
                "for authoritative language in tool names and descriptions."
            )
        
        return recommendations


# Global detector instance
_detector: Optional[MPMADetector] = None


def get_mpma_detector() -> MPMADetector:
    """Get global MPMA detector instance"""
    global _detector
    if _detector is None:
        _detector = MPMADetector()
    return _detector

