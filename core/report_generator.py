"""
MCP Threat Report Generator

Generates comprehensive threat model reports in Markdown format
Designed for MCP Scan and MCP Proxy use cases
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from database.db_manager import get_db_manager


class ReportGenerator:
    """
    Threat model report generator
    
    Generates comprehensive reports including:
    - Executive Summary
    - Scope & Context
    - Methodology
    - Findings (Threats, Vulnerabilities, Attack Techniques)
    - Risk Summary & Prioritization
    - Recommendations & Remediation Roadmap
    - Intelligence Sources
    """
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager or get_db_manager()
    
    def generate_full_report(
        self,
        project_id: str = 'default-project',
        include_intel_sources: bool = True,
        include_attack_techniques: bool = True,
        include_coverage_analysis: bool = True
    ) -> str:
        """
        Generate a complete threat model report
        
        Args:
            project_id: Project ID to generate report for
            include_intel_sources: Include intelligence sources section
            include_attack_techniques: Include attack techniques section
            include_coverage_analysis: Include coverage analysis for MCP Scan
            
        Returns:
            Markdown report content
        """
        session = self.db_manager.get_session()
        try:
            # Get all data
            from database.models import Threat, Asset, Control, AttackEvidence, IntelItem
            
            threats = session.query(Threat).filter(
                Threat.project_id == project_id
            ).all()
            
            assets = session.query(Asset).filter(
                Asset.project_id == project_id
            ).all()
            
            controls = session.query(Control).filter(
                Control.project_id == project_id
            ).all()
            
            evidence = session.query(AttackEvidence).filter(
                AttackEvidence.project_id == project_id
            ).all()
            
            intel_items = session.query(IntelItem).order_by(
                IntelItem.created_at.desc()
            ).limit(100).all() if include_intel_sources else []
            
            # Compile report data
            report_data = self._compile_report_data(
                threats, assets, controls, evidence, intel_items,
                include_attack_techniques, include_coverage_analysis
            )
            
            # Generate Markdown
            return self._generate_markdown_report(report_data)
            
        finally:
            session.close()
    
    def _compile_report_data(
        self,
        threats: List,
        assets: List,
        controls: List,
        evidence: List,
        intel_items: List,
        include_attack_techniques: bool,
        include_coverage_analysis: bool
    ) -> Dict[str, Any]:
        """Compile report data"""
        # Statistics
        risk_distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        stride_distribution = {
            "Spoofing": 0,
            "Tampering": 0,
            "Repudiation": 0,
            "Information Disclosure": 0,
            "Denial of Service": 0,
            "Elevation of Privilege": 0
        }
        
        mcpsecbench_distribution = {
            "User Interaction": 0,
            "MCP Client": 0,
            "MCP Transport": 0,
            "MCP Server": 0
        }
        
        attack_type_distribution = {}
        
        for threat in threats:
            # Risk distribution
            risk_level = threat.risk_level.lower() if threat.risk_level else "medium"
            if risk_level in risk_distribution:
                risk_distribution[risk_level] += 1
            
            # STRIDE distribution
            stride_cat = threat.stride_category or "Tampering"
            if stride_cat in stride_distribution:
                stride_distribution[stride_cat] += 1
            
            # MCPSecBench distribution
            schema_data = threat.schema_data or {}
            attack_surface = schema_data.get('attack_surface')
            attack_type = schema_data.get('attack_type')
            
            if attack_surface:
                if attack_surface in mcpsecbench_distribution:
                    mcpsecbench_distribution[attack_surface] += 1
            
            if attack_type:
                attack_type_distribution[attack_type] = attack_type_distribution.get(attack_type, 0) + 1
        
        # Find highest risk threats
        top_threats = sorted(
            [t.to_dict() for t in threats],
            key=lambda t: t.get('risk_score', 0),
            reverse=True
        )[:10]
        
        # Calculate coverage
        total_threats = len(threats)
        mitigated_threats = sum(1 for t in threats if t.is_mitigated or len(t.controls) > 0)
        coverage = (mitigated_threats / total_threats * 100) if total_threats > 0 else 0
        
        # Attack techniques (if available)
        attack_techniques = []
        if include_attack_techniques:
            for threat in threats:
                schema_data = threat.schema_data or {}
                if schema_data.get('is_attack_technique'):
                    attack_techniques.append({
                        'name': threat.name,
                        'description': threat.description,
                        'attack_steps': schema_data.get('attack_steps', []),
                        'attack_vectors': schema_data.get('attack_vectors', []),
                        'examples': schema_data.get('examples', []),
                        'detection_methods': schema_data.get('detection_methods', []),
                        'mitigations': schema_data.get('mitigations', []),
                        'risk_score': threat.risk_score
                    })
        
        # Intelligence sources
        intel_sources = {}
        for item in intel_items:
            source = item.source or "Unknown"
            if source not in intel_sources:
                intel_sources[source] = []
            intel_sources[source].append({
                'title': item.title,
                'url': item.url,
                'created_at': item.created_at.isoformat() if item.created_at else None
            })
        
        # Coverage analysis (for MCP Scan)
        coverage_analysis = None
        if include_coverage_analysis:
            coverage_analysis = self._analyze_coverage(threats, intel_items)
        
        return {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_threats": len(threats),
                "total_assets": len(assets),
                "total_controls": len(controls),
                "total_evidence": len(evidence),
                "total_intel_items": len(intel_items),
                "coverage_percentage": coverage,
                "mitigated_threats": mitigated_threats
            },
            "risk_distribution": risk_distribution,
            "stride_distribution": stride_distribution,
            "mcpsecbench_distribution": mcpsecbench_distribution,
            "attack_type_distribution": attack_type_distribution,
            "top_threats": top_threats,
            "threats": [t.to_dict() for t in threats],
            "assets": [a.to_dict() for a in assets],
            "controls": [c.to_dict() for c in controls],
            "evidence": [e.to_dict() for e in evidence],
            "attack_techniques": attack_techniques,
            "intel_sources": intel_sources,
            "coverage_analysis": coverage_analysis
        }
    
    def _analyze_coverage(
        self,
        threats: List,
        intel_items: List
    ) -> Dict[str, Any]:
        """Analyze coverage for MCP Scan use case"""
        # Count threats by MCPSecBench classification
        covered_surfaces = set()
        covered_types = set()
        
        for threat in threats:
            schema_data = threat.schema_data or {}
            attack_surface = schema_data.get('attack_surface')
            attack_type = schema_data.get('attack_type')
            
            if attack_surface:
                covered_surfaces.add(attack_surface)
            if attack_type:
                covered_types.add(attack_type)
        
        # Total possible surfaces and types
        total_surfaces = 4  # MCPSecBench has 4 surfaces
        total_types = 17  # MCPSecBench has 17 attack types
        
        return {
            "covered_surfaces": len(covered_surfaces),
            "total_surfaces": total_surfaces,
            "surface_coverage": (len(covered_surfaces) / total_surfaces * 100) if total_surfaces > 0 else 0,
            "covered_types": len(covered_types),
            "total_types": total_types,
            "type_coverage": (len(covered_types) / total_types * 100) if total_types > 0 else 0,
            "intel_items_count": len(intel_items)
        }
    
    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        report = f"""# MCP Security Threat Assessment Report

**Report Version:** 1.0  
**Generated:** {data['generated_at']}
**Report Type:** Threat Model & Vulnerability Assessment

---

## 1. Title Page

### Report Information

- **Report Name:** MCP Security Threat / Vulnerability Assessment Report
- **Version:** 1.0
- **Date:** {data['generated_at'][:10]}
- **Audience:** Security Team, Development Team, Management, Compliance Team

### Scope

This report covers:
- MCP Server static analysis and threat intelligence
- Vulnerability assessment based on collected intelligence
- Attack technique analysis
- Risk prioritization and remediation recommendations

---

## 2. Executive Summary

### Purpose & Scope

This report presents a comprehensive security assessment of the Model Context Protocol (MCP) ecosystem based on:
- **Threat Intelligence Collection:** {data['summary']['total_intel_items']} intelligence items from multiple sources
- **Threat Modeling:** {data['summary']['total_threats']} identified threats
- **Asset Inventory:** {data['summary']['total_assets']} assets analyzed
- **Security Controls:** {data['summary']['total_controls']} controls implemented

### Key Findings

- **Total Threats Identified:** {data['summary']['total_threats']}
  - Critical: {data['risk_distribution']['critical']}
  - High: {data['risk_distribution']['high']}
  - Medium: {data['risk_distribution']['medium']}
  - Low: {data['risk_distribution']['low']}
  - Info: {data['risk_distribution']['info']}

- **Security Posture:** {self._get_security_posture(data)}
- **Control Coverage:** {data['summary']['coverage_percentage']:.1f}% ({data['summary']['mitigated_threats']}/{data['summary']['total_threats']} threats mitigated)

### High-level Recommendations

1. **Immediate Actions (Short-term):**
   - Address {data['risk_distribution']['critical']} critical threats
   - Implement missing controls for high-risk threats
   - Review and update security configurations

2. **Strategic Improvements (Long-term):**
   - Establish continuous threat intelligence monitoring
   - Implement runtime detection mechanisms (MCP Proxy)
   - Build comprehensive test coverage for identified attack techniques

---

## 3. Scope & Context

### In-Scope Components

- **MCP Server Codebase:** Static analysis and configuration review
- **MCP Tools & Plugins:** Supply chain security assessment
- **MCP Client:** Configuration and interaction security
- **MCP Transport:** Protocol-level security analysis
- **Threat Intelligence:** Collected from multiple sources

### Out-of-Scope

- Dynamic runtime testing (future: MCP Proxy integration)
- Third-party dependency deep-dive (covered by intelligence)
- Physical security considerations

### Risk Model & Assumptions

- **Attacker Model:** Skilled attacker with knowledge of MCP architecture
- **Trust Boundary:** MCP Server, Client, and Transport layers
- **Plugin Supply Chain:** Considered potentially untrusted
- **User Interaction:** Users may be targeted for social engineering

### Methodology & Data Sources

- **Threat Intelligence Sources:** See Section 8 for detailed sources
- **Analysis Methods:**
  - Knowledge graph-based entity and relationship extraction
  - LLM-assisted threat classification
  - MCPSecBench framework mapping
  - STRIDE threat categorization

---

## 4. Methodology

### Threat Intelligence Collection

Intelligence items were collected from:
- CVE databases
- Security research papers (MCPGuard, AegisMCP, etc.)
- GitHub issues and discussions
- Security advisories
- Public vulnerability databases

**Total Intelligence Items:** {data['summary']['total_intel_items']}

### Analysis & Classification Process

1. **Entity Extraction:** Used knowledge graph to extract entities and relationships
2. **Threat Classification:** Applied STRIDE and MCPSecBench frameworks
3. **Deduplication:** Merged duplicate threats from multiple sources
4. **Risk Scoring:** Calculated risk scores based on severity, exploitability, and impact

### Threat Modeling Process

1. **Asset Identification:** Identified {data['summary']['total_assets']} assets
2. **Threat Identification:** Identified {data['summary']['total_threats']} threats
3. **Control Mapping:** Mapped {data['summary']['total_controls']} controls to threats
4. **Risk Assessment:** Prioritized threats by risk score

### Risk Scoring & Prioritization

- **Risk Score Range:** 0-10 (10 = most critical)
- **Scoring Factors:**
  - Severity (impact if exploited)
  - Exploitability (ease of exploitation)
  - Exposure (affected scope)
  - Likelihood (probability of occurrence)

---

## 5. Findings

### 5.1 Threat Overview

**Total Threats:** {data['summary']['total_threats']}

#### Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| Critical | {data['risk_distribution']['critical']} | {self._get_percentage(data['risk_distribution']['critical'], data['summary']['total_threats'])}% |
| High | {data['risk_distribution']['high']} | {self._get_percentage(data['risk_distribution']['high'], data['summary']['total_threats'])}% |
| Medium | {data['risk_distribution']['medium']} | {self._get_percentage(data['risk_distribution']['medium'], data['summary']['total_threats'])}% |
| Low | {data['risk_distribution']['low']} | {self._get_percentage(data['risk_distribution']['low'], data['summary']['total_threats'])}% |
| Info | {data['risk_distribution']['info']} | {self._get_percentage(data['risk_distribution']['info'], data['summary']['total_threats'])}% |

#### STRIDE Distribution

| STRIDE Category | Count |
|-----------------|-------|
| Spoofing | {data['stride_distribution']['Spoofing']} |
| Tampering | {data['stride_distribution']['Tampering']} |
| Repudiation | {data['stride_distribution']['Repudiation']} |
| Information Disclosure | {data['stride_distribution']['Information Disclosure']} |
| Denial of Service | {data['stride_distribution']['Denial of Service']} |
| Elevation of Privilege | {data['stride_distribution']['Elevation of Privilege']} |

#### MCPSecBench Distribution

| Attack Surface | Count |
|----------------|-------|
| User Interaction | {data['mcpsecbench_distribution']['User Interaction']} |
| MCP Client | {data['mcpsecbench_distribution']['MCP Client']} |
| MCP Transport | {data['mcpsecbench_distribution']['MCP Transport']} |
| MCP Server | {data['mcpsecbench_distribution']['MCP Server']} |

### 5.2 Top Priority Threats

"""
        
        # Add top threats
        for i, threat in enumerate(data['top_threats'][:10], 1):
            report += f"""
#### {i}. {threat.get('name', 'Unknown Threat')}

- **Threat ID:** {threat.get('id', 'N/A')}
- **Risk Score:** {threat.get('risk_score', 0)}/10
- **Risk Level:** {threat.get('risk_level', 'Medium')}
- **STRIDE Category:** {threat.get('stride_category', 'Tampering')}
- **MCPSecBench:** {threat.get('schema_data', {}).get('attack_surface', 'N/A')} / {threat.get('schema_data', {}).get('attack_type', 'N/A')}

**Description:**  
{threat.get('description', 'No description available')}

**Attack Vector:**  
{threat.get('attack_vector', 'Not specified')}

**Impact:**  
{threat.get('impact', 'Not specified')}

**Affected Assets:**  
{', '.join(threat.get('affected_assets', [])) if threat.get('affected_assets') else 'Not specified'}

**Recommended Controls:**
{chr(10).join('- ' + c for c in threat.get('recommended_controls', [])) if threat.get('recommended_controls') else 'None specified'}

**Source:** {threat.get('source', 'Internal Analysis')}  
**Source URL:** {threat.get('source_url', 'N/A')}

---
"""
        
        # Attack Techniques section
        if data.get('attack_techniques'):
            report += """
### 5.3 Attack Techniques

Detailed attack techniques extracted from intelligence:

"""
            for tech in data['attack_techniques'][:10]:
                report += f"""
#### {tech['name']}

- **Risk Score:** {tech.get('risk_score', 0)}/10
- **Description:** {tech.get('description', 'No description')}

**Attack Steps:**
"""
                for step in tech.get('attack_steps', [])[:5]:
                    report += f"""
{step.get('step_number', 1)}. **{step.get('action', 'Action')}**
   - Expected Result: {step.get('expected_result', 'N/A')}
   - Tools Needed: {', '.join(step.get('tools_needed', []))}
"""
                
                report += f"""
**Attack Vectors:** {', '.join(tech.get('attack_vectors', []))}

**Detection Methods:**
"""
                for dm in tech.get('detection_methods', [])[:3]:
                    report += f"""
- **{dm.get('method_type', 'Unknown')}:** {dm.get('description', 'N/A')}
  - Indicators: {', '.join(dm.get('indicators', []))}
"""
                
                report += f"""
**Mitigations:**
{chr(10).join('- ' + m for m in tech.get('mitigations', []))}

---
"""
        
        # Coverage Analysis for MCP Scan
        if data.get('coverage_analysis'):
            coverage = data['coverage_analysis']
            report += f"""
### 5.4 Coverage Analysis (MCP Scan Support)

**MCPSecBench Coverage:**
- **Attack Surfaces Covered:** {coverage['covered_surfaces']}/{coverage['total_surfaces']} ({coverage['surface_coverage']:.1f}%)
- **Attack Types Covered:** {coverage['covered_types']}/{coverage['total_types']} ({coverage['type_coverage']:.1f}%)

**Intelligence Coverage:**
- **Total Intelligence Items:** {coverage['intel_items_count']}
- **Threats Mapped to Intelligence:** {len([t for t in data['threats'] if t.get('source_intel_ids')])}

**Recommendations for MCP Scan:**
- Focus on uncovered attack surfaces and types
- Prioritize testing for high-risk attack techniques
- Validate scanner coverage against identified threats

---
"""
        
        report += """
## 6. Risk Summary & Prioritization

### Risk Summary

"""
        
        # Risk prioritization table
        critical_threats = [t for t in data['threats'] if t.get('risk_level', '').lower() == 'critical']
        high_threats = [t for t in data['threats'] if t.get('risk_level', '').lower() == 'high']
        
        report += f"""
**Priority 1 - Critical Threats:** {len(critical_threats)}  
**Priority 2 - High Threats:** {len(high_threats)}  
**Priority 3 - Medium Threats:** {data['risk_distribution']['medium']}  
**Priority 4 - Low Threats:** {data['risk_distribution']['low']}

### Recommended Priority List

1. **Immediate (Critical):** Address {len(critical_threats)} critical threats
2. **Short-term (High):** Address {len(high_threats)} high-risk threats
3. **Medium-term (Medium):** Address {data['risk_distribution']['medium']} medium-risk threats
4. **Long-term (Low):** Address {data['risk_distribution']['low']} low-risk threats

### Current Mitigation Status

- **Mitigated Threats:** {data['summary']['mitigated_threats']}/{data['summary']['total_threats']} ({data['summary']['coverage_percentage']:.1f}%)
- **Unmitigated Threats:** {data['summary']['total_threats'] - data['summary']['mitigated_threats']}

---

## 7. Recommendations & Remediation Roadmap

### 7.1 Immediate Actions (Short-term)

1. **Patch Critical Vulnerabilities**
   - Address all {len(critical_threats)} critical threats
   - Implement recommended controls
   - Update security configurations

2. **Implement Missing Controls**
   - Review control coverage: {data['summary']['coverage_percentage']:.1f}%
   - Implement controls for unmitigated threats
   - Validate control effectiveness

3. **Configuration Hardening**
   - Review MCP server configurations
   - Tighten plugin registry access
   - Enforce metadata validation

### 7.2 Strategic Improvements (Long-term)

1. **Continuous Threat Intelligence**
   - Establish automated intelligence collection
   - Regular threat model updates
   - Knowledge graph maintenance

2. **Runtime Monitoring (MCP Proxy)**
   - Implement real-time vulnerability detection
   - Behavioral anomaly detection
   - Attack chain prediction

3. **Comprehensive Testing**
   - Build test coverage for attack techniques
   - Integrate with MCP Scan tools
   - Validate scanner coverage

### 7.3 Owner Assignment & Timeline

- **Security Team:** Threat mitigation and control implementation
- **Development Team:** Code fixes and configuration updates
- **DevOps Team:** Infrastructure and monitoring setup

**Estimated Timeline:**
- Critical threats: 1-2 weeks
- High threats: 2-4 weeks
- Medium threats: 1-2 months
- Long-term improvements: 3-6 months

---

## 8. Intelligence Sources

### Source Summary

"""
        
        # Add intelligence sources
        for source, items in data.get('intel_sources', {}).items():
            report += f"""
### {source}

**Total Items:** {len(items)}

**Sample Items:**
"""
            for item in items[:5]:
                report += f"""
- **{item.get('title', 'Untitled')}**
  - URL: {item.get('url', 'N/A')}
  - Date: {item.get('created_at', 'N/A')[:10] if item.get('created_at') else 'N/A'}
"""
            report += "\n"
        
        report += """
---

## 9. Appendices

### A. Complete Threat List

"""
        
        # Add all threats
        for threat in data['threats']:
            report += f"""
- **{threat.get('name', 'Unknown')}** (Risk: {threat.get('risk_score', 0)}/10, {threat.get('risk_level', 'Medium')})
"""
        
        report += """
### B. Asset Inventory

"""
        
        for asset in data['assets']:
            report += f"""
- **{asset.get('name', 'Unknown')}** ({asset.get('type', 'Unknown')})
  - Risk Level: {asset.get('risk_level', 'Medium')}
  - Risk Score: {asset.get('risk_score', 0)}/10
"""
        
        report += """
### C. Security Controls

"""
        
        for control in data['controls']:
            status = "Enabled" if control.get('enabled', False) else "Disabled"
            report += f"""
- **{control.get('name', 'Unknown')}** ({control.get('control_type', 'Unknown')}) - {status}
  - Effectiveness: {control.get('effectiveness', 0)}%
"""
        
        report += f"""
---

## 10. Version & Change Log

**Version:** 1.0  
**Date:** {data['generated_at'][:10]}  
**Changes:**
- Initial report generation
- Threat intelligence collection: {data['summary']['total_intel_items']} items
- Threat identification: {data['summary']['total_threats']} threats
- Control mapping: {data['summary']['total_controls']} controls

---

**End of Report**
"""
        
        return report
    
    def _get_security_posture(self, data: Dict[str, Any]) -> str:
        """Calculate security posture"""
        critical = data['risk_distribution']['critical']
        high = data['risk_distribution']['high']
        coverage = data['summary']['coverage_percentage']
        
        if critical > 5 or high > 10:
            return "Poor - Immediate action required"
        elif critical > 0 or high > 5:
            return "Fair - Needs improvement"
        elif coverage < 50:
            return "Moderate - Control coverage needs improvement"
        else:
            return "Good - Continue monitoring"
    
    def _get_percentage(self, count: int, total: int) -> float:
        """Calculate percentage"""
        return (count / total * 100) if total > 0 else 0.0
