"""
Scanner Integration Module

Integrates multiple MCP security scanners for static and dynamic analysis,
configuration auditing, and real-time monitoring.

This module provides a unified interface for all scanners and converts
scan results into intelligence items for the threat modeling platform.
"""

from __future__ import annotations

import os
import sys
import json
import subprocess
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Add scan tools to path
_scan_dir = Path(__file__).parent.parent / "other" / "scan"
sys.path.insert(0, str(_scan_dir / "mcp-scan" / "src"))
sys.path.insert(0, str(_scan_dir / "mcpSafetyScanner"))


class ScannerType(Enum):
    """Supported scanner types"""
    MCP_SCAN = "mcp-scan"
    AI_INFRA_GUARD = "ai-infra-guard"
    MCP_SAFETY_SCANNER = "mcp-safety-scanner"
    MCP_GUARDIAN = "mcp-guardian"
    ALL = "all"


@dataclass
class ScanFinding:
    """Individual scan finding/vulnerability"""
    id: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low, Info
    category: str  # Prompt Injection, Tool Poisoning, etc.
    attack_surface: str  # User Interaction, MCP Client, MCP Transport, MCP Server
    attack_type: str  # From MCPSecBench 17 attack types
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    location: Optional[str] = None  # File path, URL, or component name
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan result from a scanner"""
    scanner_type: ScannerType
    scan_id: str
    target: str  # Config file path, server URL, or package name
    status: str  # success, failed, partial
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[ScanFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_output: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "scanner_type": self.scanner_type.value,
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "errors": self.errors,
            "raw_output": self.raw_output,
            "metadata": self.metadata
        }
    
    def _finding_to_dict(self, finding: ScanFinding) -> Dict[str, Any]:
        """Convert finding to dict"""
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "category": finding.category,
            "attack_surface": finding.attack_surface,
            "attack_type": finding.attack_type,
            "cwe_id": finding.cwe_id,
            "cve_id": finding.cve_id,
            "location": finding.location,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "metadata": finding.metadata
        }


class ScannerIntegration:
    """
    Unified interface for MCP security scanners.
    
    Provides integration for static analysis, dynamic scanning,
    configuration auditing, and real-time monitoring capabilities.
    """
    
    def __init__(self, db_manager=None, llm_config=None):
        """Initialize scanner integration"""
        self.db_manager = db_manager
        self.llm_config = llm_config
        self.scan_dir = Path(__file__).parent.parent / "other" / "scan"
        self.kg_builder = None  # Will be initialized when needed
        
    async def scan_with_mcp_scan(
        self,
        target: str,
        scan_type: str = "auto"
    ) -> ScanResult:
        """
        Scan using mcp-scan.
        
        Args:
            target: MCP config file path, server URL, or package identifier
            scan_type: Type of scan (auto, static, dynamic, proxy)
        
        Returns:
            ScanResult
        """
        scan_id = f"mcp-scan-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        start_time = datetime.now()
        
        try:
            mcp_scan_path = self.scan_dir / "mcp-scan"
            
            # Check if mcp-scan is available
            if not mcp_scan_path.exists():
                return ScanResult(
                    scanner_type=ScannerType.MCP_SCAN,
                    scan_id=scan_id,
                    target=target,
                    status="failed",
                    start_time=start_time,
                    end_time=datetime.now(),
                    errors=[f"mcp-scan not found at {mcp_scan_path}"]
                )
            
            # Try to use mcp-scan API
            try:
                from mcp_scan.MCPScanner import MCPScanner
                from mcp_scan.direct_scanner import direct_scan
                
                # Determine scan type from target
                if target.startswith("http://") or target.startswith("https://"):
                    # Remote server scan
                    result = await direct_scan(target)
                elif os.path.exists(target):
                    # Local config file
                    result = await direct_scan(f"tools:{target}")
                else:
                    # Try as package identifier
                    result = await direct_scan(target)
                
                # Convert mcp-scan result to ScanResult
                findings = []
                if hasattr(result, 'tools'):
                    for tool_name, tool_info in result.tools.items():
                        # Check for security issues
                        if hasattr(tool_info, 'vulnerabilities'):
                            for vuln in tool_info.vulnerabilities:
                                finding = ScanFinding(
                                    id=f"{scan_id}-{len(findings)}",
                                    title=f"Vulnerability in {tool_name}",
                                    description=str(vuln),
                                    severity="High",
                                    category="Tool Vulnerability",
                                    attack_surface="MCP Server",
                                    attack_type="Tool Poisoning",
                                    location=tool_name
                                )
                                findings.append(finding)
                
                return ScanResult(
                    scanner_type=ScannerType.MCP_SCAN,
                    scan_id=scan_id,
                    target=target,
                    status="success",
                    start_time=start_time,
                    end_time=datetime.now(),
                    findings=findings
                )
                
            except ImportError:
                # Fallback to CLI
                return await self._scan_with_mcp_scan_cli(target, scan_id, start_time)
                
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.MCP_SCAN,
                scan_id=scan_id,
                target=target,
                status="failed",
                start_time=start_time,
                end_time=datetime.now(),
                errors=[str(e)]
            )
    
    async def _scan_with_mcp_scan_cli(
        self,
        target: str,
        scan_id: str,
        start_time: datetime
    ) -> ScanResult:
        """Scan using mcp-scan CLI"""
        try:
            mcp_scan_path = self.scan_dir / "mcp-scan"
            result = await asyncio.to_thread(
                subprocess.run,
                ["uvx", "mcp-scan@latest", target],
                cwd=str(mcp_scan_path),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            findings = []
            if result.returncode == 0:
                # Parse output for vulnerabilities
                output = result.stdout
                if "vulnerability" in output.lower() or "risk" in output.lower():
                    # Extract findings from output
                    lines = output.split('\n')
                    for line in lines:
                        if any(keyword in line.lower() for keyword in ['vulnerability', 'risk', 'injection', 'poisoning']):
                            finding = ScanFinding(
                                id=f"{scan_id}-{len(findings)}",
                                title="Security Issue Detected",
                                description=line.strip(),
                                severity="Medium",
                                category="Security Issue",
                                attack_surface="MCP Server",
                                attack_type="Unknown",
                                evidence=output[:500]
                            )
                            findings.append(finding)
            
            return ScanResult(
                scanner_type=ScannerType.MCP_SCAN,
                scan_id=scan_id,
                target=target,
                status="success" if result.returncode == 0 else "partial",
                start_time=start_time,
                end_time=datetime.now(),
                findings=findings,
                raw_output=result.stdout + result.stderr
            )
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.MCP_SCAN,
                scan_id=scan_id,
                target=target,
                status="failed",
                start_time=start_time,
                end_time=datetime.now(),
                errors=[str(e)]
            )
    
    async def scan_with_ai_infra_guard(
        self,
        target: str,
        scan_type: str = "mcp_server"
    ) -> ScanResult:
        """
        Scan using AI-Infra-Guard.
        
        Args:
            target: MCP server source code path or remote URL
            scan_type: Type of scan (mcp_server, jailbreak, etc.)
        
        Returns:
            ScanResult
        """
        scan_id = f"aig-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        start_time = datetime.now()
        
        try:
            aig_path = self.scan_dir / "AI-Infra-Guard"
            
            if not aig_path.exists():
                return ScanResult(
                    scanner_type=ScannerType.AI_INFRA_GUARD,
                    scan_id=scan_id,
                    target=target,
                    status="failed",
                    start_time=start_time,
                    end_time=datetime.now(),
                    errors=[f"AI-Infra-Guard not found at {aig_path}"]
                )
            
            # AI-Infra-Guard is a Go application, need to call via CLI or API
            # For now, return a placeholder result
            # TODO: Implement actual AI-Infra-Guard integration
            
            return ScanResult(
                scanner_type=ScannerType.AI_INFRA_GUARD,
                scan_id=scan_id,
                target=target,
                status="partial",
                start_time=start_time,
                end_time=datetime.now(),
                findings=[],
                errors=["AI-Infra-Guard integration not yet implemented"]
            )
            
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.AI_INFRA_GUARD,
                scan_id=scan_id,
                target=target,
                status="failed",
                start_time=start_time,
                end_time=datetime.now(),
                errors=[str(e)]
            )
    
    async def scan_with_mcp_safety_scanner(
        self,
        target: str
    ) -> ScanResult:
        """
        Scan using mcpSafetyScanner.
        
        Args:
            target: MCP server config file path
        
        Returns:
            ScanResult
        """
        scan_id = f"mcp-safety-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        start_time = datetime.now()
        
        try:
            safety_scanner_path = self.scan_dir / "mcpSafetyScanner"
            
            if not safety_scanner_path.exists():
                return ScanResult(
                    scanner_type=ScannerType.MCP_SAFETY_SCANNER,
                    scan_id=scan_id,
                    target=target,
                    status="failed",
                    start_time=start_time,
                    end_time=datetime.now(),
                    errors=[f"mcpSafetyScanner not found at {safety_scanner_path}"]
                )
            
            # Try to import and use mcpSafetyScanner
            try:
                from mcpsafety.scanner.scan import scan_mcp_server
                
                # Run scan
                result = await scan_mcp_server(target)
                
                findings = []
                # Parse result and convert to findings
                # TODO: Implement proper parsing based on mcpSafetyScanner output format
                
                return ScanResult(
                    scanner_type=ScannerType.MCP_SAFETY_SCANNER,
                    scan_id=scan_id,
                    target=target,
                    status="success",
                    start_time=start_time,
                    end_time=datetime.now(),
                    findings=findings,
                    raw_output=str(result)
                )
                
            except ImportError:
                return ScanResult(
                    scanner_type=ScannerType.MCP_SAFETY_SCANNER,
                    scan_id=scan_id,
                    target=target,
                    status="failed",
                    start_time=start_time,
                    end_time=datetime.now(),
                    errors=["mcpSafetyScanner module not available"]
                )
                
        except Exception as e:
            return ScanResult(
                scanner_type=ScannerType.MCP_SAFETY_SCANNER,
                scan_id=scan_id,
                target=target,
                status="failed",
                start_time=start_time,
                end_time=datetime.now(),
                errors=[str(e)]
            )
    
    async def scan_all(
        self,
        target: str
    ) -> Dict[ScannerType, ScanResult]:
        """
        Run all available scanners on target.
        
        Args:
            target: Target to scan
        
        Returns:
            Dictionary mapping scanner type to results
        """
        results = {}
        
        # Run all scanners in parallel
        tasks = [
            self.scan_with_mcp_scan(target),
            self.scan_with_ai_infra_guard(target),
            self.scan_with_mcp_safety_scanner(target)
        ]
        
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        results[ScannerType.MCP_SCAN] = scan_results[0] if not isinstance(scan_results[0], Exception) else ScanResult(
            scanner_type=ScannerType.MCP_SCAN,
            scan_id=f"error-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            target=target,
            status="failed",
            start_time=datetime.now(),
            errors=[str(scan_results[0])]
        )
        
        results[ScannerType.AI_INFRA_GUARD] = scan_results[1] if not isinstance(scan_results[1], Exception) else ScanResult(
            scanner_type=ScannerType.AI_INFRA_GUARD,
            scan_id=f"error-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            target=target,
            status="failed",
            start_time=datetime.now(),
            errors=[str(scan_results[1])]
        )
        
        results[ScannerType.MCP_SAFETY_SCANNER] = scan_results[2] if not isinstance(scan_results[2], Exception) else ScanResult(
            scanner_type=ScannerType.MCP_SAFETY_SCANNER,
            scan_id=f"error-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            target=target,
            status="failed",
            start_time=datetime.now(),
            errors=[str(scan_results[2])]
        )
        
        return results
    
    def convert_scan_result_to_intel(
        self,
        scan_result: ScanResult
    ) -> Dict[str, Any]:
        """
        Convert scan result to intelligence item format.
        
        Args:
            scan_result: Scan result to convert
        
        Returns:
            Dictionary with intel_items and metadata
        """
        intel_items = []
        
        for finding in scan_result.findings:
            # Build intelligence item from finding
            intel_item = {
                "id": finding.id,
                "title": f"[{scan_result.scanner_type.value}] {finding.title}",
                "content": f"""
**Description:** {finding.description}

**Severity:** {finding.severity}
**Category:** {finding.category}
**Attack Surface:** {finding.attack_surface}
**Attack Type:** {finding.attack_type}

**Location:** {finding.location or 'N/A'}

**Evidence:**
{finding.evidence or 'N/A'}

**Recommendation:**
{finding.recommendation or 'N/A'}

**CWE ID:** {finding.cwe_id or 'N/A'}
**CVE ID:** {finding.cve_id or 'N/A'}
""".strip(),
                "source_type": "scan",
                "url": scan_result.target,
                "source_date": scan_result.start_time,
                "author": scan_result.scanner_type.value,
                "is_relevant": True,
                "ai_relevance_score": self._calculate_relevance_score(finding),
                "ai_summary": f"{finding.title}: {finding.description[:200]}",
                "is_processed": True,
                "raw_data": {
                    "scanner_type": scan_result.scanner_type.value,
                    "scan_id": scan_result.scan_id,
                    "severity": finding.severity,
                    "category": finding.category,
                    "attack_surface": finding.attack_surface,
                    "attack_type": finding.attack_type,
                    "cwe_id": finding.cwe_id,
                    "cve_id": finding.cve_id,
                    "location": finding.location,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation
                }
            }
            intel_items.append(intel_item)
        
        return {
            "intel_items": intel_items,
            "scan_metadata": {
                "scanner_type": scan_result.scanner_type.value,
                "scan_id": scan_result.scan_id,
                "target": scan_result.target,
                "status": scan_result.status,
                "findings_count": len(scan_result.findings),
                "errors": scan_result.errors
            }
        }
    
    def _calculate_relevance_score(self, finding: ScanFinding) -> float:
        """Calculate relevance score based on severity and category"""
        severity_scores = {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.4,
            "Info": 0.2
        }
        
        base_score = severity_scores.get(finding.severity, 0.5)
        
        # Boost score for MCP-specific categories
        if any(keyword in finding.category.lower() for keyword in ['mcp', 'prompt injection', 'tool poisoning']):
            base_score = min(1.0, base_score + 0.2)
        
        return base_score
    
    def enhance_scan_with_kg(
        self,
        scan_result: ScanResult,
        kg_data: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """
        Enhance scan results using knowledge graph from intelligence.
        
        Uses knowledge graph to:
        - Match findings with known threats
        - Identify related vulnerabilities
        - Suggest additional checks
        - Provide context from intelligence
        
        Args:
            scan_result: Original scan result
            kg_data: Knowledge graph data (nodes and edges)
        
        Returns:
            Enhanced ScanResult with additional findings and context
        """
        if not kg_data or not kg_data.get('nodes'):
            return scan_result
        
        enhanced_findings = []
        kg_nodes = {node['id']: node for node in kg_data.get('nodes', [])}
        kg_edges = kg_data.get('edges', [])
        
        # Enhance each finding with KG context
        for finding in scan_result.findings:
            enhanced_finding = finding
            
            # Find related entities in KG
            related_entities = self._find_related_entities(finding, kg_nodes, kg_edges)
            
            if related_entities:
                # Add KG context to finding
                enhanced_finding.metadata['kg_related_entities'] = related_entities
                enhanced_finding.metadata['kg_enhanced'] = True
                
                # Add additional recommendations based on KG
                kg_recommendations = self._get_kg_recommendations(related_entities, kg_nodes)
                if kg_recommendations:
                    enhanced_finding.recommendation = (
                        (enhanced_finding.recommendation or '') + 
                        '\n\n**Knowledge Graph Recommendations:**\n' +
                        '\n'.join(f'- {rec}' for rec in kg_recommendations)
                    )
            
            enhanced_findings.append(enhanced_finding)
        
        # Create enhanced result
        enhanced_result = ScanResult(
            scanner_type=scan_result.scanner_type,
            scan_id=scan_result.scan_id,
            target=scan_result.target,
            status=scan_result.status,
            start_time=scan_result.start_time,
            end_time=scan_result.end_time,
            findings=enhanced_findings,
            errors=scan_result.errors,
            raw_output=scan_result.raw_output,
            metadata={
                **scan_result.metadata,
                'kg_enhanced': True,
                'kg_nodes_count': len(kg_nodes),
                'kg_edges_count': len(kg_edges)
            }
        )
        
        return enhanced_result
    
    def _find_related_entities(
        self,
        finding: ScanFinding,
        kg_nodes: Dict[str, Dict[str, Any]],
        kg_edges: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find entities in KG related to the finding"""
        related = []
        
        finding_text = f"{finding.title} {finding.description}".lower()
        
        # Search for matching entities
        for node_id, node in kg_nodes.items():
            node_label = (node.get('label') or node.get('name') or '').lower()
            node_type = (node.get('type') or '').lower()
            
            # Check if finding mentions this entity
            if node_label and node_label in finding_text:
                related.append({
                    'id': node_id,
                    'label': node.get('label') or node.get('name'),
                    'type': node.get('type'),
                    'description': node.get('properties', {}).get('description', ''),
                    'source_urls': node.get('properties', {}).get('source_urls', [])
                })
            
            # Check if entity type matches finding category
            if finding.category.lower() in node_type or node_type in finding.category.lower():
                related.append({
                    'id': node_id,
                    'label': node.get('label') or node.get('name'),
                    'type': node.get('type'),
                    'description': node.get('properties', {}).get('description', ''),
                    'source_urls': node.get('properties', {}).get('source_urls', [])
                })
        
        return related[:5]  # Limit to top 5 related entities
    
    def _get_kg_recommendations(
        self,
        related_entities: List[Dict[str, Any]],
        kg_nodes: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Get recommendations based on related KG entities"""
        recommendations = []
        
        for entity in related_entities:
            entity_id = entity['id']
            if entity_id in kg_nodes:
                node = kg_nodes[entity_id]
                props = node.get('properties', {})
                
                # Extract recommendations from entity properties
                if 'recommendation' in props:
                    recommendations.append(props['recommendation'])
                if 'mitigation' in props:
                    recommendations.append(props['mitigation'])
        
        return list(set(recommendations))  # Remove duplicates

