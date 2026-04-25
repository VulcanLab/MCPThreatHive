"""
MCP Security Scanner - Main Scanner Orchestrator

Coordinates all scanning modules and provides unified API.
"""

import os
import uuid
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path

from .models import ScanConfig, ScanResult, Vulnerability, SeverityLevel
from .static_analyzer import StaticAnalyzer
from .llm_enhanced_detector import LLMEnhancedDetector
from .supply_chain_analyzer import SupplyChainAnalyzer
from .threat_intel import ThreatIntelIntegrator
from .attack_chain_analyzer import AttackChainAnalyzer
from .utils import clone_repository, discover_files

logger = logging.getLogger(__name__)


class MCPSecurityScanner:
    """
    Comprehensive MCP Security Scanner
    
    Integrates:
    - Static analysis (code, config, metadata)
    - LLM-enhanced detection
    - Supply chain security
    - Threat intelligence
    - Attack chain analysis
    """
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """
        Initialize scanner
        
        Args:
            config: Scan configuration (uses defaults if not provided)
        """
        self.config = config or ScanConfig(target="")
        
        # Initialize modules
        self.static_analyzer = StaticAnalyzer() if self.config.enable_static_analysis else None
        self.llm_detector = None
        if self.config.enable_llm_detection:
            self.llm_detector = LLMEnhancedDetector(
                provider=self.config.llm_provider,
                model=self.config.llm_model,
                api_key=self.config.llm_api_key or os.getenv("LITELLM_API_KEY"),
                temperature=self.config.llm_temperature,
                max_tokens=self.config.llm_max_tokens
            )
        self.supply_chain_analyzer = SupplyChainAnalyzer() if self.config.enable_supply_chain else None
        self.threat_intel = ThreatIntelIntegrator() if self.config.enable_threat_intel else None
        self.attack_chain_analyzer = AttackChainAnalyzer() if self.config.enable_attack_chain else None
    
    async def scan(self, target: Optional[str] = None) -> ScanResult:
        """
        Perform comprehensive security scan
        
        Args:
            target: Target to scan (path or GitHub URL). Uses config.target if not provided.
            
        Returns:
            ScanResult with all findings
        """
        target = target or self.config.target
        if not target:
            raise ValueError("Target must be provided in config or as parameter")
        
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            config=self.config,
            started_at=datetime.now()
        )
        
        logger.info(f"[Scan {scan_id}] Starting scan of {target}")
        
        try:
            # Step 1: Prepare target (clone if GitHub URL, validate if local path)
            project_path = await self._prepare_target(target)
            result.metadata['project_path'] = str(project_path)
            
            # Step 2: Static Analysis
            if self.config.enable_static_analysis and self.static_analyzer:
                logger.info(f"[Scan {scan_id}] Running static analysis...")
                static_vulns = await self.static_analyzer.analyze(project_path, self.config)
                result.vulnerabilities.extend(static_vulns)
                result.total_files_scanned = self.static_analyzer.files_scanned
            
            # Step 3: LLM-Enhanced Detection
            if self.config.enable_llm_detection and self.llm_detector:
                logger.info(f"[Scan {scan_id}] Running LLM-enhanced detection...")
                llm_vulns = await self.llm_detector.analyze(project_path, result.vulnerabilities, self.config)
                result.vulnerabilities.extend(llm_vulns)
            
            # Step 4: Supply Chain Analysis
            if self.config.enable_supply_chain and self.supply_chain_analyzer:
                logger.info(f"[Scan {scan_id}] Running supply chain analysis...")
                supply_vulns = await self.supply_chain_analyzer.analyze(project_path, self.config)
                result.vulnerabilities.extend(supply_vulns)
                result.total_dependencies_checked = self.supply_chain_analyzer.dependencies_checked
            
            # Step 5: Threat Intelligence Enrichment
            if self.config.enable_threat_intel and self.threat_intel:
                logger.info(f"[Scan {scan_id}] Enriching with threat intelligence...")
                await self.threat_intel.enrich_vulnerabilities(result.vulnerabilities)
            
            # Step 6: Attack Chain Analysis
            if self.config.enable_attack_chain and self.attack_chain_analyzer:
                logger.info(f"[Scan {scan_id}] Analyzing attack chains...")
                attack_chains = await self.attack_chain_analyzer.analyze(result.vulnerabilities)
                result.attack_chains = attack_chains
            
            # Step 7: Post-process results
            self._post_process(result)
            
            result.completed_at = datetime.now()
            logger.info(f"[Scan {scan_id}] Scan completed in {result.duration_seconds:.2f}s")
            logger.info(f"[Scan {scan_id}] Found {len(result.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"[Scan {scan_id}] Scan failed: {e}", exc_info=True)
            result.errors.append(str(e))
            result.completed_at = datetime.now()
        
        return result
    
    async def _prepare_target(self, target: str) -> Path:
        """
        Prepare target for scanning (clone if GitHub URL, validate if local)
        
        Args:
            target: Target path or GitHub URL
            
        Returns:
            Path to project directory
        """
        # Check if it's a GitHub URL
        if target.startswith(("http://", "https://")) and "github.com" in target:
            logger.info(f"Cloning repository: {target}")
            return await clone_repository(target)
        
        # Local path
        path = Path(target)
        if not path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        if not path.is_dir():
            raise ValueError(f"Target must be a directory: {target}")
        
        return path
    
    def _post_process(self, result: ScanResult):
        """Post-process scan results"""
        # Filter by minimum severity
        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0
        }
        min_severity_level = severity_order.get(self.config.min_severity, 0)
        
        result.vulnerabilities = [
            v for v in result.vulnerabilities
            if severity_order.get(v.severity, 0) >= min_severity_level
        ]
        
        # Deduplicate vulnerabilities
        seen = set()
        unique_vulns = []
        for vuln in result.vulnerabilities:
            # Create unique key from category, file_path, and line_number
            key = (vuln.category, vuln.file_path, vuln.line_number)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        result.vulnerabilities = unique_vulns
        
        # Calculate statistics
        for vuln in result.vulnerabilities:
            severity = vuln.severity.value
            category = vuln.category.value
            result.severity_counts[severity] = result.severity_counts.get(severity, 0) + 1
            result.category_counts[category] = result.category_counts.get(category, 0) + 1
        
        # Count tools analyzed (from metadata)
        if self.static_analyzer:
            result.total_tools_analyzed = self.static_analyzer.tools_analyzed

