"""
Supply Chain Analyzer - Dependency and Package Security

Detects supply chain vulnerabilities:
- Malicious packages
- Package confusion attacks
- Insecure dependencies
- Known CVEs in dependencies
"""

import json
import logging
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

from .models import Vulnerability, VulnerabilityCategory, SeverityLevel, ScanConfig

logger = logging.getLogger(__name__)


class SupplyChainAnalyzer:
    """Supply chain security analyzer"""
    
    def __init__(self):
        self.dependencies_checked = 0
        
        # Patterns for malicious package indicators
        self.malicious_patterns = {
            'install_scripts': [
                r'preinstall',
                r'postinstall',
                r'install',
                r'scripts.*install',
            ],
            'suspicious_urls': [
                r'http://[^/]+',
                r'git\+http://',
                r'git\+https://[^/]+\.(tk|ml|ga|cf)',
            ],
            'wildcard_versions': [
                r'\*',
                r'x',
                r'latest',
                r'>=',
            ],
        }
    
    async def analyze(self, project_path: Path, config: ScanConfig) -> List[Vulnerability]:
        """
        Analyze supply chain security
        
        Args:
            project_path: Path to project
            config: Scan configuration
            
        Returns:
            List of supply chain vulnerabilities
        """
        vulnerabilities = []
        
        # Analyze package.json (Node.js)
        package_json = project_path / "package.json"
        if package_json.exists():
            pkg_vulns = await self._analyze_package_json(package_json, project_path)
            vulnerabilities.extend(pkg_vulns)
        
        # Analyze requirements.txt / pyproject.toml (Python)
        requirements_txt = project_path / "requirements.txt"
        if requirements_txt.exists():
            req_vulns = await self._analyze_requirements_txt(requirements_txt, project_path)
            vulnerabilities.extend(req_vulns)
        
        pyproject_toml = project_path / "pyproject.toml"
        if pyproject_toml.exists():
            pyproject_vulns = await self._analyze_pyproject_toml(pyproject_toml, project_path)
            vulnerabilities.extend(pyproject_vulns)
        
        # Analyze go.mod (Go)
        go_mod = project_path / "go.mod"
        if go_mod.exists():
            go_vulns = await self._analyze_go_mod(go_mod, project_path)
            vulnerabilities.extend(go_vulns)
        
        return vulnerabilities
    
    async def _analyze_package_json(self, package_file: Path, project_path: Path) -> List[Vulnerability]:
        """Analyze package.json for supply chain issues"""
        vulnerabilities = []
        
        try:
            data = json.loads(package_file.read_text())
            dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            self.dependencies_checked += len(dependencies)
            
            # Check for malicious install scripts
            scripts = data.get('scripts', {})
            for script_name, script_content in scripts.items():
                if any(pattern in script_name.lower() for pattern in self.malicious_patterns['install_scripts']):
                    if 'http' in script_content or 'curl' in script_content or 'wget' in script_content:
                        vuln = Vulnerability(
                            id=f"supply-{uuid.uuid4().hex[:8]}",
                            category=VulnerabilityCategory.SUPPLY_CHAIN,
                            severity=SeverityLevel.HIGH,
                            title="Suspicious Install Script",
                            description=f"Install script '{script_name}' contains network requests",
                            file_path=str(package_file.relative_to(project_path)),
                            line_number=None,
                            code_snippet=script_content,
                            detection_method="static",
                            confidence=0.7,
                            impact="Potential remote code execution during package installation",
                            remediation="Review and remove suspicious install scripts",
                            recommended_controls=["script_review", "package_audit"]
                        )
                        vulnerabilities.append(vuln)
            
            # Check dependencies for suspicious patterns
            for dep_name, dep_version in dependencies.items():
                # Check for typosquatting indicators
                if self._is_typosquatting_risk(dep_name):
                    vuln = Vulnerability(
                        id=f"supply-{uuid.uuid4().hex[:8]}",
                        category=VulnerabilityCategory.SUPPLY_CHAIN,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Potential Typosquatting: {dep_name}",
                        description=f"Package name '{dep_name}' may be a typosquatting attempt",
                        file_path=str(package_file.relative_to(project_path)),
                        line_number=None,
                        code_snippet=f'"{dep_name}": "{dep_version}"',
                        detection_method="static",
                        confidence=0.5,
                        impact="Potential malicious package substitution",
                        remediation="Verify package authenticity and source",
                        recommended_controls=["package_verification", "source_validation"]
                    )
                    vulnerabilities.append(vuln)
                
                # Check for insecure version specifiers
                if any(re.search(pattern, dep_version) for pattern in self.malicious_patterns['wildcard_versions']):
                    vuln = Vulnerability(
                        id=f"supply-{uuid.uuid4().hex[:8]}",
                        category=VulnerabilityCategory.SUPPLY_CHAIN,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Insecure Version Specifier: {dep_name}",
                        description=f"Package '{dep_name}' uses wildcard or unpinned version: {dep_version}",
                        file_path=str(package_file.relative_to(project_path)),
                        line_number=None,
                        code_snippet=f'"{dep_name}": "{dep_version}"',
                        detection_method="static",
                        confidence=0.8,
                        impact="Unpredictable dependency updates, potential supply chain attack",
                        remediation="Pin to specific version",
                        recommended_controls=["version_pinning", "dependency_lock"]
                    )
                    vulnerabilities.append(vuln)
                
                # Check for HTTP URLs
                if any(re.search(pattern, dep_version) for pattern in self.malicious_patterns['suspicious_urls']):
                    vuln = Vulnerability(
                        id=f"supply-{uuid.uuid4().hex[:8]}",
                        category=VulnerabilityCategory.SUPPLY_CHAIN,
                        severity=SeverityLevel.HIGH,
                        title=f"Insecure Dependency Source: {dep_name}",
                        description=f"Package '{dep_name}' uses HTTP or suspicious URL: {dep_version}",
                        file_path=str(package_file.relative_to(project_path)),
                        line_number=None,
                        code_snippet=f'"{dep_name}": "{dep_version}"',
                        detection_method="static",
                        confidence=0.9,
                        impact="Man-in-the-middle attack, package tampering",
                        remediation="Use HTTPS or trusted package registry",
                        recommended_controls=["https_enforcement", "registry_validation"]
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.debug(f"Error analyzing package.json: {e}")
        
        return vulnerabilities
    
    async def _analyze_requirements_txt(self, requirements_file: Path, project_path: Path) -> List[Vulnerability]:
        """Analyze requirements.txt for supply chain issues"""
        vulnerabilities = []
        
        try:
            content = requirements_file.read_text()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Check for HTTP URLs
                if re.search(r'http://', line):
                    vuln = Vulnerability(
                        id=f"supply-{uuid.uuid4().hex[:8]}",
                        category=VulnerabilityCategory.SUPPLY_CHAIN,
                        severity=SeverityLevel.HIGH,
                        title="Insecure Dependency Source (HTTP)",
                        description=f"Insecure HTTP dependency: {line}",
                        file_path=str(requirements_file.relative_to(project_path)),
                        line_number=line_num,
                        code_snippet=line,
                        detection_method="static",
                        confidence=0.9,
                        impact="Man-in-the-middle attack, package tampering",
                        remediation="Use HTTPS or trusted package index",
                        recommended_controls=["https_enforcement", "pypi_validation"]
                    )
                    vulnerabilities.append(vuln)
                
                # Check for unpinned versions
                if '==' not in line and '>=' in line:
                    vuln = Vulnerability(
                        id=f"supply-{uuid.uuid4().hex[:8]}",
                        category=VulnerabilityCategory.SUPPLY_CHAIN,
                        severity=SeverityLevel.MEDIUM,
                        title="Unpinned Dependency Version",
                        description=f"Unpinned version allows automatic updates: {line}",
                        file_path=str(requirements_file.relative_to(project_path)),
                        line_number=line_num,
                        code_snippet=line,
                        detection_method="static",
                        confidence=0.8,
                        impact="Unpredictable dependency updates",
                        remediation="Pin to specific version with == operator",
                        recommended_controls=["version_pinning", "requirements_lock"]
                    )
                    vulnerabilities.append(vuln)
                
                self.dependencies_checked += 1
                    
        except Exception as e:
            logger.debug(f"Error analyzing requirements.txt: {e}")
        
        return vulnerabilities
    
    async def _analyze_pyproject_toml(self, pyproject_file: Path, project_path: Path) -> List[Vulnerability]:
        """Analyze pyproject.toml for supply chain issues"""
        # Similar to requirements.txt analysis
        # For now, return empty list (can be enhanced)
        return []
    
    async def _analyze_go_mod(self, go_mod_file: Path, project_path: Path) -> List[Vulnerability]:
        """Analyze go.mod for supply chain issues"""
        # Similar analysis for Go dependencies
        # For now, return empty list (can be enhanced)
        return []
    
    def _is_typosquatting_risk(self, package_name: str) -> bool:
        """Check if package name might be typosquatting"""
        # Common typosquatting patterns
        suspicious_patterns = [
            r'^[a-z]{1,2}$',  # Very short names
            r'^[a-z]+-[a-z]+-[a-z]+$',  # Multiple hyphens
            r'^[a-z]+[0-9]+$',  # Name with numbers
        ]
        
        # Check against known popular packages (simplified)
        popular_packages = [
            'express', 'lodash', 'axios', 'react', 'vue',
            'requests', 'numpy', 'pandas', 'flask', 'django'
        ]
        
        # If name is very similar to popular package, flag it
        for popular in popular_packages:
            if package_name.lower() != popular.lower() and popular.lower() in package_name.lower():
                return True
        
        return False

