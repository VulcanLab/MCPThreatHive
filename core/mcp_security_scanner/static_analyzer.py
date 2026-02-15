"""
Static Analyzer - Code, Configuration, and Metadata Analysis

Detects vulnerabilities through static analysis of:
- MCP tool definitions and metadata
- Code patterns (command injection, path traversal, etc.)
- Configuration files
- Hardcoded credentials
"""

import re
import json
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import uuid

from .models import Vulnerability, VulnerabilityCategory, SeverityLevel, ScanConfig
from .utils import discover_files

logger = logging.getLogger(__name__)


class StaticAnalyzer:
    """Static code and configuration analyzer"""
    
    def __init__(self):
        self.files_scanned = 0
        self.tools_analyzed = 0
        
        # Pattern definitions for various vulnerability types
        self.patterns = {
            'command_injection': [
                r'os\.system\s*\(',
                r'subprocess\.(call|run|Popen)\s*\(',
                r'eval\s*\(',
                r'exec\s*\(',
                r'child_process\.(exec|spawn)\s*\(',
                r'\.exec\s*\(',
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\\\',
                r'open\s*\(\s*["\'].*\.\.',
                r'readFile\s*\(\s*["\'].*\.\.',
                r'fs\.(readFile|writeFile)\s*\(\s*["\'].*\.\.',
            ],
            'hardcoded_credentials': [
                r'(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']+["\']',
                r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']',
                r'(secret|token|credential)\s*[=:]\s*["\'][^"\']+["\']',
                r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\'][^"\']+["\']',
                r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\'][^"\']+["\']',
            ],
            'ssrf': [
                r'requests?\.(get|post|put|delete)\s*\(\s*["\'](http|https)://',
                r'fetch\s*\(\s*["\'](http|https)://',
                r'urllib\.(urlopen|request)\s*\(',
                r'http\.(get|post|request)\s*\(',
            ],
            'prompt_injection_keywords': [
                r'ignore\s+previous\s+instructions',
                r'system\s+override',
                r'forget\s+all\s+previous',
                r'new\s+instructions',
                r'you\s+are\s+now',
                r'act\s+as\s+if',
            ],
        }
    
    async def analyze(self, project_path: Path, config: ScanConfig) -> List[Vulnerability]:
        """
        Perform static analysis
        
        Args:
            project_path: Path to project directory
            config: Scan configuration
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Load custom detection rules from database
        custom_rules = await self._load_detection_rules()
        
        # Discover files
        files = discover_files(
            project_path,
            config.static_include_patterns,
            config.static_exclude_patterns
        )
        
        self.files_scanned = len(files)
        logger.info(f"Scanning {self.files_scanned} files for static vulnerabilities")
        
        # Analyze each file
        for file_path in files:
            try:
                file_vulns = await self._analyze_file(file_path, project_path, custom_rules)
                vulnerabilities.extend(file_vulns)
            except Exception as e:
                logger.warning(f"Error analyzing {file_path}: {e}")
        
        # Analyze MCP-specific files
        mcp_vulns = await self._analyze_mcp_files(project_path)
        vulnerabilities.extend(mcp_vulns)
        
        return vulnerabilities
    
    async def _load_detection_rules(self) -> List[Dict[str, Any]]:
        """Load active detection rules from database"""
        try:
            from database.db_manager import get_db_manager
            db = get_db_manager()
            rules = db.get_detection_rules(
                filters={"rule_type": "static", "status": "active"},
                limit=100
            )
            return [{"id": r.id, "name": r.name, "rule_json": r.rule_json} for r in rules]
        except Exception as e:
            logger.warning(f"Could not load detection rules: {e}")
            return []
    
    async def _analyze_file(self, file_path: Path, project_path: Path, custom_rules: List[Dict[str, Any]] = None) -> List[Vulnerability]:
        """Analyze a single file"""
        vulnerabilities = []
        custom_rules = custom_rules or []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Cannot read {file_path}: {e}")
            return []
        
        relative_path = str(file_path.relative_to(project_path))
        
        # Apply custom detection rules
        for rule in custom_rules:
            try:
                rule_json = rule.get("rule_json")
                if isinstance(rule_json, str):
                    import json
                    rule_json = json.loads(rule_json)
                
                if rule_json.get("type") == "static":
                    patterns = rule_json.get("patterns", [])
                    file_types = rule_json.get("file_types", [])
                    
                    # Check if file matches file types
                    matches_file_type = False
                    for ft in file_types:
                        if ft.startswith("*."):
                            ext = ft[2:]
                            if file_path.suffix.lower() == f".{ext}":
                                matches_file_type = True
                                break
                        elif file_path.name.endswith(ft):
                            matches_file_type = True
                            break
                    
                    if not matches_file_type:
                        continue
                    
                    # Check patterns
                    for pattern_def in patterns:
                        pattern_str = pattern_def.get("pattern", "")
                        if pattern_str:
                            for match in re.finditer(pattern_str, content, re.IGNORECASE):
                                line_num = content[:match.start()].count('\n') + 1
                                vuln = Vulnerability(
                                    id=f"rule-{rule['id']}-{uuid.uuid4().hex[:8]}",
                                    category=VulnerabilityCategory.OTHER,
                                    severity=SeverityLevel.MEDIUM,
                                    title=f"[Custom Rule] {rule.get('name', 'Unknown')}",
                                    description=pattern_def.get("description", f"Pattern matched: {pattern_str[:50]}"),
                                    file_path=relative_path,
                                    line_number=line_num,
                                    code_snippet=self._get_code_snippet(content, line_num),
                                    detection_method="static_rule",
                                    confidence=0.7,
                                    impact=rule_json.get("description", "Custom rule violation"),
                                    remediation="Review and fix according to rule requirements",
                                    recommended_controls=["custom_rule_compliance"],
                                    metadata={"rule_id": rule['id'], "rule_name": rule.get('name')}
                                )
                                vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug(f"Error applying custom rule {rule.get('id')}: {e}")
        
        # Check for command injection
        for pattern in self.patterns['command_injection']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                vuln = Vulnerability(
                    id=f"static-{uuid.uuid4().hex[:8]}",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=SeverityLevel.HIGH,
                    title="Potential Command Injection",
                    description=f"Dangerous function call detected: {match.group()}",
                    file_path=relative_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(content, line_num),
                    detection_method="static",
                    confidence=0.7,
                    impact="Potential remote code execution",
                    remediation="Use parameterized commands or safe alternatives",
                    recommended_controls=["input_validation", "parameterized_commands", "sandboxing"]
                )
                vulnerabilities.append(vuln)
        
        # Check for path traversal
        for pattern in self.patterns['path_traversal']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                vuln = Vulnerability(
                    id=f"static-{uuid.uuid4().hex[:8]}",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=SeverityLevel.MEDIUM,
                    title="Potential Path Traversal",
                    description=f"Path traversal pattern detected: {match.group()}",
                    file_path=relative_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(content, line_num),
                    detection_method="static",
                    confidence=0.6,
                    impact="Unauthorized file access",
                    remediation="Validate and sanitize file paths",
                    recommended_controls=["path_validation", "whitelist_allowed_paths"]
                )
                vulnerabilities.append(vuln)
        
        # Check for hardcoded credentials
        for pattern in self.patterns['hardcoded_credentials']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                vuln = Vulnerability(
                    id=f"static-{uuid.uuid4().hex[:8]}",
                    category=VulnerabilityCategory.CREDENTIAL_LEAK,
                    severity=SeverityLevel.CRITICAL,
                    title="Hardcoded Credentials Detected",
                    description=f"Potential hardcoded credential: {match.group()[:50]}...",
                    file_path=relative_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(content, line_num),
                    detection_method="static",
                    confidence=0.8,
                    impact="Credential exposure and potential unauthorized access",
                    remediation="Move credentials to environment variables or secure vault",
                    recommended_controls=["environment_variables", "secret_management", "credential_rotation"]
                )
                vulnerabilities.append(vuln)
        
        # Check for SSRF
        for pattern in self.patterns['ssrf']:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                vuln = Vulnerability(
                    id=f"static-{uuid.uuid4().hex[:8]}",
                    category=VulnerabilityCategory.SSRF,
                    severity=SeverityLevel.HIGH,
                    title="Potential SSRF Vulnerability",
                    description=f"Unvalidated HTTP request: {match.group()}",
                    file_path=relative_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(content, line_num),
                    detection_method="static",
                    confidence=0.6,
                    impact="Server-side request forgery, internal network access",
                    remediation="Validate and whitelist allowed URLs",
                    recommended_controls=["url_whitelist", "network_isolation", "input_validation"]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _analyze_mcp_files(self, project_path: Path) -> List[Vulnerability]:
        """Analyze MCP-specific files (tool definitions, configs)"""
        vulnerabilities = []
        
        # Look for MCP config files
        config_files = [
            project_path / "mcp.json",
            project_path / ".mcp.json",
            project_path / "package.json",
            project_path / "pyproject.toml",
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    if config_file.suffix == '.json':
                        config_data = json.loads(config_file.read_text())
                    elif config_file.suffix in ['.yaml', '.yml']:
                        config_data = yaml.safe_load(config_file.read_text())
                    else:
                        continue
                    
                    # Analyze tool definitions
                    tools = self._extract_tools(config_data)
                    self.tools_analyzed += len(tools)
                    
                    for tool in tools:
                        tool_vulns = self._analyze_tool_definition(tool, config_file, project_path)
                        vulnerabilities.extend(tool_vulns)
                        
                except Exception as e:
                    logger.debug(f"Error analyzing config {config_file}: {e}")
        
        return vulnerabilities
    
    def _extract_tools(self, config_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract tool definitions from config"""
        tools = []
        
        # Common MCP tool definition locations
        if isinstance(config_data, dict):
            if 'tools' in config_data:
                tools.extend(config_data['tools'])
            if 'mcp' in config_data and 'tools' in config_data['mcp']:
                tools.extend(config_data['mcp']['tools'])
            if 'server' in config_data and 'tools' in config_data['server']:
                tools.extend(config_data['server']['tools'])
        
        return tools
    
    def _analyze_tool_definition(self, tool: Dict[str, Any], config_file: Path, project_path: Path) -> List[Vulnerability]:
        """Analyze a single tool definition for vulnerabilities"""
        vulnerabilities = []
        
        tool_name = tool.get('name', 'unknown')
        description = tool.get('description', '')
        
        # Check for prompt injection in description
        for pattern in self.patterns['prompt_injection_keywords']:
            if re.search(pattern, description, re.IGNORECASE):
                vuln = Vulnerability(
                    id=f"static-{uuid.uuid4().hex[:8]}",
                    category=VulnerabilityCategory.TOOL_POISONING,
                    severity=SeverityLevel.CRITICAL,
                    title=f"Tool Poisoning in {tool_name}",
                    description=f"Malicious instruction detected in tool description: {pattern}",
                    file_path=str(config_file.relative_to(project_path)),
                    line_number=None,
                    code_snippet=description[:200],
                    detection_method="static",
                    confidence=0.9,
                    impact="LLM may execute hidden malicious instructions",
                    remediation="Remove malicious instructions from tool description",
                    recommended_controls=["description_validation", "content_sanitization", "tool_review"]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_code_snippet(self, content: str, line_num: int, context_lines: int = 3) -> str:
        """Extract code snippet around line number"""
        lines = content.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return '\n'.join(lines[start:end])

