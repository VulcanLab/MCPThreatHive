"""
MCP Environment Configuration Scanner

Scans the entire MCP environment configuration to discover all servers, tools, and potential risks.
This is different from scanning Canvas components - it scans the actual MCP configuration files
in the system (VSCode settings, Claude Desktop config, project configs, etc.).
"""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class MCPEnvironmentComponent:
    """Represents a component discovered from MCP environment configuration"""
    id: str
    component_type: str  # 'MCP Server', 'Tool', 'Resource', etc.
    name: str
    config_path: Optional[str] = None
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tools: List[Dict[str, Any]] = field(default_factory=list)


class MCPEnvironmentScanner:
    """
    Scans the entire MCP environment configuration to discover all servers and tools.
    
    Looks for MCP configuration in:
    - VSCode settings (user and workspace)
    - Claude Desktop configuration
    - Project-level MCP config files
    - System-wide MCP configurations
    """
    
    def __init__(self):
        """Initialize the scanner"""
        self.discovered_components: List[MCPEnvironmentComponent] = []
        self.config_locations: List[Path] = []
    
    def scan_environment(self) -> List[MCPEnvironmentComponent]:
        """
        Scan the entire MCP environment for configuration files.
        
        Returns:
            List of discovered MCP components
        """
        self.discovered_components = []
        
        # 1. Scan VSCode MCP settings
        self._scan_vscode_config()
        
        # 2. Scan Claude Desktop config
        self._scan_claude_desktop_config()
        
        # 3. Scan project-level configs
        self._scan_project_configs()
        
        # 4. Scan system-wide configs
        self._scan_system_configs()
        
        return self.discovered_components
    
    def _scan_vscode_config(self):
        """Scan VSCode MCP configuration"""
        # VSCode user settings
        vscode_user_settings = self._get_vscode_user_settings_path()
        if vscode_user_settings and vscode_user_settings.exists():
            self._parse_vscode_config(vscode_user_settings, 'vscode-user')
        
        # VSCode workspace settings
        vscode_workspace_settings = self._get_vscode_workspace_settings_path()
        if vscode_workspace_settings and vscode_workspace_settings.exists():
            self._parse_vscode_config(vscode_workspace_settings, 'vscode-workspace')
    
    def _get_vscode_user_settings_path(self) -> Optional[Path]:
        """Get VSCode user settings path"""
        home = Path.home()
        
        # macOS
        if os.name == 'posix' and sys.platform == 'darwin':
            return home / 'Library' / 'Application Support' / 'Code' / 'User' / 'settings.json'
        
        # Linux
        elif os.name == 'posix':
            return home / '.config' / 'Code' / 'User' / 'settings.json'
        
        # Windows
        elif os.name == 'nt':
            appdata = os.getenv('APPDATA')
            if appdata:
                return Path(appdata) / 'Code' / 'User' / 'settings.json'
        
        return None
    
    def _get_vscode_workspace_settings_path(self) -> Optional[Path]:
        """Get VSCode workspace settings path (current directory)"""
        cwd = Path.cwd()
        workspace_settings = cwd / '.vscode' / 'settings.json'
        if workspace_settings.exists():
            return workspace_settings
        return None
    
    def _parse_vscode_config(self, config_path: Path, source: str):
        """Parse VSCode MCP configuration"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            
            # VSCode stores MCP config in 'mcp.servers' or 'mcpServers'
            mcp_servers = settings.get('mcp.servers', settings.get('mcpServers', {}))
            
            if not isinstance(mcp_servers, dict):
                return
            
            for server_name, server_config in mcp_servers.items():
                component = self._create_component_from_vscode_config(
                    server_name, server_config, config_path, source
                )
                if component:
                    self.discovered_components.append(component)
        
        except Exception as e:
            print(f"[MCPEnvScanner] Error parsing VSCode config {config_path}: {e}")
    
    def _create_component_from_vscode_config(
        self, 
        server_name: str, 
        server_config: Dict[str, Any],
        config_path: Path,
        source: str
    ) -> Optional[MCPEnvironmentComponent]:
        """Create component from VSCode MCP server configuration"""
        command = server_config.get('command', '')
        args = server_config.get('args', [])
        env = server_config.get('env', {})
        
        # Extract capabilities from command and args
        capabilities = self._extract_capabilities_from_config(command, args, env)
        
        # Extract tools if available
        tools = server_config.get('tools', [])
        
        return MCPEnvironmentComponent(
            id=f"mcp-env-{source}-{server_name}",
            component_type='MCP Server',
            name=server_name,
            config_path=str(config_path),
            command=command,
            args=args if isinstance(args, list) else [],
            env=env if isinstance(env, dict) else {},
            capabilities=capabilities,
            metadata={
                'source': source,
                'config_type': 'vscode',
                'original_config': server_config
            },
            tools=tools if isinstance(tools, list) else []
        )
    
    def _scan_claude_desktop_config(self):
        """Scan Claude Desktop MCP configuration"""
        claude_config = self._get_claude_desktop_config_path()
        if claude_config and claude_config.exists():
            self._parse_claude_desktop_config(claude_config)
    
    def _get_claude_desktop_config_path(self) -> Optional[Path]:
        """Get Claude Desktop configuration path"""
        home = Path.home()
        
        # macOS
        if os.name == 'posix' and sys.platform == 'darwin':
            return home / 'Library' / 'Application Support' / 'Claude' / 'claude_desktop_config.json'
        
        # Linux
        elif os.name == 'posix':
            return home / '.config' / 'claude' / 'claude_desktop_config.json'
        
        # Windows
        elif os.name == 'nt':
            appdata = os.getenv('APPDATA')
            if appdata:
                return Path(appdata) / 'Claude' / 'claude_desktop_config.json'
        
        return None
    
    def _parse_claude_desktop_config(self, config_path: Path):
        """Parse Claude Desktop MCP configuration"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Claude Desktop stores MCP config in 'mcpServers'
            mcp_servers = config.get('mcpServers', {})
            
            if not isinstance(mcp_servers, dict):
                return
            
            for server_name, server_config in mcp_servers.items():
                component = self._create_component_from_claude_config(
                    server_name, server_config, config_path
                )
                if component:
                    self.discovered_components.append(component)
        
        except Exception as e:
            print(f"[MCPEnvScanner] Error parsing Claude Desktop config {config_path}: {e}")
    
    def _create_component_from_claude_config(
        self,
        server_name: str,
        server_config: Dict[str, Any],
        config_path: Path
    ) -> Optional[MCPEnvironmentComponent]:
        """Create component from Claude Desktop MCP server configuration"""
        command = server_config.get('command', '')
        args = server_config.get('args', [])
        env = server_config.get('env', {})
        
        capabilities = self._extract_capabilities_from_config(command, args, env)
        
        return MCPEnvironmentComponent(
            id=f"mcp-env-claude-{server_name}",
            component_type='MCP Server',
            name=server_name,
            config_path=str(config_path),
            command=command,
            args=args if isinstance(args, list) else [],
            env=env if isinstance(env, dict) else {},
            capabilities=capabilities,
            metadata={
                'source': 'claude-desktop',
                'config_type': 'claude',
                'original_config': server_config
            },
            tools=[]  # Claude Desktop config usually doesn't include tool definitions
        )
    
    def _scan_project_configs(self):
        """Scan project-level MCP configuration files"""
        cwd = Path.cwd()
        
        # Look for common MCP config file names
        config_files = [
            cwd / 'mcp.json',
            cwd / '.mcp.json',
            cwd / 'mcp.config.json',
            cwd / 'package.json',  # May contain MCP config
        ]
        
        for config_file in config_files:
            if config_file.exists():
                self._parse_project_config(config_file)
    
    def _parse_project_config(self, config_path: Path):
        """Parse project-level MCP configuration"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Check for MCP config in various formats
            mcp_servers = (
                config.get('mcpServers') or
                config.get('mcp.servers') or
                config.get('mcp', {}).get('servers', {})
            )
            
            if not isinstance(mcp_servers, dict):
                return
            
            for server_name, server_config in mcp_servers.items():
                component = self._create_component_from_project_config(
                    server_name, server_config, config_path
                )
                if component:
                    self.discovered_components.append(component)
        
        except Exception as e:
            print(f"[MCPEnvScanner] Error parsing project config {config_path}: {e}")
    
    def _create_component_from_project_config(
        self,
        server_name: str,
        server_config: Dict[str, Any],
        config_path: Path
    ) -> Optional[MCPEnvironmentComponent]:
        """Create component from project-level MCP configuration"""
        command = server_config.get('command', '')
        args = server_config.get('args', [])
        env = server_config.get('env', {})
        
        capabilities = self._extract_capabilities_from_config(command, args, env)
        tools = server_config.get('tools', [])
        
        return MCPEnvironmentComponent(
            id=f"mcp-env-project-{server_name}",
            component_type='MCP Server',
            name=server_name,
            config_path=str(config_path),
            command=command,
            args=args if isinstance(args, list) else [],
            env=env if isinstance(env, dict) else {},
            capabilities=capabilities,
            metadata={
                'source': 'project',
                'config_type': 'project',
                'original_config': server_config
            },
            tools=tools if isinstance(tools, list) else []
        )
    
    def _scan_system_configs(self):
        """Scan system-wide MCP configurations"""
        # This could include:
        # - /etc/mcp/config.json (Linux)
        # - /usr/local/etc/mcp/config.json (macOS)
        # - Other system-wide locations
        pass
    
    def _extract_capabilities_from_config(
        self,
        command: str,
        args: List[str],
        env: Dict[str, str]
    ) -> List[str]:
        """Extract capabilities from MCP server configuration"""
        capabilities = []
        
        # Combine command and args for analysis
        full_command = f"{command} {' '.join(args) if args else ''}"
        full_command_lower = full_command.lower()
        
        # Check for filesystem access
        if any(keyword in full_command_lower for keyword in ['filesystem', 'file', 'fs', 'read', 'write']):
            if 'write' in full_command_lower or 'write_file' in full_command_lower:
                capabilities.append('write_file')
            if 'read' in full_command_lower or 'read_file' in full_command_lower:
                capabilities.append('read_file')
            capabilities.append('filesystem_access')
        
        # Check for browser access
        if any(keyword in full_command_lower for keyword in ['browser', 'puppeteer', 'playwright', 'selenium']):
            capabilities.append('browser_access')
        
        # Check for network access
        if any(keyword in full_command_lower for keyword in ['fetch', 'http', 'https', 'network', 'request']):
            capabilities.append('network_access')
        
        # Check for execution capabilities
        if any(keyword in full_command_lower for keyword in ['exec', 'execute', 'shell', 'command', 'run']):
            capabilities.append('exec')
        
        # Check for database access
        if any(keyword in full_command_lower for keyword in ['database', 'db', 'sql', 'postgres', 'mysql', 'mongodb']):
            capabilities.append('db_access')
        
        # Check environment variables for additional capabilities
        env_str = ' '.join(env.values()).lower() if env else ''
        if 'api_key' in env_str or 'token' in env_str or 'secret' in env_str:
            capabilities.append('credential_access')
        
        return list(set(capabilities))  # Remove duplicates
    
    def get_components_as_dicts(self) -> List[Dict[str, Any]]:
        """Convert discovered components to dictionary format for API"""
        return [
            {
                'id': comp.id,
                'type': comp.component_type,
                'name': comp.name,
                'capabilities': comp.capabilities,
                'metadata': {
                    **comp.metadata,
                    'config_path': comp.config_path,
                    'command': comp.command,
                    'args': comp.args,
                    'env': comp.env,
                    'tools': comp.tools
                },
                'connections': []  # Environment components don't have Canvas connections
            }
            for comp in self.discovered_components
        ]


# Import sys for platform detection
import sys


