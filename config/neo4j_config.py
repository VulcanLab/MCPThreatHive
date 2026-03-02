"""
Neo4j Configuration for MCP Threat Platform

Supports local Neo4j and Neo4j AuraDB (cloud)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from pathlib import Path
import json

# Default config file path
CONFIG_DIR = Path(__file__).parent.parent / "data" / "config"
NEO4J_CONFIG_FILE = CONFIG_DIR / "neo4j_config.json"


@dataclass
class Neo4jConfig:
    """
    Neo4j connection configuration
    
    Supports:
    - Local Neo4j (bolt://localhost:7687)
    - Neo4j AuraDB cloud (neo4j+s://xxx.databases.neo4j.io)
    """
    
    # Connection
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = ""
    database: str = "neo4j"
    
    # Connection type
    connection_type: str = "local"  # "local" or "aura"
    
    # Optional metadata
    instance_name: str = "MCP Threat Platform"
    auto_connect: bool = False
    
    def __post_init__(self):
        """Load from environment variables if available."""
        self.uri = os.getenv("NEO4J_URI", self.uri)
        self.username = os.getenv("NEO4J_USERNAME", self.username)
        self.password = os.getenv("NEO4J_PASSWORD", self.password)
        self.database = os.getenv("NEO4J_DATABASE", self.database)
    
    @classmethod
    def from_local(
        cls,
        host: str = "localhost",
        port: int = 7687,
        username: str = "neo4j",
        password: str = "password"
    ) -> "Neo4jConfig":
        """Create config for local Neo4j instance."""
        return cls(
            uri=f"bolt://{host}:{port}",
            username=username,
            password=password,
            connection_type="local"
        )
    
    @classmethod
    def from_aura(
        cls,
        instance_id: str,
        username: str,
        password: str
    ) -> "Neo4jConfig":
        """Create config for Neo4j AuraDB cloud instance."""
        return cls(
            uri=f"neo4j+s://{instance_id}.databases.neo4j.io",
            username=username,
            password=password,
            connection_type="aura"
        )
    
    @classmethod
    def load(cls, config_file: Optional[Path] = None) -> "Neo4jConfig":
        """Load config from file."""
        config_path = config_file or NEO4J_CONFIG_FILE
        
        if config_path.exists():
            with open(config_path, 'r') as f:
                data = json.load(f)
                return cls(**data)
        
        return cls()
    
    def save(self, config_file: Optional[Path] = None) -> bool:
        """Save config to file."""
        config_path = config_file or NEO4J_CONFIG_FILE
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
            return True
        except Exception as e:
            print(f"[Neo4jConfig] Error saving config: {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding password for display)."""
        return {
            "uri": self.uri,
            "username": self.username,
            "password": self.password,
            "database": self.database,
            "connection_type": self.connection_type,
            "instance_name": self.instance_name,
            "auto_connect": self.auto_connect
        }
    
    def get_display_dict(self) -> Dict[str, Any]:
        """Get dictionary for display (password masked)."""
        data = self.to_dict()
        if data["password"]:
            data["password"] = "***" + data["password"][-4:] if len(data["password"]) > 4 else "****"
        return data
    
    @property
    def is_configured(self) -> bool:
        """Check if Neo4j is configured with credentials."""
        return bool(self.uri and self.username and self.password)


class Neo4jConfigManager:
    """
    Neo4j configuration manager
    
    Provides:
    - Configuration load/save
    - Connection testing
    - Multi-environment support
    """
    
    def __init__(self, config: Optional[Neo4jConfig] = None):
        self.config = config or Neo4jConfig.load()
        self._driver = None
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test Neo4j connection.
        
        Returns:
            Dict with status, message, and stats if connected
        """
        if not self.config.is_configured:
            return {
                "status": "not_configured",
                "message": "Neo4j credentials not configured",
                "connected": False
            }
        
        try:
            from neo4j import GraphDatabase
            
            driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.username, self.config.password)
            )
            
            with driver.session(database=self.config.database) as session:
                # Test query
                result = session.run("RETURN 1 as test")
                result.single()
                
                # Get stats
                stats_result = session.run("""
                    MATCH (n) 
                    OPTIONAL MATCH (n)-[r]->()
                    RETURN count(DISTINCT n) as nodes, count(r) as relationships
                """)
                stats = stats_result.single()
                
            driver.close()
            
            return {
                "status": "connected",
                "message": f"Successfully connected to {self.config.uri}",
                "connected": True,
                "stats": {
                    "nodes": stats["nodes"],
                    "relationships": stats["relationships"]
                }
            }
            
        except ImportError:
            return {
                "status": "error",
                "message": "neo4j Python driver not installed. Run: pip install neo4j",
                "connected": False
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Connection failed: {str(e)}",
                "connected": False
            }
    
    def update_config(
        self,
        uri: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        connection_type: Optional[str] = None,
        auto_save: bool = True
    ) -> Neo4jConfig:
        """Update configuration."""
        if uri:
            self.config.uri = uri
        if username:
            self.config.username = username
        if password:
            self.config.password = password
        if database:
            self.config.database = database
        if connection_type:
            self.config.connection_type = connection_type
        
        if auto_save:
            self.config.save()
        
        return self.config
    
    def get_cypher_examples(self) -> Dict[str, str]:
        """Get example Cypher queries for MCP Threat analysis."""
        return {
            "all_threats": """
                MATCH (t:Threat)
                RETURN t.title, t.category, t.risk_score
                ORDER BY t.risk_score DESC
            """,
            "threat_to_asset": """
                MATCH (t:Threat)-[r:AFFECTS]->(a:Asset)
                RETURN t.title, type(r), a.name
            """,
            "control_coverage": """
                MATCH (t:Threat)
                OPTIONAL MATCH (t)-[:MITIGATED_BY]->(c:Control)
                RETURN t.title, collect(c.name) as controls
            """,
            "attack_chain": """
                MATCH path = (start:Threat)-[*1..3]->(end:Asset)
                RETURN path
                LIMIT 10
            """,
            "high_risk_threats": """
                MATCH (t:Threat)
                WHERE t.risk_score >= 7.0
                RETURN t.title, t.category, t.risk_score, t.impact
                ORDER BY t.risk_score DESC
            """,
            "mcp_components": """
                MATCH (n)
                WHERE n:MCPServer OR n:MCPTool OR n:LLMProvider
                RETURN labels(n) as type, n.name, n.description
            """
        }


def get_neo4j_config() -> Neo4jConfig:
    """Get Neo4j configuration."""
    return Neo4jConfig.load()


def get_neo4j_manager() -> Neo4jConfigManager:
    """Get Neo4j configuration manager."""
    return Neo4jConfigManager()

