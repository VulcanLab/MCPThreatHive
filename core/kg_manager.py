"""
Knowledge Graph Manager for MCP Threat Platform

Integrates KG and Neo4j to provide knowledge graph capabilities for MCP threat modeling:
- Generate knowledge graphs from threat intelligence
- Build relationships from threat cards
- Store to Neo4j / JSON
- Visualize relationship graphs
"""

from __future__ import annotations

import sys
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime
import uuid

# Ensure project root is in Python path
_script_dir = Path(__file__).parent
_project_root = _script_dir.parent

sys.path.insert(0, str(_project_root))
sys.path.insert(0, str(_project_root.parent / "mcp_intel_gatherer"))



# Try to import Neo4j
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    print("[KGManager] ⚠️  neo4j not installed. Install with: pip install neo4j")

from schemas.mcp_threat_schema import (
    MCPThreat, MCPAsset, MCPControl, MCPAttackEvidence,
    StrideCategory, RiskLevel
)
from config.neo4j_config import Neo4jConfig, Neo4jConfigManager


class MCPKnowledgeGraph:
    """
    MCP Threat Knowledge Graph
    
    Knowledge graph designed specifically for MCP security threat modeling, including:
    - Node types: Threat, Asset, Control, Evidence, MCPServer, MCPTool, LLMProvider
    - Relationship types: AFFECTS, MITIGATED_BY, EXPLOITS, DEPENDS_ON, RELATED_TO
    """
    
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}  # id -> node data
        self.edges: List[Dict[str, Any]] = []  # list of edges
        self.metadata: Dict[str, Any] = {
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "name": "MCP Threat Knowledge Graph",
            "version": "1.0"
        }
    
    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> str:
        """Add a node to the graph."""
        self.nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "properties": properties or {},
            "created_at": datetime.now().isoformat()
        }
        self.metadata["updated_at"] = datetime.now().isoformat()
        return node_id
    
    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Add an edge to the graph."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return False
        
        self.edges.append({
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
            "properties": properties or {}
        })
        self.metadata["updated_at"] = datetime.now().isoformat()
        return True
    
    def add_threat(self, threat: MCPThreat) -> str:
        """Add a threat as a node."""
        node_id = threat.id
        self.add_node(
            node_id=node_id,
            label=threat.title,
            node_type="Threat",
            properties={
                "category": threat.category.value if hasattr(threat.category, 'value') else str(threat.category),
                "risk_score": threat.risk_score,
                "risk_level": threat.risk_level.value if hasattr(threat.risk_level, 'value') else str(threat.risk_level),
                "description": threat.description,
                "impact": threat.impact,
                "attack_vector": threat.attack_vector,
                "recommended_controls": threat.recommended_controls
            }
        )
        
        # Add affected components as nodes and edges
        for component in threat.affected_components:
            component_id = f"asset-{component.lower().replace(' ', '-').replace(':', '-')}"
            if component_id not in self.nodes:
                self.add_node(
                    node_id=component_id,
                    label=component,
                    node_type="Asset"
                )
            self.add_edge(node_id, component_id, "AFFECTS")
        
        return node_id
    
    def add_asset(self, asset: MCPAsset) -> str:
        """Add an asset as a node."""
        node_id = asset.id
        self.add_node(
            node_id=node_id,
            label=asset.name,
            node_type=f"Asset:{asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)}",
            properties={
                "description": asset.description or "",
                "asset_type": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type),
                "tags": asset.tags if hasattr(asset, 'tags') else []
            }
        )
        return node_id
    
    def add_control(self, control: MCPControl) -> str:
        """Add a security control as a node."""
        node_id = control.id
        properties = {
            "description": control.description,
            "control_type": control.control_type.value if hasattr(control.control_type, 'value') else str(control.control_type),
            "effectiveness": control.effectiveness,
        }
        # Only add implementation_status if it exists (it's not in MCPControl schema)
        if hasattr(control, 'implementation_status'):
            properties["implementation_status"] = control.implementation_status
        
        self.add_node(
            node_id=node_id,
            label=control.name,
            node_type="Control",
            properties=properties
        )
        return node_id
    
    def link_threat_to_control(self, threat_id: str, control_id: str) -> bool:
        """Link a threat to a mitigating control."""
        return self.add_edge(threat_id, control_id, "MITIGATED_BY")
    
    def link_threat_to_asset(self, threat_id: str, asset_id: str) -> bool:
        """Link a threat to an affected asset."""
        return self.add_edge(threat_id, asset_id, "AFFECTS")
    
    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def get_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        """Get all nodes connected to the given node."""
        neighbors = []
        for edge in self.edges:
            if edge["source"] == node_id:
                if edge["target"] in self.nodes:
                    neighbors.append({
                        "node": self.nodes[edge["target"]],
                        "relationship": edge["relationship"],
                        "direction": "outgoing"
                    })
            elif edge["target"] == node_id:
                if edge["source"] in self.nodes:
                    neighbors.append({
                        "node": self.nodes[edge["source"]],
                        "relationship": edge["relationship"],
                        "direction": "incoming"
                    })
        return neighbors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "metadata": self.metadata
        }
    
    def to_vis_format(self) -> Dict[str, Any]:
        """Convert to vis.js format for visualization."""
        # Node colors by type
        type_colors = {
            "Threat": "#dc3545",      # Red
            "Vulnerability": "#f97316",  # Orange
            "Technique": "#8b5cf6",   # Purple
            "Asset": "#17a2b8",       # Blue
            "Control": "#28a745",     # Green
            "Evidence": "#ffc107",    # Yellow
            "MCPServer": "#6f42c1",   # Purple
            "MCPTool": "#fd7e14",     # Orange
            "Component": "#3b82f6",   # Blue
            "Tool": "#06b6d4",        # Cyan
            "Entity": "#6366f1",      # Indigo
            "LLMProvider": "#20c997"  # Teal
        }
        
        vis_nodes = []
        for node_id, node in self.nodes.items():
            node_type = node["type"].split(":")[0]  # Get base type
            properties = node.get("properties", {})
            source_urls = properties.get("source_urls", [])
            primary_url = properties.get("primary_url")
            
            # Build tooltip with source info
            tooltip = f"{node['label']}\nType: {node_type}"
            if properties.get("description"):
                tooltip += f"\n{properties['description'][:100]}"
            if source_urls:
                tooltip += f"\n\nSources: {len(source_urls)} URL(s)"
            
            vis_nodes.append({
                "id": node_id,
                "node_id": node_id,  # For compatibility
                "label": node["label"][:30] + "..." if len(node["label"]) > 30 else node["label"],
                "name": node["label"],  # Full name
                "type": node_type,
                "node_type": node_type,  # For compatibility
                "title": tooltip,
                "color": type_colors.get(node_type, "#95a5a6"),
                "shape": "dot",
                "size": (25 if node_type in ["Threat", "Vulnerability"] else 20) + min(properties.get("source_count", 0) * 3, 40),
                "properties": properties  # Include all properties for click handler
            })
        
        vis_edges = []
        for edge in self.edges:
            edge_properties = edge.get("properties", {})
            vis_edges.append({
                "from": edge["source"],
                "source": edge["source"],  # For compatibility
                "to": edge["target"],
                "target": edge["target"],  # For compatibility
                "label": edge["relationship"],
                "relation": edge["relationship"],  # For compatibility
                "arrows": "to",
                "color": {"color": "#888", "highlight": "#e94560"},
                "properties": edge_properties  # Include properties for click handler
            })
        
        return {"nodes": vis_nodes, "edges": vis_edges}
    
    def save(self, filepath: str) -> bool:
        """Save graph to JSON file."""
        try:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[KGManager] Error saving graph: {e}")
            return False
    
    @classmethod
    def load(cls, filepath: str) -> "MCPKnowledgeGraph":
        """Load graph from JSON file."""
        graph = cls()
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Load nodes
            for node in data.get("nodes", []):
                graph.nodes[node["id"]] = node
            
            # Load edges
            graph.edges = data.get("edges", [])
            
            # Load metadata
            if "metadata" in data:
                graph.metadata.update(data["metadata"])
            
        except Exception as e:
            print(f"[KGManager] Error loading graph: {e}")
        
        return graph


class KnowledgeGraphManager:
    """
    Knowledge Graph Manager
    
    Features:
    - Automatically generate knowledge graphs from threat intelligence
    - Build relationships from threat cards
    - Integrate Neo4j persistence
    - Generate visualizations
    """
    
    def __init__(
        self,
        neo4j_config: Optional[Neo4jConfig] = None,
        llm_config: Optional[Any] = None
    ):
        """
        Initialize Knowledge Graph Manager.
        
        Args:
            neo4j_config: Neo4j connection configuration (optional)
            llm_config: LLM configuration for kg-gen
        """
        self.neo4j_config = neo4j_config or Neo4jConfig.load()
        self.llm_config = llm_config
        self._driver = None
        self._kg_gen = None
        
        # Data directory
        self.data_dir = Path(__file__).parent.parent / "data" / "knowledge_graphs"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Current graph
        self.current_graph = MCPKnowledgeGraph()
    
    def init_kg_gen(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        temperature: float = 0.0
    ) -> bool:
        """Initialize kg-gen for graph generation."""
        # Try to import kg-gen locally
        try:
            from kg_gen import KGGen
        except ImportError:
            print("[KGManager] ⚠️  kg-gen not installed. Install with: pip install kg-gen")
            return False
        
        # Get model from parameter or environment
        actual_model = model or os.getenv("LITELLM_MODEL")
        if not actual_model:
            print("[KGManager] No model specified, check LITELLM_MODEL environment variable")
            return False
        
        try:
            init_kwargs = {
                "model": actual_model,
                "temperature": temperature
            }
            if api_key:
                init_kwargs["api_key"] = api_key
            if api_base:
                init_kwargs["api_base"] = api_base
            
            self._kg_gen = KGGen(**init_kwargs)
            print(f"[KGManager] kg-gen initialized with model: {actual_model}")
            return True
        except Exception as e:
            print(f"[KGManager] ❌ Failed to initialize kg-gen: {e}")
            return False
    
    def connect_neo4j(self) -> bool:
        """Connect to Neo4j database."""
        if not NEO4J_AVAILABLE:
            print("[KGManager] Neo4j driver not available")
            return False
        
        if not self.neo4j_config or not self.neo4j_config.is_configured:
            print("[KGManager] Neo4j not configured")
            return False
        
        try:
            self._driver = GraphDatabase.driver(
                self.neo4j_config.uri,
                auth=(self.neo4j_config.username, self.neo4j_config.password)
            )
            # Test connection
            with self._driver.session(database=self.neo4j_config.database) as session:
                session.run("RETURN 1")
            print(f"[KGManager] ✓ Connected to Neo4j: {self.neo4j_config.uri}")
            return True
        except Exception as e:
            print(f"[KGManager] ❌ Failed to connect to Neo4j: {e}")
            self._driver = None
            return False
    
    def disconnect_neo4j(self):
        """Disconnect from Neo4j."""
        if self._driver:
            self._driver.close()
            self._driver = None
            print("[KGManager] Disconnected from Neo4j")
    
    def generate_from_threats(
        self,
        threats: List[MCPThreat],
        assets: Optional[List[MCPAsset]] = None,
        controls: Optional[List[MCPControl]] = None,
        use_ai: bool = False
    ) -> MCPKnowledgeGraph:
        """
        Generate knowledge graph from threat cards.
        
        Args:
            threats: List of MCPThreat objects
            assets: Optional list of MCPAsset objects
            controls: Optional list of MCPControl objects
            use_ai: Whether to use kg-gen for enhanced relationship extraction
        
        Returns:
            MCPKnowledgeGraph
        """
        graph = MCPKnowledgeGraph()
        graph.metadata["name"] = f"MCP Threat Graph ({len(threats)} threats)"
        
        # Add threats
        for threat in threats:
            graph.add_threat(threat)
        
        # Add assets
        if assets:
            for asset in assets:
                graph.add_asset(asset)
        
        # Add controls
        if controls:
            for control in controls:
                graph.add_control(control)
                
                # Auto-link controls to threats based on recommended_controls
                for threat in threats:
                    if control.name in threat.recommended_controls or \
                       any(control.name.lower() in rc.lower() for rc in threat.recommended_controls):
                        graph.link_threat_to_control(threat.id, control.id)
        
        # Auto-link threats based on STRIDE category
        threat_by_category: Dict[str, List[str]] = {}
        for threat in threats:
            category = threat.category.value if hasattr(threat.category, 'value') else str(threat.category)
            if category not in threat_by_category:
                threat_by_category[category] = []
            threat_by_category[category].append(threat.id)
        
        # Link threats in same category
        for category, threat_ids in threat_by_category.items():
            for i, tid1 in enumerate(threat_ids):
                for tid2 in threat_ids[i+1:]:
                    graph.add_edge(tid1, tid2, "RELATED_TO", {"reason": f"Same STRIDE category: {category}"})
        
        # Use AI for enhanced extraction if available
        if use_ai and self._kg_gen:
            graph = self._enhance_with_ai(graph, threats)
        
        self.current_graph = graph
        return graph
    
    def generate_from_intel(
        self,
        intel_items: List[Dict[str, Any]],
        context: str = "MCP Security Threat Intelligence"
    ) -> Optional[MCPKnowledgeGraph]:
        """
        Generate knowledge graph from intelligence items using kg-gen.
        
        Args:
            intel_items: List of intelligence items (from intel_gatherer)
            context: Context for kg-gen
        
        Returns:
            MCPKnowledgeGraph or None
        """
        if not self._kg_gen:
            print("[KGManager] kg-gen not initialized. Call init_kg_gen() first.")
            return None
        
        if not intel_items:
            print("[KGManager] No intelligence items provided")
            return None
        
        try:
            # Combine intel items into text
            text_parts = []
            for item in intel_items:
                parts = []
                if item.get("title"):
                    parts.append(f"Title: {item['title']}")
                if item.get("summary"):
                    parts.append(f"Summary: {item['summary']}")
                if item.get("content"):
                    parts.append(f"Content: {item['content'][:2000]}")
                text_parts.append("\n".join(parts))
            
            combined_text = "\n\n---\n\n".join(text_parts)
            
            # Generate with kg-gen
            print(f"[KGManager] Generating graph from {len(intel_items)} intel items...")
            kg_gen_graph = self._kg_gen.generate(
                input_data=combined_text,
                context=context,
                cluster=True
            )
            
            # Convert to MCPKnowledgeGraph
            mcp_graph = MCPKnowledgeGraph()
            mcp_graph.metadata["name"] = f"Intel-based Graph ({len(intel_items)} sources)"
            
            # Add entities as nodes
            for entity in kg_gen_graph.entities:
                node_id = f"entity-{entity.lower().replace(' ', '-')[:50]}"
                node_type = self._infer_entity_type(entity)
                mcp_graph.add_node(node_id, entity, node_type)
            
            # Add relations as edges
            for relation in kg_gen_graph.relations:
                if len(relation) >= 3:
                    source = f"entity-{relation[0].lower().replace(' ', '-')[:50]}"
                    target = f"entity-{relation[2].lower().replace(' ', '-')[:50]}"
                    relationship = relation[1].upper().replace(" ", "_")
                    mcp_graph.add_edge(source, target, relationship)
            
            print(f"[KGManager] ✓ Generated: {len(mcp_graph.nodes)} nodes, {len(mcp_graph.edges)} edges")
            
            self.current_graph = mcp_graph
            return mcp_graph
            
        except Exception as e:
            print(f"[KGManager] ❌ Error generating graph: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _infer_entity_type(self, entity: str) -> str:
        """Infer entity type from name."""
        entity_lower = entity.lower()
        
        if any(kw in entity_lower for kw in ["attack", "injection", "exploit", "vulnerability", "cve"]):
            return "Threat"
        elif any(kw in entity_lower for kw in ["mcp", "server", "tool", "client"]):
            return "MCPServer"
        elif any(kw in entity_lower for kw in ["llm", "model", "gpt", "claude", "openai", "anthropic"]):
            return "LLMProvider"
        elif any(kw in entity_lower for kw in ["sandbox", "validation", "whitelist", "permission", "control"]):
            return "Control"
        elif any(kw in entity_lower for kw in ["file", "browser", "database", "api", "resource"]):
            return "Asset"
        else:
            return "Entity"
    
    def _enhance_with_ai(
        self,
        graph: MCPKnowledgeGraph,
        threats: List[MCPThreat]
    ) -> MCPKnowledgeGraph:
        """Enhance graph using AI to find additional relationships."""
        if not self._kg_gen:
            return graph
        
        try:
            # Combine threat descriptions
            text_parts = []
            for threat in threats:
                text_parts.append(f"""
Threat: {threat.title}
Category: {threat.category}
Description: {threat.description}
Attack Vectors: {', '.join(threat.attack_vector)}
Impact: {', '.join(threat.impact)}
""")
            
            combined_text = "\n\n".join(text_parts)
            
            # Generate relationships
            kg_gen_graph = self._kg_gen.generate(
                input_data=combined_text,
                context="MCP Security Threat Relationships",
                cluster=True
            )
            
            # Add new relationships to graph
            for relation in kg_gen_graph.relations:
                if len(relation) >= 3:
                    source = relation[0]
                    target = relation[2]
                    rel_type = relation[1].upper().replace(" ", "_")
                    
                    # Find matching nodes
                    source_id = self._find_matching_node(graph, source)
                    target_id = self._find_matching_node(graph, target)
                    
                    if source_id and target_id:
                        graph.add_edge(source_id, target_id, rel_type, {"ai_generated": True})
            
            return graph
            
        except Exception as e:
            print(f"[KGManager] AI enhancement failed: {e}")
            return graph
    
    def _find_matching_node(self, graph: MCPKnowledgeGraph, name: str) -> Optional[str]:
        """Find a node in graph matching the given name."""
        name_lower = name.lower()
        for node_id, node in graph.nodes.items():
            if name_lower in node["label"].lower() or node["label"].lower() in name_lower:
                return node_id
        return None
    
    def upload_to_neo4j(
        self,
        graph: Optional[MCPKnowledgeGraph] = None,
        clear_existing: bool = False
    ) -> bool:
        """
        Upload knowledge graph to Neo4j.
        
        Args:
            graph: Graph to upload (uses current_graph if not specified)
            clear_existing: Whether to clear existing data first
        
        Returns:
            True if successful
        """
        if not self._driver:
            if not self.connect_neo4j():
                return False
        
        graph = graph or self.current_graph
        
        try:
            with self._driver.session(database=self.neo4j_config.database) as session:
                # Clear if requested
                if clear_existing:
                    session.run("MATCH (n) DETACH DELETE n")
                    print("[KGManager] Cleared existing graph data")
                
                # Create nodes
                for node_id, node in graph.nodes.items():
                    node_type = node["type"].replace(":", "_")
                    query = f"""
                        MERGE (n:{node_type} {{id: $id}})
                        SET n.label = $label,
                            n.properties = $properties,
                            n.created_at = $created_at
                    """
                    session.run(
                        query,
                        id=node_id,
                        label=node["label"],
                        properties=json.dumps(node.get("properties", {})),
                        created_at=node.get("created_at", datetime.now().isoformat())
                    )
                
                # Create edges
                for edge in graph.edges:
                    rel_type = edge["relationship"].replace(" ", "_").replace("-", "_")
                    query = f"""
                        MATCH (s {{id: $source}})
                        MATCH (t {{id: $target}})
                        MERGE (s)-[r:{rel_type}]->(t)
                        SET r.properties = $properties
                    """
                    session.run(
                        query,
                        source=edge["source"],
                        target=edge["target"],
                        properties=json.dumps(edge.get("properties", {}))
                    )
                
                print(f"[KGManager] ✓ Uploaded: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
                return True
                
        except Exception as e:
            print(f"[KGManager] ❌ Failed to upload: {e}")
            return False
    
    def query_neo4j(self, cypher_query: str) -> List[Dict[str, Any]]:
        """Execute Cypher query on Neo4j."""
        if not self._driver:
            if not self.connect_neo4j():
                return []
        
        try:
            with self._driver.session(database=self.neo4j_config.database) as session:
                result = session.run(cypher_query)
                return [record.data() for record in result]
        except Exception as e:
            print(f"[KGManager] Query error: {e}")
            return []
    
    def save_graph(
        self,
        filepath: Optional[str] = None,
        graph: Optional[MCPKnowledgeGraph] = None
    ) -> str:
        """Save graph to JSON file."""
        graph = graph or self.current_graph
        
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = str(self.data_dir / f"kg_{timestamp}.json")
        
        if graph.save(filepath):
            print(f"[KGManager] ✓ Saved graph to: {filepath}")
            return filepath
        return ""
    
    def load_graph(self, filepath: str) -> MCPKnowledgeGraph:
        """Load graph from JSON file."""
        self.current_graph = MCPKnowledgeGraph.load(filepath)
        print(f"[KGManager] ✓ Loaded graph: {len(self.current_graph.nodes)} nodes, {len(self.current_graph.edges)} edges")
        return self.current_graph
    
    def generate_html_visualization(
        self,
        graph: Optional[MCPKnowledgeGraph] = None,
        output_path: Optional[str] = None
    ) -> str:
        """Generate HTML visualization of the graph."""
        graph = graph or self.current_graph
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(self.data_dir / f"kg_viz_{timestamp}.html")
        
        vis_data = graph.to_vis_format()
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>MCP Threat Knowledge Graph</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0f0f1a;
            color: #fff;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%);
            padding: 20px;
            border-bottom: 1px solid rgba(233, 69, 96, 0.3);
        }}
        .header h1 {{ font-size: 1.5rem; }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-top: 10px;
        }}
        .stat {{
            background: rgba(255,255,255,0.1);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85rem;
        }}
        #network {{
            width: 100%;
            height: calc(100vh - 100px);
            background: #0f0f1a;
        }}
        .legend {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: rgba(26, 26, 46, 0.9);
            padding: 15px;
            border-radius: 8px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 5px;
            font-size: 0.8rem;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔗 MCP Threat Knowledge Graph</h1>
        <div class="stats">
            <span class="stat">📊 Nodes: {len(vis_data['nodes'])}</span>
            <span class="stat">🔗 Edges: {len(vis_data['edges'])}</span>
            <span class="stat">📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
        </div>
    </div>
    <div id="network"></div>
    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background:#dc3545"></div>Threat</div>
        <div class="legend-item"><div class="legend-color" style="background:#17a2b8"></div>Asset</div>
        <div class="legend-item"><div class="legend-color" style="background:#28a745"></div>Control</div>
        <div class="legend-item"><div class="legend-color" style="background:#ffc107"></div>Evidence</div>
        <div class="legend-item"><div class="legend-color" style="background:#6f42c1"></div>MCP Server</div>
        <div class="legend-item"><div class="legend-color" style="background:#fd7e14"></div>MCP Tool</div>
        <div class="legend-item"><div class="legend-color" style="background:#20c997"></div>LLM Provider</div>
    </div>
    <script>
        var nodes = new vis.DataSet({json.dumps(vis_data['nodes'])});
        var edges = new vis.DataSet({json.dumps(vis_data['edges'])});
        
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            nodes: {{
                font: {{ color: '#fff', size: 12 }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                font: {{ color: '#888', size: 10, align: 'middle' }},
                smooth: {{ type: 'continuous' }}
            }},
            physics: {{
                enabled: true,
                barnesHut: {{
                    gravitationalConstant: -8000,
                    centralGravity: 0.3,
                    springLength: 150
                }}
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 100,
                navigationButtons: true
            }}
        }};
        
        var network = new vis.Network(container, data, options);
        
        network.on("click", function(params) {{
            if (params.nodes.length > 0) {{
                var nodeId = params.nodes[0];
                var node = nodes.get(nodeId);
                console.log("Selected:", node);
            }}
        }});
    </script>
</body>
</html>"""
        
        try:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[KGManager] ✓ Generated visualization: {output_path}")
            return output_path
        except Exception as e:
            print(f"[KGManager] ❌ Error generating visualization: {e}")
            return ""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the current graph."""
        graph = self.current_graph
        
        # Count by type
        type_counts: Dict[str, int] = {}
        for node in graph.nodes.values():
            node_type = node["type"].split(":")[0]
            type_counts[node_type] = type_counts.get(node_type, 0) + 1
        
        # Count relationships
        rel_counts: Dict[str, int] = {}
        for edge in graph.edges:
            rel = edge["relationship"]
            rel_counts[rel] = rel_counts.get(rel, 0) + 1
        
        return {
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "nodes_by_type": type_counts,
            "edges_by_type": rel_counts,
            "metadata": graph.metadata
        }

