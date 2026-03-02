"""
Intel Connector - Intelligence Integration Module

Connects to mcp_intel_gatherer and converts intelligence to threat cards
"""

from __future__ import annotations

import json
import sys
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "mcp_intel_gatherer"))

from schemas.mcp_threat_schema import MCPThreat, Evidence
from core.threat_analyzer import MCPThreatAnalyzer, IntelToThreatConverter


class IntelConnector:
    """
    Intelligence Connector
    
    Connects to mcp_intel_gatherer intelligence gathering system, providing:
    - Load intelligence files
    - Execute intelligence gathering
    - Convert intelligence to threat cards
    """
    
    def __init__(self, intel_data_dir: Optional[str] = None):
        """
        Initialize intelligence connector
        
        Args:
            intel_data_dir: Intelligence data directory (default: mcp_intel_gatherer/data/intelligence_results)
        """
        self.intel_data_dir = Path(intel_data_dir) if intel_data_dir else \
            Path(__file__).parent.parent.parent / "mcp_intel_gatherer" / "data" / "intelligence_results"
        
        self.converter = IntelToThreatConverter()
        self.analyzer = MCPThreatAnalyzer()
    
    def load_intel_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Load intelligence file
        
        Args:
            filepath: Path to intelligence JSON file
            
        Returns:
            List of intelligence items
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Support different formats
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                if "intelligence_items" in data:
                    return data["intelligence_items"]
                elif "items" in data:
                    return data["items"]
            
            return []
            
        except Exception as e:
            print(f"[IntelConnector] Error loading file: {e}")
            return []
    
    def load_latest_intel(self) -> List[Dict[str, Any]]:
        """
        Load latest intelligence file
        
        Returns:
            Latest intelligence items list
        """
        if not self.intel_data_dir.exists():
            print(f"[IntelConnector] Intel data directory not found: {self.intel_data_dir}")
            return []
        
        # Find latest JSON file
        json_files = list(self.intel_data_dir.glob("*.json"))
        if not json_files:
            print("[IntelConnector] No intel files found")
            return []
        
        # Sort by modification time
        latest_file = max(json_files, key=lambda f: f.stat().st_mtime)
        print(f"[IntelConnector] Loading latest intel: {latest_file.name}")
        
        return self.load_intel_file(str(latest_file))
    
    def run_intel_gathering(
        self,
        topic: str = "MCP Security",
        max_items: int = 50,
        mode: str = "standard"
    ) -> List[Dict[str, Any]]:
        """
        Execute intelligence gathering
        
        Args:
            topic: Gathering topic
            max_items: Maximum number of items
            mode: Gathering mode (standard/attack/defense/tools)
            
        Returns:
            List of gathered intelligence items
        """
        try:
            # Try to import mcp_intel_gatherer
            from intel_gatherer import MCPWebSearchPipeline
            
            print(f"[IntelConnector] Starting intel gathering: {topic}")
            
            pipeline = MCPWebSearchPipeline(
                output_dir=str(self.intel_data_dir)
            )
            
            items = pipeline.gather_intelligence(
                topic=topic,
                max_items=max_items,
                relevance_threshold=60.0
            )
            
            # Convert to list of dictionaries
            return [item.to_dict() for item in items]
            
        except ImportError as e:
            print(f"[IntelConnector] mcp_intel_gatherer not available: {e}")
            print("[IntelConnector] Please ensure mcp_intel_gatherer is installed")
            return []
        except Exception as e:
            print(f"[IntelConnector] Error during intel gathering: {e}")
            return []
    
    def convert_to_threats(
        self,
        intel_items: List[Dict[str, Any]],
        relevance_threshold: float = 60.0
    ) -> List[MCPThreat]:
        """
        Convert intelligence items to threat cards
        
        Args:
            intel_items: List of intelligence items
            relevance_threshold: Minimum relevance score
            
        Returns:
            List of MCPThreat objects
        """
        return self.converter.batch_convert(intel_items, relevance_threshold)
    
    def ingest_and_convert(
        self,
        topic: str = "MCP Security",
        max_items: int = 50,
        auto_gather: bool = True
    ) -> List[MCPThreat]:
        """
        Complete intelligence ingestion and conversion pipeline
        
        Args:
            topic: Gathering topic
            max_items: Maximum number of items
            auto_gather: Whether to automatically execute intelligence gathering
            
        Returns:
            List of MCPThreat objects
        """
        intel_items = []
        
        # Prioritize loading existing intelligence
        intel_items = self.load_latest_intel()
        
        # If no existing intelligence, or auto-gather is enabled
        if not intel_items and auto_gather:
            print("[IntelConnector] No existing intel, starting new gathering...")
            intel_items = self.run_intel_gathering(topic, max_items)
        
        if not intel_items:
            print("[IntelConnector] No intel items to convert")
            return []
        
        print(f"[IntelConnector] Converting {len(intel_items)} intel items to threats...")
        
        threats = self.convert_to_threats(intel_items)
        
        print(f"[IntelConnector] ✓ Generated {len(threats)} threat cards")
        
        return threats
    
    def get_intel_statistics(self) -> Dict[str, Any]:
        """
        Get intelligence statistics
        
        Returns:
            Statistics information
        """
        stats = {
            "total_files": 0,
            "total_items": 0,
            "latest_file": None,
            "latest_timestamp": None,
            "files": []
        }
        
        if not self.intel_data_dir.exists():
            return stats
        
        json_files = list(self.intel_data_dir.glob("*.json"))
        stats["total_files"] = len(json_files)
        
        for f in json_files:
            items = self.load_intel_file(str(f))
            stats["files"].append({
                "name": f.name,
                "items": len(items),
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            })
            stats["total_items"] += len(items)
        
        if json_files:
            latest = max(json_files, key=lambda f: f.stat().st_mtime)
            stats["latest_file"] = latest.name
            stats["latest_timestamp"] = datetime.fromtimestamp(latest.stat().st_mtime).isoformat()
        
        return stats


class IntelIngestionPipeline:
    """
    Intelligence Ingestion Pipeline
    
    Automated intelligence gathering → cleaning → analysis → conversion → storage
    """
    
    def __init__(
        self,
        output_dir: Optional[str] = None,
        intel_connector: Optional[IntelConnector] = None
    ):
        self.output_dir = Path(output_dir) if output_dir else \
            Path(__file__).parent.parent / "data" / "threats"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.intel_connector = intel_connector or IntelConnector()
        self.analyzer = MCPThreatAnalyzer()
    
    def run_pipeline(
        self,
        topics: List[str] = None,
        max_items_per_topic: int = 30
    ) -> List[MCPThreat]:
        """
        Execute complete ingestion pipeline
        
        Args:
            topics: List of gathering topics
            max_items_per_topic: Maximum items per topic
            
        Returns:
            List of all converted MCPThreat objects
        """
        if topics is None:
            topics = [
                "MCP protocol security vulnerabilities",
                "Large Language Model tool injection attacks",
                "MCP server unauthorized access",
                "Model Context Protocol authentication bypass",
                "MCP transport layer security analysis"
            ]
        
        all_threats = []
        
        for topic in topics:
            print(f"\n[Pipeline] Processing topic: {topic}")
            
            # Gather intelligence
            intel_items = self.intel_connector.run_intel_gathering(
                topic=topic,
                max_items=max_items_per_topic
            )
            
            # Convert to threats
            threats = self.intel_connector.convert_to_threats(intel_items)
            
            all_threats.extend(threats)
            print(f"[Pipeline] ✓ {len(threats)} threats from '{topic}'")
        
        # Deduplicate
        seen_titles = set()
        unique_threats = []
        for threat in all_threats:
            if threat.title not in seen_titles:
                seen_titles.add(threat.title)
                unique_threats.append(threat)
        
        # Save
        self._save_threats(unique_threats)
        
        print(f"\n[Pipeline] ✓ Total unique threats: {len(unique_threats)}")
        
        return unique_threats
    
    def _save_threats(self, threats: List[MCPThreat]):
        """Save threats to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threats_{timestamp}.json"
        filepath = self.output_dir / filename
        
        data = {
            "generated_at": datetime.now().isoformat(),
            "total_threats": len(threats),
            "threats": [t.to_dict() for t in threats]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"[Pipeline] Saved to: {filepath}")


