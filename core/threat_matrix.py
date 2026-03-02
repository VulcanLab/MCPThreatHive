"""
Threat Matrix Generator for MCP Threat Platform

Generates threat matrices that visualize threats across:
- STRIDE categories (X-axis)
- Assets/Components (Y-axis)
- Risk levels and relationships

The matrix can be used to:
- Assess threats from intelligence data
- Link threats to assets and controls
- Generate threat model database entries
- Visualize threat relationships
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    """Risk level enumeration"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatMatrixCell:
    """A single cell in the threat matrix"""
    threat_id: Optional[str] = None
    threat_name: str = ""
    risk_level: RiskLevel = RiskLevel.NONE
    risk_score: float = 0.0
    is_mitigated: bool = False
    control_ids: List[str] = field(default_factory=list)
    evidence_count: int = 0
    last_updated: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat_name": self.threat_name,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "is_mitigated": self.is_mitigated,
            "control_ids": self.control_ids,
            "evidence_count": self.evidence_count,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None
        }


@dataclass
class ThreatMatrix:
    """
    Complete threat matrix representation.
    
    Structure:
    - Rows: Assets/Components
    - Columns: STRIDE categories
    - Cells: Threat information
    """
    matrix_id: str
    project_id: str
    name: str
    
    # Matrix dimensions
    stride_categories: List[str] = field(default_factory=lambda: [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege"
    ])
    
    assets: List[str] = field(default_factory=list)  # Asset IDs
    
    # Matrix data: {asset_id: {stride_category: ThreatMatrixCell}}
    cells: Dict[str, Dict[str, ThreatMatrixCell]] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert matrix to dictionary for API/JSON"""
        cells_dict = {}
        for asset_id, stride_dict in self.cells.items():
            cells_dict[asset_id] = {
                stride: cell.to_dict() 
                for stride, cell in stride_dict.items()
            }
        
        return {
            "matrix_id": self.matrix_id,
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "stride_categories": self.stride_categories,
            "assets": self.assets,
            "cells": cells_dict,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "stats": self.get_stats()
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get matrix statistics"""
        total_cells = len(self.assets) * len(self.stride_categories)
        threats_found = sum(
            1 for asset_dict in self.cells.values()
            for cell in asset_dict.values()
            if cell.threat_id
        )
        mitigated = sum(
            1 for asset_dict in self.cells.values()
            for cell in asset_dict.values()
            if cell.is_mitigated
        )
        
        risk_distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }
        
        for asset_dict in self.cells.values():
            for cell in asset_dict.values():
                if cell and cell.threat_id and cell.risk_level:
                    risk_distribution[cell.risk_level.value] += 1
        
        return {
            "total_cells": total_cells,
            "threats_found": threats_found,
            "mitigated": mitigated,
            "unmitigated": threats_found - mitigated,
            "coverage": (threats_found / total_cells * 100) if total_cells > 0 else 0,
            "risk_distribution": risk_distribution
        }
    
    def add_threat(
        self,
        asset_id: str,
        stride_category: str,
        threat_id: str,
        threat_name: str,
        risk_score: float,
        control_ids: Optional[List[str]] = None
    ):
        """Add a threat to the matrix"""
        if asset_id not in self.assets:
            self.assets.append(asset_id)
        
        if asset_id not in self.cells:
            self.cells[asset_id] = {}
        
        # Determine risk level from score
        if risk_score >= 9.0:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 5.0:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 3.0:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE
        
        self.cells[asset_id][stride_category] = ThreatMatrixCell(
            threat_id=threat_id,
            threat_name=threat_name,
            risk_level=risk_level,
            risk_score=risk_score,
            is_mitigated=bool(control_ids),
            control_ids=control_ids or [],
            last_updated=datetime.now()
        )
        
        self.updated_at = datetime.now()
    
    def get_cell(self, asset_id: str, stride_category: str) -> Optional[ThreatMatrixCell]:
        """Get a specific cell"""
        return self.cells.get(asset_id, {}).get(stride_category)
    
    def get_asset_threats(self, asset_id: str) -> List[ThreatMatrixCell]:
        """Get all threats for an asset"""
        return list(self.cells.get(asset_id, {}).values())
    
    def get_stride_threats(self, stride_category: str) -> List[Tuple[str, ThreatMatrixCell]]:
        """Get all threats for a STRIDE category"""
        threats = []
        for asset_id, stride_dict in self.cells.items():
            if stride_category in stride_dict:
                threats.append((asset_id, stride_dict[stride_category]))
        return threats


class ThreatMatrixGenerator:
    """
    Generates threat matrices from threats, assets, and controls.
    
    Can be used to:
    - Build matrices from database data
    - Assess intelligence data
    - Generate threat model entries
    """
    
    def __init__(self, db_manager=None):
        """
        Initialize matrix generator.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
    
    def generate_from_project(
        self,
        project_id: str = "default-project",
        matrix_name: str = "Threat Matrix"
    ) -> ThreatMatrix:
        """
        Generate threat matrix from project data.
        
        Args:
            project_id: Project ID
            matrix_name: Name for the matrix
            
        Returns:
            ThreatMatrix instance
        """
        import uuid
        
        matrix = ThreatMatrix(
            matrix_id=str(uuid.uuid4()),
            project_id=project_id,
            name=matrix_name
        )
        
        if not self.db_manager:
            return matrix
        
        # Get all assets
        assets = self.db_manager.get_project_assets(project_id)
        for asset in assets:
            matrix.assets.append(asset.id)
        
        # Get all threats and map to assets/STRIDE
        threats = self.db_manager.get_project_threats(project_id)
        
        # Get threat-control mappings directly from database to avoid detached instance errors
        threat_control_map = self.db_manager.get_threat_control_mappings(project_id)
        
        for threat in threats:
            # Map threat to assets (simplified: use project assets)
            # In real implementation, use threat.affected_assets relationship
            for asset_id in matrix.assets:
                stride_category = threat.stride_category or "Tampering"
                
                # Get controls for this threat from the pre-fetched map
                control_ids = threat_control_map.get(threat.id, [])
                
                matrix.add_threat(
                    asset_id=asset_id,
                    stride_category=stride_category,
                    threat_id=threat.id,
                    threat_name=threat.name,
                    risk_score=threat.risk_score or 5.0,
                    control_ids=control_ids
                )
        
        return matrix
    
    def assess_intelligence_data(
        self,
        intel_items: List[Dict[str, Any]],
        assets: List[Dict[str, Any]],
        matrix_name: str = "Intelligence Assessment Matrix"
    ) -> ThreatMatrix:
        """
        Generate threat matrix from intelligence data.
        
        This allows the matrix to assess and categorize threats from
        intelligence gathering, creating a threat model database source.
        
        Args:
            intel_items: List of intelligence items (from intel pipeline)
            assets: List of assets to assess
            matrix_name: Name for the matrix
            
        Returns:
            ThreatMatrix instance
        """
        import uuid
        
        matrix = ThreatMatrix(
            matrix_id=str(uuid.uuid4()),
            project_id="intel-assessment",
            name=matrix_name
        )
        
        # Extract asset IDs
        for asset in assets:
            asset_id = asset.get("id", asset.get("name", ""))
            if asset_id:
                matrix.assets.append(asset_id)
        
        # Process intelligence items
        for item in intel_items:
            # Extract threat information
            threat_name = item.get("name", item.get("title", "Unknown Threat"))
            stride_category = item.get("stride_category", item.get("category", "Tampering"))
            risk_score = item.get("risk_score", item.get("ai_relevance_score", 5.0) * 2)
            
            # Map to assets (simplified: all assets for now)
            # In real implementation, use AI to determine affected assets
            for asset_id in matrix.assets:
                matrix.add_threat(
                    asset_id=asset_id,
                    stride_category=stride_category,
                    threat_id=item.get("id", ""),
                    threat_name=threat_name,
                    risk_score=float(risk_score),
                    control_ids=item.get("recommended_controls", [])
                )
        
        return matrix
    
    def export_to_threat_model(
        self,
        matrix: ThreatMatrix
    ) -> List[Dict[str, Any]]:
        """
        Export matrix to threat model database format.
        
        Converts matrix cells into threat model entries that can be
        stored in the database and linked to other components.
        
        Args:
            matrix: ThreatMatrix instance
            
        Returns:
            List of threat model entries
        """
        threat_models = []
        
        for asset_id, stride_dict in matrix.cells.items():
            for stride_category, cell in stride_dict.items():
                if cell.threat_id:
                    threat_models.append({
                        "id": cell.threat_id,
                        "name": cell.threat_name,
                        "asset_id": asset_id,
                        "stride_category": stride_category,
                        "risk_score": cell.risk_score,
                        "risk_level": cell.risk_level.value,
                        "is_mitigated": cell.is_mitigated,
                        "control_ids": cell.control_ids,
                        "evidence_count": cell.evidence_count,
                        "source": "threat_matrix",
                        "matrix_id": matrix.matrix_id
                    })
        
        return threat_models
    
    def generate_from_mcp_knowledge(
        self,
        project_id: str = "default-project",
        matrix_name: str = "MCP Threat Matrix",
        knowledge_base = None
    ) -> ThreatMatrix:
        """
        Generate threat matrix from MCP knowledge base.
        
        Maps MCP threats from the knowledge base to matrix cells,
        creating assets from components and mapping threats by STRIDE category.
        
        Args:
            project_id: Project ID
            matrix_name: Name for the matrix
            knowledge_base: MCPKnowledgeBase instance
            
        Returns:
            ThreatMatrix instance
        """
        import uuid
        
        if not knowledge_base:
            from core.mcp_knowledge_base import get_knowledge_base
            knowledge_base = get_knowledge_base()
            if not knowledge_base.threats:
                knowledge_base.import_from_markdown()
        
        matrix = ThreatMatrix(
            matrix_id=str(uuid.uuid4()),
            project_id=project_id,
            name=matrix_name
        )
        
        # Create assets from components
        components = set()
        for threat in knowledge_base.threats.values():
            if threat.component:
                components.add(threat.component)
        
        # Add components as assets
        for component in components:
            component_id = component.lower().replace(' ', '-').replace('/', '-')
            matrix.assets.append(component_id)
            
            # Create asset in database if db_manager available
            if self.db_manager:
                existing_assets = self.db_manager.get_project_assets(project_id)
                if not any(a.id == component_id for a in existing_assets):
                    try:
                        self.db_manager.create_asset(
                            project_id=project_id,
                            asset_id=component_id,
                            name=component,
                            asset_type="MCP Component",
                            description=f"MCP component: {component}"
                        )
                    except Exception:
                        pass  # Asset might already exist
        
        # Map threats to matrix cells
        threat_control_map = {}
        if self.db_manager:
            threat_control_map = self.db_manager.get_threat_control_mappings(project_id)
        
        for threat in knowledge_base.threats.values():
            # Determine asset ID from component
            asset_id = threat.component.lower().replace(' ', '-').replace('/', '-') if threat.component else matrix.assets[0] if matrix.assets else "unknown"
            
            # Use STRIDE category from threat
            stride_category = threat.stride_category or "Tampering"
            
            # Get controls for this threat
            control_ids = []
            if threat.mitigation_controls and self.db_manager:
                # Try to find or create controls
                for control_name in threat.mitigation_controls[:3]:  # Limit to first 3
                    try:
                        # Check if control exists
                        existing_controls = self.db_manager.get_project_controls(project_id)
                        control = next((c for c in existing_controls if control_name.lower() in c.name.lower()), None)
                        if control:
                            control_ids.append(control.id)
                    except Exception:
                        pass
            
            # Add threat to matrix
            matrix.add_threat(
                asset_id=asset_id,
                stride_category=stride_category,
                threat_id=threat.id,
                threat_name=threat.threat_category or threat.id,
                risk_score=threat.risk_score or 5.0,
                control_ids=control_ids
            )
            
            # Also create threat in database if db_manager available
            if self.db_manager:
                existing_threats = self.db_manager.get_project_threats(project_id)
                if not any(t.id == threat.id for t in existing_threats):
                    try:
                        self.db_manager.create_threat(
                            project_id=project_id,
                            threat_id=threat.id,
                            name=threat.threat_category or threat.id,
                            description=threat.description or "",
                            threat_type="MCP Security",
                            stride_category=stride_category,
                            risk_score=threat.risk_score or 5.0
                        )
                    except Exception:
                        pass  # Threat might already exist
        
        return matrix


