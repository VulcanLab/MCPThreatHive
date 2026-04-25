"""
MCP Threat Platform - Database Models

SQLAlchemy models for persistent storage
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy import (
    create_engine, Column, String, Text, Integer, Float, Boolean,
    DateTime, ForeignKey, JSON, Enum as SQLEnum, Table, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship, Session
from sqlalchemy.ext.hybrid import hybrid_property

Base = declarative_base()


# ==================== Association Tables ====================

# Many-to-many: Threats <-> Controls (mitigation relationship)
threat_control_association = Table(
    'threat_control_association',
    Base.metadata,
    Column('threat_id', String(64), ForeignKey('threats.id'), primary_key=True),
    Column('control_id', String(64), ForeignKey('controls.id'), primary_key=True)
)

# Many-to-many: Assets <-> Threats (affected by relationship)
asset_threat_association = Table(
    'asset_threat_association',
    Base.metadata,
    Column('asset_id', String(64), ForeignKey('assets.id'), primary_key=True),
    Column('threat_id', String(64), ForeignKey('threats.id'), primary_key=True)
)

# Many-to-many: Projects <-> Users (collaboration)
project_user_association = Table(
    'project_user_association',
    Base.metadata,
    Column('project_id', String(64), ForeignKey('projects.id'), primary_key=True),
    Column('user_id', String(64), ForeignKey('users.id'), primary_key=True)
)


# ==================== User & Project Models ====================

class User(Base):
    """User model for multi-user support"""
    __tablename__ = 'users'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(128), unique=True, nullable=False)
    email = Column(String(256), unique=True, nullable=True)
    password_hash = Column(String(256), nullable=True)  # For future auth
    display_name = Column(String(256), nullable=True)
    role = Column(String(32), default='user')  # admin, user, viewer
    
    # User preferences (JSON for flexibility)
    preferences = Column(JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    owned_projects = relationship('Project', back_populates='owner', foreign_keys='Project.owner_id')
    projects = relationship('Project', secondary=project_user_association, back_populates='collaborators')
    custom_templates = relationship('CustomTemplate', back_populates='creator')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'display_name': self.display_name,
            'role': self.role,
            'preferences': self.preferences or {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Project(Base):
    """Project/Workspace model - each threat model is a project"""
    __tablename__ = 'projects'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    
    # Owner
    owner_id = Column(String(64), ForeignKey('users.id'), nullable=True)
    owner = relationship('User', back_populates='owned_projects', foreign_keys=[owner_id])
    
    # Collaborators
    collaborators = relationship('User', secondary=project_user_association, back_populates='projects')
    
    # Project settings (JSON for flexibility)
    settings = Column(JSON, default=dict)
    
    # Status
    status = Column(String(32), default='active')  # active, archived, deleted
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships to threat model elements
    assets = relationship('Asset', back_populates='project', cascade='all, delete-orphan')
    threats = relationship('Threat', back_populates='project', cascade='all, delete-orphan')
    controls = relationship('Control', back_populates='project', cascade='all, delete-orphan')
    evidence = relationship('AttackEvidence', back_populates='project', cascade='all, delete-orphan')
    data_flows = relationship('DataFlow', back_populates='project', cascade='all, delete-orphan')
    canvas_states = relationship('CanvasState', back_populates='project', cascade='all, delete-orphan')
    risk_plannings = relationship('RiskPlanning', back_populates='project', cascade='all, delete-orphan')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'settings': self.settings or {},
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'asset_count': len(self.assets) if self.assets else 0,
            'threat_count': len(self.threats) if self.threats else 0,
            'control_count': len(self.controls) if self.controls else 0,
        }


# ==================== Threat Model Elements ====================

class Asset(Base):
    """Asset model - MCP servers, tools, data stores, etc."""
    __tablename__ = 'assets'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)
    
    # Basic info
    name = Column(String(256), nullable=False)
    asset_type = Column(String(64), nullable=False)  # mcp_server, tool, llm_provider, etc.
    description = Column(Text, nullable=True)
    
    # Asset-specific data (flexible JSON)
    properties = Column(JSON, default=dict)
    
    # MCP-specific fields
    mcp_config = Column(JSON, nullable=True)  # MCP configuration if applicable
    tools = Column(JSON, nullable=True)  # List of tools if MCP server
    permissions = Column(JSON, nullable=True)  # Permission settings
    
    # Risk assessment
    risk_level = Column(String(32), default='medium')
    risk_score = Column(Float, default=5.0)
    
    # Canvas position
    canvas_x = Column(Float, default=0)
    canvas_y = Column(Float, default=0)
    
    # Status & metadata
    status = Column(String(32), default='active')
    tags = Column(JSON, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship('Project', back_populates='assets')
    threats = relationship('Threat', secondary=asset_threat_association, back_populates='affected_assets')
    source_flows = relationship('DataFlow', back_populates='source_asset', foreign_keys='DataFlow.source_id')
    target_flows = relationship('DataFlow', back_populates='target_asset', foreign_keys='DataFlow.target_id')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'type': self.asset_type,
            'description': self.description,
            'properties': self.properties or {},
            'mcp_config': self.mcp_config,
            'tools': self.tools,
            'permissions': self.permissions,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'canvas_x': self.canvas_x,
            'canvas_y': self.canvas_y,
            'status': self.status,
            'tags': self.tags or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'cardType': 'asset',  # For frontend compatibility
        }


class Threat(Base):
    """Threat model - security threats identified"""
    __tablename__ = 'threats'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)
    
    # Basic info
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    
    # STRIDE classification
    stride_category = Column(String(32), nullable=False)  # spoofing, tampering, etc.
    
    # Threat details
    threat_type = Column(String(64), default='template')  # template, ai_generated, custom
    attack_vector = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    likelihood = Column(String(32), default='medium')
    
    # Risk assessment
    risk_level = Column(String(32), default='high')
    risk_score = Column(Float, default=7.0)
    cvss_score = Column(Float, nullable=True)
    
    # Source info (for AI-generated threats)
    source = Column(String(256), nullable=True)  # GitHub, CVE, Paper, etc.
    source_url = Column(String(1024), nullable=True)
    source_date = Column(DateTime, nullable=True)
    
    # AI analysis
    ai_summary = Column(Text, nullable=True)
    ai_relevance_score = Column(Float, nullable=True)
    
    # Canvas position
    canvas_x = Column(Float, default=0)
    canvas_y = Column(Float, default=0)
    
    # Status & metadata
    status = Column(String(32), default='active')  # active, mitigated, accepted, archived
    is_mitigated = Column(Boolean, default=False)
    tags = Column(JSON, default=list)
    
    # MAESTRO layer classification
    maestro_layer = Column(Integer, nullable=True)  # Primary MAESTRO layer (1-7)
    is_cross_layer = Column(Boolean, default=False)  # Whether threat spans multiple layers
    affected_layers = Column(JSON, default=list)  # List of affected MAESTRO layers
    
    # MCP Workflow Phase Classification (MSB Taxonomy)
    mcp_workflow_phase = Column(String(64), nullable=True)  # Task Planning, Tool Invocation, Response Handling, Cross-Phase
    msb_attack_type = Column(String(128), nullable=True)  # PI, PM, NC, OP, UI, FE, RI, Mixed
    
    # MCP-UPD Classification
    mcp_upd_phase = Column(String(64), nullable=True)  # Parasitic Ingestion, Privacy Collection, Privacy Disclosure
    mcp_upd_tools = Column(JSON, default=list)  # List of tool types: EIT, PAT, NAT
    
    # MPMA Classification
    mpma_attack_type = Column(String(128), nullable=True)  # DPMA, GAPMA
    gapma_strategy = Column(String(64), nullable=True)  # Authoritative, Emotional, Exaggerated, Subliminal
    
    # NRP Metrics (Net Resilient Performance)
    asr_score = Column(Float, nullable=True)  # Attack Success Rate (0.0-1.0)
    pua_score = Column(Float, nullable=True)  # Performance Under Attack (0.0-1.0)
    nrp_score = Column(Float, nullable=True)  # Net Resilient Performance = PUA * (1 - ASR)
    
    # MCPSecBench Classification (4×17 Threat Matrix)
    mcp_surface = Column(String(64), nullable=True)  # Server APIs & Functionality, Tool Metadata & Toolchain, Runtime / Invocation Flow, Client / Integration Surface
    mcpsecbench_attack_type = Column(String(128), nullable=True)  # 17 standard attack types
    mcpsecbench_severity = Column(Integer, nullable=True)  # 0-10 severity from matrix
    graph_pattern_data = Column(JSON, default=dict)  # Graph pattern information
    test_template_data = Column(JSON, default=dict)  # Test template information
    
    # MCP Threat ID Classification (MCP-01 to MCP-38)
    mcp_threat_ids = Column(JSON, default=list)  # List of MCP threat IDs (e.g., ["MCP-19", "MCP-20"])
    
    # Full schema (flexible JSON for EnhancedMCPThreat)
    schema_data = Column(JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship('Project', back_populates='threats')
    controls = relationship('Control', secondary=threat_control_association, back_populates='mitigated_threats')
    affected_assets = relationship('Asset', secondary=asset_threat_association, back_populates='threats')
    evidence = relationship('AttackEvidence', back_populates='threat')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'category': self.stride_category,
            'stride_category': self.stride_category,
            'threat_type': self.threat_type,
            'type': self.threat_type,
            'attack_vector': self.attack_vector,
            'impact': self.impact,
            'likelihood': self.likelihood,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'cvss_score': self.cvss_score,
            'source': self.source,
            'source_url': self.source_url,
            'ai_summary': self.ai_summary,
            'canvas_x': self.canvas_x,
            'canvas_y': self.canvas_y,
            'status': self.status,
            'is_mitigated': self.is_mitigated,
            'tags': self.tags or [],
            'schema_data': self.schema_data or {},
            'maestro_layer': self.maestro_layer,
            'is_cross_layer': self.is_cross_layer,
            'affected_layers': self.affected_layers or [],
            # MCP Workflow Phase Classification (use getattr for backward compatibility)
            'mcp_workflow_phase': getattr(self, 'mcp_workflow_phase', None),
            'msb_attack_type': getattr(self, 'msb_attack_type', None),
            # MCP-UPD Classification
            'mcp_upd_phase': getattr(self, 'mcp_upd_phase', None),
            'mcp_upd_tools': getattr(self, 'mcp_upd_tools', None) or [],
            # MPMA Classification
            'mpma_attack_type': getattr(self, 'mpma_attack_type', None),
            'gapma_strategy': getattr(self, 'gapma_strategy', None),
            # NRP Metrics
            'asr_score': getattr(self, 'asr_score', None),
            'pua_score': getattr(self, 'pua_score', None),
            'nrp_score': getattr(self, 'nrp_score', None),
            # MCPSecBench Classification
            'mcp_surface': getattr(self, 'mcp_surface', None),
            'mcpsecbench_attack_type': getattr(self, 'mcpsecbench_attack_type', None),
            'mcpsecbench_severity': getattr(self, 'mcpsecbench_severity', None),
            'graph_pattern_data': getattr(self, 'graph_pattern_data', None) or {},
            'test_template_data': getattr(self, 'test_template_data', None) or {},
            # MCP Threat ID Classification (MCP-01 to MCP-38)
            'mcp_threat_ids': getattr(self, 'mcp_threat_ids', None) or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'cardType': 'threat',  # For frontend compatibility
            'control_count': self._safe_count('controls'),
        }
    
    def _safe_count(self, attr_name: str) -> int:
        """Safely count related items without triggering lazy load errors"""
        try:
            attr = getattr(self, attr_name, None)
            return len(attr) if attr else 0
        except:
            return 0


class Control(Base):
    """Security control model - mitigations and defenses"""
    __tablename__ = 'controls'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)
    
    # Basic info
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    control_type = Column(String(64), nullable=False)  # tool_sandbox, permission, rate_limit, etc.
    
    # Control configuration (flexible JSON)
    configuration = Column(JSON, default=dict)
    
    # Effectiveness
    effectiveness = Column(String(32), default='medium')  # low, medium, high
    effectiveness_score = Column(Float, default=5.0)
    
    # Implementation status
    implementation_status = Column(String(32), default='planned')  # planned, in_progress, implemented, verified
    implementation_notes = Column(Text, nullable=True)
    
    # Canvas position
    canvas_x = Column(Float, default=0)
    canvas_y = Column(Float, default=0)
    
    # Status & metadata
    status = Column(String(32), default='active')
    tags = Column(JSON, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship('Project', back_populates='controls')
    mitigated_threats = relationship('Threat', secondary=threat_control_association, back_populates='controls')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'type': self.control_type,
            'control_type': self.control_type,
            'configuration': self.configuration or {},
            'effectiveness': self.effectiveness,
            'effectiveness_score': self.effectiveness_score,
            'implementation_status': self.implementation_status,
            'implementation_notes': self.implementation_notes,
            'canvas_x': self.canvas_x,
            'canvas_y': self.canvas_y,
            'status': self.status,
            'tags': self.tags or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'cardType': 'control',  # For frontend compatibility
            'threat_count': self._safe_count('mitigated_threats'),
        }
    
    def _safe_count(self, attr_name: str) -> int:
        """Safely count related items without triggering lazy load errors"""
        try:
            attr = getattr(self, attr_name, None)
            return len(attr) if attr else 0
        except:
            return 0


class AttackEvidence(Base):
    """Attack evidence model - results from attack simulations"""
    __tablename__ = 'attack_evidence'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)
    threat_id = Column(String(64), ForeignKey('threats.id'), nullable=True)
    
    # Basic info
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    evidence_type = Column(String(64), nullable=False)  # fuzz_test, prompt_injection, path_traversal, etc.
    
    # Attack details
    attack_payload = Column(Text, nullable=True)
    attack_target = Column(String(256), nullable=True)
    attack_method = Column(String(128), nullable=True)
    
    # Results
    success = Column(Boolean, default=False)
    result_data = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    
    # Severity assessment
    severity = Column(String(32), default='medium')
    
    # Canvas position
    canvas_x = Column(Float, default=0)
    canvas_y = Column(Float, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    executed_at = Column(DateTime, nullable=True)
    
    # Relationships
    project = relationship('Project', back_populates='evidence')
    threat = relationship('Threat', back_populates='evidence')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'threat_id': self.threat_id,
            'name': self.name,
            'description': self.description,
            'type': self.evidence_type,
            'evidence_type': self.evidence_type,
            'attack_payload': self.attack_payload,
            'attack_target': self.attack_target,
            'attack_method': self.attack_method,
            'success': self.success,
            'result_data': self.result_data or {},
            'error_message': self.error_message,
            'severity': self.severity,
            'canvas_x': self.canvas_x,
            'canvas_y': self.canvas_y,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'cardType': 'evidence',  # For frontend compatibility
        }


# ==================== Knowledge Base & Rules ====================

class ThreatKnowledge(Base):
    """
    MCP Threat Knowledge Base entry
    Stores structured threat intel for search and rule generation.
    """
    __tablename__ = 'threat_knowledge'

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)

    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    surface = Column(String(128), nullable=True)  # e.g., Server, Client, Tool, Protocol
    attack_type = Column(String(128), nullable=True)
    impact = Column(Text, nullable=True)
    severity = Column(String(32), default='medium')

    cve = Column(String(64), nullable=True)
    cwe = Column(String(64), nullable=True)

    detections = Column(JSON, default=list)      # detection methods / rules hints
    mitigations = Column(JSON, default=list)     # recommended controls
    ioc = Column(JSON, default=list)             # indicators of compromise
    references = Column(JSON, default=list)      # external links / refs
    tags = Column(JSON, default=list)

    status = Column(String(32), default='active')
    version = Column(String(32), default='1.0.0')
    source = Column(String(256), nullable=True)
    source_url = Column(String(1024), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'title': self.title,
            'description': self.description,
            'surface': self.surface,
            'attack_type': self.attack_type,
            'impact': self.impact,
            'severity': self.severity,
            'cve': self.cve,
            'cwe': self.cwe,
            'detections': self.detections or [],
            'mitigations': self.mitigations or [],
            'ioc': self.ioc or [],
            'references': self.references or [],
            'tags': self.tags or [],
            'status': self.status,
            'version': self.version,
            'source': self.source,
            'source_url': self.source_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class DetectionRule(Base):
    """
    Detection rules generated from threat knowledge.
    Stored as simple JSON for flexibility.
    """
    __tablename__ = 'detection_rules'

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)

    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    rule_type = Column(String(32), default='static')  # static, dynamic, behavioral
    target_component = Column(String(128), nullable=True)  # server, client, tool, protocol
    severity = Column(String(32), default='medium')
    status = Column(String(32), default='draft')  # draft, active, disabled
    source_threat_id = Column(String(64), nullable=True)  # link to ThreatKnowledge id

    rule_json = Column(JSON, default=dict)  # simple JSON format per user request
    tags = Column(JSON, default=list)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'rule_type': self.rule_type,
            'target_component': self.target_component,
            'severity': self.severity,
            'status': self.status,
            'source_threat_id': self.source_threat_id,
            'rule_json': self.rule_json or {},
            'tags': self.tags or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class BaselineResult(Base):
    """
    Baseline compliance check results for MCP configurations.
    """
    __tablename__ = 'baseline_results'

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)

    target = Column(String(512), nullable=True)  # path or identifier
    target_type = Column(String(64), nullable=True)  # server_config, tool_config, etc.
    baseline_version = Column(String(32), default='1.0.0')

    passed_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    score = Column(Float, default=0.0)
    status = Column(String(32), default='completed')  # completed, failed

    findings = Column(JSON, default=list)  # list of {rule_id, title, passed, details}
    meta_data = Column(JSON, default=dict)  # renamed from 'metadata' to avoid SQLAlchemy reserved word

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'target': self.target,
            'target_type': self.target_type,
            'baseline_version': self.baseline_version,
            'passed_count': self.passed_count,
            'failed_count': self.failed_count,
            'score': self.score,
            'status': self.status,
            'findings': self.findings or [],
            'metadata': self.meta_data or {},  # Keep 'metadata' in API response for compatibility
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class DataFlow(Base):
    """Data flow model - connections between assets"""
    __tablename__ = 'data_flows'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)
    
    # Source and target
    source_id = Column(String(64), ForeignKey('assets.id'), nullable=True)
    target_id = Column(String(64), ForeignKey('assets.id'), nullable=True)
    
    # Or generic node references (for non-asset connections)
    source_node_id = Column(String(64), nullable=True)
    target_node_id = Column(String(64), nullable=True)
    source_connector = Column(String(32), default='right')
    target_connector = Column(String(32), default='left')
    
    # Flow details
    name = Column(String(256), nullable=True)
    description = Column(Text, nullable=True)
    flow_type = Column(String(64), default='data')  # data, control, trust
    
    # Data classification
    data_classification = Column(String(64), nullable=True)  # public, internal, confidential, secret
    
    # Properties
    properties = Column(JSON, default=dict)
    
    # Status
    status = Column(String(32), default='active')
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship('Project', back_populates='data_flows')
    source_asset = relationship('Asset', back_populates='source_flows', foreign_keys=[source_id])
    target_asset = relationship('Asset', back_populates='target_flows', foreign_keys=[target_id])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'source_id': self.source_id or self.source_node_id,
            'target_id': self.target_id or self.target_node_id,
            'source_node_id': self.source_node_id,
            'target_node_id': self.target_node_id,
            'source_connector': self.source_connector,
            'target_connector': self.target_connector,
            'name': self.name,
            'description': self.description,
            'flow_type': self.flow_type,
            'data_classification': self.data_classification,
            'properties': self.properties or {},
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class CanvasState(Base):
    """Canvas state model - stores the visual state of the threat model canvas"""
    __tablename__ = 'canvas_states'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)
    
    # State name (for versioning)
    name = Column(String(256), default='default')
    description = Column(Text, nullable=True)
    
    # Canvas state data (full JSON snapshot)
    nodes = Column(JSON, default=list)  # All node positions and data
    connections = Column(JSON, default=list)  # All connections
    viewport = Column(JSON, default=dict)  # Zoom, pan, etc.
    
    # Settings
    settings = Column(JSON, default=dict)
    
    # Version info
    version = Column(Integer, default=1)
    is_current = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship('Project', back_populates='canvas_states')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'nodes': self.nodes or [],
            'connections': self.connections or [],
            'viewport': self.viewport or {},
            'settings': self.settings or {},
            'version': self.version,
            'is_current': self.is_current,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


# ==================== User Customization ====================

class CustomTemplate(Base):
    """Custom template model - user-defined threat/control templates"""
    __tablename__ = 'custom_templates'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    creator_id = Column(String(64), ForeignKey('users.id'), nullable=True)
    
    # Template info
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    template_type = Column(String(32), nullable=False)  # threat, control, asset
    
    # Template data (flexible JSON)
    template_data = Column(JSON, default=dict)
    
    # Visibility
    is_public = Column(Boolean, default=False)
    is_system = Column(Boolean, default=False)  # Built-in templates
    
    # Usage stats
    usage_count = Column(Integer, default=0)
    
    # Status
    status = Column(String(32), default='active')
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = relationship('User', back_populates='custom_templates')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'creator_id': self.creator_id,
            'name': self.name,
            'description': self.description,
            'template_type': self.template_type,
            'template_data': self.template_data or {},
            'is_public': self.is_public,
            'is_system': self.is_system,
            'usage_count': self.usage_count,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


# ==================== Intelligence Sources ====================

class IntelSource(Base):
    """Intelligence source model - configured intel gathering sources"""
    __tablename__ = 'intel_sources'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Source info
    name = Column(String(256), nullable=False)
    source_type = Column(String(64), nullable=False)  # github, cve, twitter, rss, etc.
    url = Column(String(1024), nullable=True)
    
    # Configuration
    config = Column(JSON, default=dict)  # API keys, filters, etc.
    
    # Scheduling
    enabled = Column(Boolean, default=True)
    schedule = Column(String(64), default='daily')  # hourly, daily, weekly
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    
    # Stats
    total_items = Column(Integer, default=0)
    relevant_items = Column(Integer, default=0)
    
    # Status
    status = Column(String(32), default='active')
    last_error = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    items = relationship('IntelItem', back_populates='source', cascade='all, delete-orphan')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'source_type': self.source_type,
            'url': self.url,
            'config': self.config or {},
            'enabled': self.enabled,
            'schedule': self.schedule,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'total_items': self.total_items,
            'relevant_items': self.relevant_items,
            'status': self.status,
            'last_error': self.last_error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class RiskPlanning(Base):
    """Risk Planning model - stores generated risk planning and detection methods"""
    __tablename__ = 'risk_planning'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(64), ForeignKey('projects.id'), nullable=True)
    
    # Planning metadata
    name = Column(String(256), nullable=False, default='Risk Planning')
    description = Column(Text, nullable=True)
    
    # Full planning data (JSON)
    planning_data = Column(JSON, default=dict)  # Stores the full risk_planning array
    summary = Column(JSON, default=dict)  # Stores the summary statistics
    
    # Generation metadata
    threats_analyzed = Column(Integer, default=0)
    intel_items_analyzed = Column(Integer, default=0)
    generation_method = Column(String(64), default='ai')  # ai, manual, imported
    
    # Status
    status = Column(String(32), default='active')  # active, archived, draft
    version = Column(Integer, default=1)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = relationship('Project', back_populates='risk_plannings')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'project_id': self.project_id,
            'name': self.name,
            'description': self.description,
            'planning_data': self.planning_data or [],
            'summary': self.summary or {},
            'threats_analyzed': self.threats_analyzed,
            'intel_items_analyzed': self.intel_items_analyzed,
            'generation_method': self.generation_method,
            'status': self.status,
            'version': self.version,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class IntelItem(Base):
    """Intelligence item model - individual intel items collected"""
    __tablename__ = 'intel_items'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_id = Column(String(64), ForeignKey('intel_sources.id'), nullable=True)
    
    # Item info
    title = Column(String(512), nullable=False)
    content = Column(Text, nullable=True)
    url = Column(String(1024), nullable=True)
    
    # Source metadata
    source_type = Column(String(64), nullable=True)
    source_date = Column(DateTime, nullable=True)
    author = Column(String(256), nullable=True)
    
    # AI analysis
    ai_summary = Column(Text, nullable=True)
    ai_relevance_score = Column(Float, nullable=True)
    ai_threat_type = Column(String(64), nullable=True)
    ai_stride_category = Column(String(32), nullable=True)
    
    # Classification
    is_relevant = Column(Boolean, default=False)
    is_processed = Column(Boolean, default=False)
    is_converted = Column(Boolean, default=False)  # Converted to threat
    converted_threat_id = Column(String(64), nullable=True)
    
    # Raw data
    raw_data = Column(JSON, default=dict)
    
    # Status
    status = Column(String(32), default='new')  # new, processing, processed, archived
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)
    
    # Relationships
    source = relationship('IntelSource', back_populates='items')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source_id': self.source_id,
            'title': self.title,
            'content': self.content,
            'url': self.url,
            'source_type': self.source_type,
            'source_date': self.source_date.isoformat() if self.source_date else None,
            'author': self.author,
            'ai_summary': self.ai_summary,
            'ai_relevance_score': self.ai_relevance_score,
            'ai_threat_type': self.ai_threat_type,
            'ai_stride_category': self.ai_stride_category,
            'is_relevant': self.is_relevant,
            'is_processed': self.is_processed,
            'is_converted': self.is_converted,
            'converted_threat_id': self.converted_threat_id,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
        }


# ==================== Configuration Models ====================

class LLMConfig(Base):
    """LLM configuration model - stores LLM provider settings"""
    __tablename__ = 'llm_configs'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Config name
    name = Column(String(256), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    
    # Provider settings
    provider = Column(String(64), nullable=False)  # litellm, openai, anthropic, local
    api_base = Column(String(512), nullable=True)
    api_key = Column(String(512), nullable=True)  # Encrypted in production
    model_name = Column(String(128), nullable=True)
    
    # Additional config
    config = Column(JSON, default=dict)
    
    # Usage assignment
    is_default = Column(Boolean, default=False)
    usage_type = Column(String(64), default='general')  # general, analysis, summarization, attack
    
    # Status
    status = Column(String(32), default='active')
    last_tested = Column(DateTime, nullable=True)
    test_result = Column(String(32), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'provider': self.provider,
            'api_base': self.api_base,
            'model_name': self.model_name,
            'config': self.config or {},
            'is_default': self.is_default,
            'usage_type': self.usage_type,
            'status': self.status,
            'last_tested': self.last_tested.isoformat() if self.last_tested else None,
            'test_result': self.test_result,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class SystemConfig(Base):
    """System configuration model - global platform settings"""
    __tablename__ = 'system_configs'
    
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Config key-value
    key = Column(String(256), nullable=False, unique=True)
    value = Column(JSON, nullable=True)
    
    # Metadata
    description = Column(Text, nullable=True)
    category = Column(String(64), default='general')  # general, security, ui, intel, etc.
    
    # Flags
    is_secret = Column(Boolean, default=False)  # Should be encrypted
    is_user_editable = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value if not self.is_secret else '***',
            'description': self.description,
            'category': self.category,
            'is_secret': self.is_secret,
            'is_user_editable': self.is_user_editable,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

