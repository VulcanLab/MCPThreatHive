"""
MCP Threat Platform - Database Manager

Handles all database operations with SQLAlchemy
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Type, TypeVar

from sqlalchemy import create_engine, and_, or_, desc
from sqlalchemy.orm import sessionmaker, Session, scoped_session

from .models import (
    Base, User, Project, Asset, Threat, Control,
    AttackEvidence, DataFlow, CanvasState, CustomTemplate,
    IntelSource, IntelItem, LLMConfig, SystemConfig,
    ThreatKnowledge, DetectionRule, BaselineResult,
    threat_control_association
)

T = TypeVar('T', bound=Base)


class DatabaseManager:
    """
    Database manager for MCP Threat Platform
    
    Supports SQLite (development) and PostgreSQL (production)
    """
    
    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database manager
        
        Args:
            database_url: Database connection URL. If None, uses SQLite in data folder.
        """
        if database_url is None:
            # Default to SQLite in data folder
            data_dir = Path(__file__).parent.parent / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            database_url = f"sqlite:///{data_dir / 'mcp_threat_platform.db'}"
        
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            echo=False,  # Set to True for SQL debugging
            pool_pre_ping=True,
            # SQLite specific settings
            connect_args={"check_same_thread": False} if "sqlite" in database_url else {}
        )
        
        # Create session factory
        session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.Session = scoped_session(session_factory)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables and default data"""
        # Create all tables
        Base.metadata.create_all(self.engine)
        
        # Initialize default data
        self._init_defaults()
    
    def _init_defaults(self):
        """Initialize default system configuration"""
        session = self.get_session()
        try:
            # Check if defaults already exist
            existing = session.query(SystemConfig).filter_by(key='app.initialized').first()
            if existing:
                return
            
            # Create default system configs
            defaults = [
                SystemConfig(key='app.initialized', value=True, category='system', is_user_editable=False),
                SystemConfig(key='app.version', value='1.0.0', category='system', is_user_editable=False),
                SystemConfig(key='app.name', value='MCP Threat Platform', category='general'),
                SystemConfig(key='canvas.default_zoom', value=1.0, category='ui'),
                SystemConfig(key='canvas.snap_to_grid', value=True, category='ui'),
                SystemConfig(key='canvas.grid_size', value=20, category='ui'),
                SystemConfig(key='intel.auto_gather', value=False, category='intel'),
                SystemConfig(key='intel.gather_interval_hours', value=24, category='intel'),
                SystemConfig(key='security.require_auth', value=False, category='security'),
                SystemConfig(key='security.session_timeout_minutes', value=60, category='security'),
            ]
            
            for config in defaults:
                session.add(config)
            
            # Create default user if auth not required
            default_user = User(
                id='default-user',
                username='default',
                display_name='Default User',
                role='admin'
            )
            session.add(default_user)
            
            # Create default project
            default_project = Project(
                id='default-project',
                name='Default Project',
                description='Default threat modeling project',
                owner_id='default-user'
            )
            session.add(default_project)
            
            session.commit()
            print("✅ Database initialized with defaults")
            
        except Exception as e:
            session.rollback()
            print(f"⚠️ Error initializing defaults: {e}")
        finally:
            session.close()
    
    def get_session(self) -> Session:
        """Get a database session"""
        return self.Session()
    
    def close_session(self, session: Session):
        """Close a database session"""
        session.close()
    
    # ==================== Generic CRUD Operations ====================
    
    def create(self, model_class: Type[T], data: Dict[str, Any], session: Optional[Session] = None) -> T:
        """Create a new record"""
        should_close = session is None
        session = session or self.get_session()
        
        # Sanitize date fields (SQLite requires datetime objects, not strings)
        for date_field in ['created_at', 'updated_at']:
            if date_field in data and isinstance(data[date_field], str):
                try:
                    # Parse ISO format string to datetime object
                    # Handle 'Z' suffix if present
                    dt_str = data[date_field].replace('Z', '+00:00')
                    data[date_field] = datetime.fromisoformat(dt_str)
                except (ValueError, AttributeError):
                    # If parsing fails, remove the field and let default value take over
                    del data[date_field]

        try:
            instance = model_class(**data)
            session.add(instance)
            session.commit()
            session.refresh(instance)
            return instance
        except Exception as e:
            session.rollback()
            raise e
        finally:
            if should_close:
                session.close()
    
    def get(self, model_class: Type[T], id: str, session: Optional[Session] = None) -> Optional[T]:
        """Get a record by ID"""
        should_close = session is None
        session = session or self.get_session()
        
        try:
            return session.query(model_class).filter_by(id=id).first()
        finally:
            if should_close:
                session.close()
    
    def get_all(self, model_class: Type[T], filters: Optional[Dict] = None, 
                limit: int = 100, offset: int = 0, session: Optional[Session] = None) -> List[T]:
        """Get all records with optional filters"""
        should_close = session is None
        session = session or self.get_session()
        
        try:
            query = session.query(model_class)
            
            if filters:
                for key, value in filters.items():
                    if hasattr(model_class, key):
                        query = query.filter(getattr(model_class, key) == value)
            
            return query.offset(offset).limit(limit).all()
        finally:
            if should_close:
                session.close()
    
    def update(self, model_class: Type[T], id: str, data: Dict[str, Any], 
               session: Optional[Session] = None) -> Optional[T]:
        """Update a record"""
        should_close = session is None
        session = session or self.get_session()
        
        # Sanitize date fields
        for date_field in ['created_at', 'updated_at']:
            if date_field in data and isinstance(data[date_field], str):
                try:
                    dt_str = data[date_field].replace('Z', '+00:00')
                    data[date_field] = datetime.fromisoformat(dt_str)
                except (ValueError, AttributeError):
                    # For update, just ignore invalid date strings
                    pass
        
        try:
            instance = session.query(model_class).filter_by(id=id).first()
            if instance:
                for key, value in data.items():
                    if hasattr(instance, key):
                        setattr(instance, key, value)
                instance.updated_at = datetime.now(timezone.utc)
                session.commit()
                session.refresh(instance)
            return instance
        except Exception as e:
            session.rollback()
            raise e
        finally:
            if should_close:
                session.close()
    
    def delete(self, model_class: Type[T], id: str, session: Optional[Session] = None) -> bool:
        """Delete a record"""
        should_close = session is None
        session = session or self.get_session()
        
        try:
            instance = session.query(model_class).filter_by(id=id).first()
            if instance:
                session.delete(instance)
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            raise e
        finally:
            if should_close:
                session.close()
    
    # ==================== Project Operations ====================
    
    def get_default_project(self, session: Optional[Session] = None) -> Optional[Project]:
        """Get the default project"""
        return self.get(Project, 'default-project', session)
    
    def get_project_stats(self, project_id: str, session: Optional[Session] = None) -> Dict[str, int]:
        """Get statistics for a project"""
        should_close = session is None
        session = session or self.get_session()
        
        try:
            return {
                'assets': session.query(Asset).filter_by(project_id=project_id).count(),
                'threats': session.query(Threat).filter_by(project_id=project_id).count(),
                'controls': session.query(Control).filter_by(project_id=project_id).count(),
                'evidence': session.query(AttackEvidence).filter_by(project_id=project_id).count(),
                'data_flows': session.query(DataFlow).filter_by(project_id=project_id).count(),
            }
        finally:
            if should_close:
                session.close()
    
    # ==================== Asset Operations ====================
    
    def create_asset(self, data: Dict[str, Any], project_id: str = 'default-project') -> Asset:
        """Create a new asset"""
        data['project_id'] = project_id
        if 'asset_type' not in data and 'type' in data:
            data['asset_type'] = data.pop('type')
        return self.create(Asset, data)
    
    def get_project_assets(self, project_id: str = 'default-project') -> List[Asset]:
        """Get all assets for a project"""
        return self.get_all(Asset, {'project_id': project_id})
    
    # ==================== Threat Operations ====================
    
    def create_threat(self, data: Dict[str, Any], project_id: str = 'default-project') -> Threat:
        """Create a new threat"""
        data['project_id'] = project_id
        if 'stride_category' not in data and 'category' in data:
            data['stride_category'] = data.pop('category')
        return self.create(Threat, data)
    
    def get_project_threats(self, project_id: str = 'default-project') -> List[Threat]:
        """Get all threats for a project with controls eager loaded"""
        from sqlalchemy.orm import joinedload
        session = self.get_session()
        try:
            return session.query(Threat).filter(
                Threat.project_id == project_id
            ).options(joinedload(Threat.controls)).all()
        finally:
            session.close()
    
    def get_unmitigated_threats(self, project_id: str = 'default-project', session: Optional[Session] = None) -> List[Threat]:
        """Get threats without controls"""
        should_close = session is None
        session = session or self.get_session()
        
        try:
            return session.query(Threat).filter(
                and_(
                    Threat.project_id == project_id,
                    Threat.is_mitigated == False
                )
            ).all()
        finally:
            if should_close:
                session.close()
    
    # ==================== Control Operations ====================
    
    def create_control(self, data: Dict[str, Any], project_id: str = 'default-project') -> Control:
        """Create a new control"""
        data['project_id'] = project_id
        if 'control_type' not in data and 'type' in data:
            data['control_type'] = data.pop('type')
        return self.create(Control, data)
    
    def get_project_controls(self, project_id: str = 'default-project') -> List[Control]:
        """Get all controls for a project"""
        return self.get_all(Control, {'project_id': project_id})
    
    def get_threat_control_mappings(self, project_id: str = 'default-project') -> Dict[str, List[str]]:
        """Get threat ID to control IDs mapping to avoid detached instance errors"""
        session = self.get_session()
        try:
            # Query the association table directly
            result = session.query(
                threat_control_association.c.threat_id,
                threat_control_association.c.control_id
            ).join(
                Threat, threat_control_association.c.threat_id == Threat.id
            ).filter(
                Threat.project_id == project_id
            ).all()
            
            # Build mapping: threat_id -> [control_id, ...]
            mapping = {}
            for threat_id, control_id in result:
                if threat_id not in mapping:
                    mapping[threat_id] = []
                mapping[threat_id].append(control_id)
            
            return mapping
        finally:
            session.close()
    
    def link_control_to_threat(self, control_id: str, threat_id: str, session: Optional[Session] = None) -> bool:
        """Link a control to a threat (mitigation relationship)"""
        should_close = session is None
        session = session or self.get_session()
        
        try:
            control = session.query(Control).filter_by(id=control_id).first()
            threat = session.query(Threat).filter_by(id=threat_id).first()
            
            if control and threat:
                if threat not in control.mitigated_threats:
                    control.mitigated_threats.append(threat)
                    threat.is_mitigated = True
                    session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            raise e
        finally:
            if should_close:
                session.close()
    
    # ==================== Evidence Operations ====================
    
    def create_evidence(self, data: Dict[str, Any], project_id: str = 'default-project') -> AttackEvidence:
        """Create new attack evidence"""
        data['project_id'] = project_id
        if 'evidence_type' not in data and 'type' in data:
            data['evidence_type'] = data.pop('type')
        return self.create(AttackEvidence, data)
    
    def get_project_evidence(self, project_id: str = 'default-project') -> List[AttackEvidence]:
        """Get all evidence for a project"""
        return self.get_all(AttackEvidence, {'project_id': project_id})
    
    # ==================== Canvas State Operations ====================
    
    def save_canvas_state(self, nodes: List[Dict], connections: List[Dict], 
                          viewport: Dict, project_id: str = 'default-project',
                          name: str = 'default') -> CanvasState:
        """Save canvas state"""
        session = self.get_session()
        
        try:
            # Find existing canvas state
            existing = session.query(CanvasState).filter(
                and_(
                    CanvasState.project_id == project_id,
                    CanvasState.name == name,
                    CanvasState.is_current == True
                )
            ).first()
            
            if existing:
                # Update existing
                existing.nodes = nodes
                existing.connections = connections
                existing.viewport = viewport
                existing.version += 1
                existing.updated_at = datetime.now(timezone.utc)
                session.commit()
                return existing
            else:
                # Create new
                canvas_state = CanvasState(
                    project_id=project_id,
                    name=name,
                    nodes=nodes,
                    connections=connections,
                    viewport=viewport,
                    is_current=True
                )
                session.add(canvas_state)
                session.commit()
                return canvas_state
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def load_canvas_state(self, project_id: str = 'default-project', name: str = 'default') -> Optional[CanvasState]:
        """Load canvas state"""
        session = self.get_session()
        
        try:
            return session.query(CanvasState).filter(
                and_(
                    CanvasState.project_id == project_id,
                    CanvasState.name == name,
                    CanvasState.is_current == True
                )
            ).first()
        finally:
            session.close()
    
    # ==================== Custom Template Operations ====================
    
    def create_custom_template(self, data: Dict[str, Any], creator_id: str = 'default-user') -> CustomTemplate:
        """Create a custom template"""
        data['creator_id'] = creator_id
        return self.create(CustomTemplate, data)
    
    def get_templates(self, template_type: Optional[str] = None, include_system: bool = True) -> List[CustomTemplate]:
        """Get templates (custom and optionally system)"""
        session = self.get_session()
        
        try:
            query = session.query(CustomTemplate).filter(
                or_(
                    CustomTemplate.is_public == True,
                    CustomTemplate.is_system == True if include_system else False
                )
            )
            
            if template_type:
                query = query.filter(CustomTemplate.template_type == template_type)
            
            return query.all()
        finally:
            session.close()
    
    # ==================== Intel Operations ====================
    
    def create_intel_source(self, data: Dict[str, Any]) -> IntelSource:
        """Create an intel source"""
        return self.create(IntelSource, data)
    
    def get_active_intel_sources(self) -> List[IntelSource]:
        """Get all active intel sources"""
        return self.get_all(IntelSource, {'enabled': True, 'status': 'active'})
    
    def create_intel_item(self, data: Dict[str, Any]) -> IntelItem:
        """Create an intel item"""
        return self.create(IntelItem, data)
    
    def get_unprocessed_intel(self, limit: int = 100) -> List[IntelItem]:
        """Get unprocessed intel items"""
        session = self.get_session()
        
        try:
            return session.query(IntelItem).filter(
                IntelItem.is_processed == False
            ).order_by(IntelItem.created_at.desc()).limit(limit).all()
        finally:
            session.close()
    
    def get_relevant_intel(self, limit: int = 100) -> List[IntelItem]:
        """Get relevant intel items"""
        session = self.get_session()
        
        try:
            return session.query(IntelItem).filter(
                and_(
                    IntelItem.is_relevant == True,
                    IntelItem.is_converted == False
                )
            ).order_by(desc(IntelItem.ai_relevance_score)).limit(limit).all()
        finally:
            session.close()
    
    # ==================== Configuration Operations ====================
    
    def get_config(self, key: str) -> Any:
        """Get a system config value"""
        session = self.get_session()
        
        try:
            config = session.query(SystemConfig).filter_by(key=key).first()
            return config.value if config else None
        finally:
            session.close()
    
    def set_config(self, key: str, value: Any, category: str = 'general', 
                   description: str = None, is_secret: bool = False) -> SystemConfig:
        """Set a system config value"""
        session = self.get_session()
        
        try:
            config = session.query(SystemConfig).filter_by(key=key).first()
            
            if config:
                config.value = value
                if description:
                    config.description = description
                config.updated_at = datetime.now(timezone.utc)
            else:
                config = SystemConfig(
                    key=key,
                    value=value,
                    category=category,
                    description=description,
                    is_secret=is_secret
                )
                session.add(config)
            
            session.commit()
            return config
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_all_configs(self, category: Optional[str] = None) -> List[SystemConfig]:
        """Get all system configs"""
        filters = {}
        if category:
            filters['category'] = category
        return self.get_all(SystemConfig, filters, limit=1000)
    
    # ==================== LLM Config Operations ====================
    
    def save_llm_config(self, data: Dict[str, Any]) -> LLMConfig:
        """Save or update LLM config"""
        session = self.get_session()
        
        try:
            existing = session.query(LLMConfig).filter_by(name=data.get('name')).first()
            
            if existing:
                for key, value in data.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                existing.updated_at = datetime.now(timezone.utc)
                session.commit()
                return existing
            else:
                config = LLMConfig(**data)
                session.add(config)
                session.commit()
                return config
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_default_llm_config(self) -> Optional[LLMConfig]:
        """Get the default LLM config"""
        session = self.get_session()
        
        try:
            return session.query(LLMConfig).filter_by(is_default=True).first()
        finally:
            session.close()
    
    def get_llm_configs(self) -> List[LLMConfig]:
        """Get all LLM configs"""
        return self.get_all(LLMConfig, {'status': 'active'}, limit=100)

    # ==================== Knowledge Base Operations ====================
    
    def create_threat_knowledge(self, data: Dict[str, Any], project_id: str = 'default-project') -> ThreatKnowledge:
        """Create a threat knowledge entry"""
        data['project_id'] = data.get('project_id', project_id)
        return self.create(ThreatKnowledge, data)
    
    def get_threat_knowledge(self, filters: Dict[str, Any], limit: int = 100, offset: int = 0) -> List[ThreatKnowledge]:
        """List threat knowledge entries"""
        return self.get_all(ThreatKnowledge, filters, limit=limit, offset=offset)
    
    # ==================== Detection Rule Operations ====================
    
    def create_detection_rule(self, data: Dict[str, Any], project_id: str = 'default-project') -> DetectionRule:
        """Create a detection rule"""
        data['project_id'] = data.get('project_id', project_id)
        return self.create(DetectionRule, data)
    
    def get_detection_rules(self, filters: Dict[str, Any], limit: int = 200, offset: int = 0) -> List[DetectionRule]:
        """List detection rules"""
        return self.get_all(DetectionRule, filters, limit=limit, offset=offset)
    
    # ==================== Baseline Result Operations ====================
    
    def create_baseline_result(self, data: Dict[str, Any], project_id: str = 'default-project') -> BaselineResult:
        """Create a baseline compliance result"""
        data['project_id'] = data.get('project_id', project_id)
        return self.create(BaselineResult, data)
    
    def get_baseline_results(self, filters: Dict[str, Any], limit: int = 200, offset: int = 0) -> List[BaselineResult]:
        """List baseline results"""
        return self.get_all(BaselineResult, filters, limit=limit, offset=offset)
    
    # ==================== Data Export/Import ====================
    
    def export_project(self, project_id: str = 'default-project') -> Dict[str, Any]:
        """Export entire project data"""
        session = self.get_session()
        
        try:
            project = session.query(Project).filter_by(id=project_id).first()
            if not project:
                return {}
            
            return {
                'project': project.to_dict(),
                'assets': [a.to_dict() for a in project.assets],
                'threats': [t.to_dict() for t in project.threats],
                'controls': [c.to_dict() for c in project.controls],
                'evidence': [e.to_dict() for e in project.evidence],
                'data_flows': [d.to_dict() for d in project.data_flows],
                'canvas_states': [cs.to_dict() for cs in project.canvas_states],
                'exported_at': datetime.now(timezone.utc).isoformat()
            }
        finally:
            session.close()
    
    def import_project(self, data: Dict[str, Any], new_project_name: Optional[str] = None) -> Project:
        """Import project data"""
        session = self.get_session()
        
        try:
            # Create new project
            project_data = data.get('project', {})
            project_data['id'] = str(__import__('uuid').uuid4())
            if new_project_name:
                project_data['name'] = new_project_name
            
            project = Project(**{k: v for k, v in project_data.items() 
                                if k not in ['created_at', 'updated_at', 'asset_count', 'threat_count', 'control_count']})
            session.add(project)
            
            # Import assets
            id_mapping = {}
            for asset_data in data.get('assets', []):
                old_id = asset_data['id']
                asset_data['id'] = str(__import__('uuid').uuid4())
                asset_data['project_id'] = project.id
                asset = Asset(**{k: v for k, v in asset_data.items() 
                               if k not in ['created_at', 'updated_at', 'cardType']})
                session.add(asset)
                id_mapping[old_id] = asset.id
            
            # Import threats
            for threat_data in data.get('threats', []):
                old_id = threat_data['id']
                threat_data['id'] = str(__import__('uuid').uuid4())
                threat_data['project_id'] = project.id
                if 'stride_category' not in threat_data and 'category' in threat_data:
                    threat_data['stride_category'] = threat_data.pop('category')
                threat = Threat(**{k: v for k, v in threat_data.items() 
                                  if k not in ['created_at', 'updated_at', 'cardType', 'control_count', 'category']})
                session.add(threat)
                id_mapping[old_id] = threat.id
            
            # Import controls
            for control_data in data.get('controls', []):
                old_id = control_data['id']
                control_data['id'] = str(__import__('uuid').uuid4())
                control_data['project_id'] = project.id
                if 'control_type' not in control_data and 'type' in control_data:
                    control_data['control_type'] = control_data.pop('type')
                control = Control(**{k: v for k, v in control_data.items() 
                                    if k not in ['created_at', 'updated_at', 'cardType', 'threat_count', 'type']})
                session.add(control)
                id_mapping[old_id] = control.id
            
            session.commit()
            return project
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()


# ==================== Global Instance ====================

_db_manager: Optional[DatabaseManager] = None


def get_db_manager(database_url: Optional[str] = None) -> DatabaseManager:
    """Get or create the global database manager instance"""
    global _db_manager
    
    if _db_manager is None:
        _db_manager = DatabaseManager(database_url)
    
    return _db_manager


def init_db(database_url: Optional[str] = None) -> DatabaseManager:
    """Initialize the database (alias for get_db_manager)"""
    return get_db_manager(database_url)


