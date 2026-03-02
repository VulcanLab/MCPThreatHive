#!/usr/bin/env python3
"""
Database Migration: Add MAESTRO fields to threats table

This migration adds:
- maestro_layer (Integer) - Primary MAESTRO layer
- is_cross_layer (Boolean) - Whether threat spans multiple layers
- affected_layers (JSON) - List of affected layers
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy import text
from sqlalchemy import inspect as sqlalchemy_inspect
from database.db_manager import get_db_manager


def migrate():
    """Run migration to add MAESTRO fields"""
    db = get_db_manager()
    engine = db.engine
    
    print("🔄 Starting MAESTRO fields migration...")
    
    try:
        # Check if columns already exist using SQLAlchemy inspect
        inspector = sqlalchemy_inspect(engine)
        existing_columns = [col['name'] for col in inspector.get_columns('threats')]
        
        # Use begin() for automatic transaction management
        with engine.begin() as conn:
            
            # Add maestro_layer if not exists
            if 'maestro_layer' not in existing_columns:
                print("  ➕ Adding maestro_layer column...")
                conn.execute(text("""
                    ALTER TABLE threats 
                    ADD COLUMN maestro_layer INTEGER
                """))
                print("  ✅ Added maestro_layer")
            else:
                print("  ⏭️  maestro_layer already exists")
            
            # Add is_cross_layer if not exists
            if 'is_cross_layer' not in existing_columns:
                print("  ➕ Adding is_cross_layer column...")
                conn.execute(text("""
                    ALTER TABLE threats 
                    ADD COLUMN is_cross_layer BOOLEAN DEFAULT FALSE
                """))
                print("  ✅ Added is_cross_layer")
            else:
                print("  ⏭️  is_cross_layer already exists")
            
            # Add affected_layers if not exists
            if 'affected_layers' not in existing_columns:
                print("  ➕ Adding affected_layers column...")
                # SQLite uses TEXT for JSON, PostgreSQL uses JSON
                if 'sqlite' in str(engine.url).lower():
                    conn.execute(text("""
                        ALTER TABLE threats 
                        ADD COLUMN affected_layers TEXT DEFAULT '[]'
                    """))
                else:
                    conn.execute(text("""
                        ALTER TABLE threats 
                        ADD COLUMN affected_layers JSON DEFAULT '[]'::json
                    """))
                print("  ✅ Added affected_layers")
            else:
                print("  ⏭️  affected_layers already exists")
        
        print("✅ Migration completed successfully!")
        
        # Map existing threats to MAESTRO layers
        print("\n🔄 Mapping existing threats to MAESTRO layers...")
        map_existing_threats()
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise


def map_existing_threats():
    """Map existing threats to MAESTRO layers"""
    from core.maestro import MaestroThreatMapper
    from database.models import Project
    
    db = get_db_manager()
    mapper = MaestroThreatMapper()
    session = db.get_session()
    
    try:
        # Get all projects using get_all method (with higher limit to get all)
        projects = db.get_all(Project, {}, limit=1000, session=session)
        
        # If no projects found, try to get default project
        if not projects:
            default_project = db.get_default_project(session)
            if default_project:
                projects = [default_project]
            else:
                print("  ⚠️  No projects found, skipping threat mapping")
                return
        
        print(f"  📋 Found {len(projects)} project(s) to process")
        
        mapped_count = 0
        
        for project in projects:
            threats = db.get_project_threats(project.id)
            
            for threat in threats:
                threat_dict = threat.to_dict()
                mapping = mapper.map_threat(
                    threat_dict.get('name', ''),
                    threat_dict.get('stride_category', '')
                )
                
                # Update threat with MAESTRO mapping
                threat.maestro_layer = mapping['primary_layer']
                threat.is_cross_layer = len(mapping.get('secondary_layers', [])) > 0
                threat.affected_layers = [mapping['primary_layer']] + mapping.get('secondary_layers', [])
                
                mapped_count += 1
            
            session.commit()
        
        print(f"  ✅ Mapped {mapped_count} threats to MAESTRO layers")
    except Exception as e:
        session.rollback()
        print(f"  ⚠️  Failed to map threats: {e}")
        import traceback
        traceback.print_exc()
        # Don't raise - allow migration to complete even if mapping fails
    finally:
        session.close()


if __name__ == "__main__":
    migrate()

