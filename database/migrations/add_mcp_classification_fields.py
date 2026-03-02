"""
Database Migration: Add MCP Classification Fields to threats table

This migration adds:
- mcp_workflow_phase (String) - MCP workflow phase classification
- msb_attack_type (String) - MSB attack type classification
- mcp_upd_phase (String) - MCP-UPD attack phase
- mcp_upd_tools (JSON) - MCP-UPD tool types
- mpma_attack_type (String) - MPMA attack type
- gapma_strategy (String) - GAPMA strategy
- asr_score (Float) - Attack Success Rate
- pua_score (Float) - Performance Under Attack
- nrp_score (Float) - Net Resilient Performance
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db_manager import get_db_manager
from sqlalchemy import text, inspect


def migrate():
    """Run migration to add MCP classification fields"""
    print("\n" + "="*60)
    print("🔄 Starting MCP Classification Fields Migration...")
    print("="*60)
    
    db = get_db_manager()
    session = db.get_session()
    
    try:
        # Check if table exists
        inspector = inspect(db.engine)
        if 'threats' not in inspector.get_table_names():
            print("  ⚠️  'threats' table does not exist. Creating tables...")
            from database.models import Base
            Base.metadata.create_all(db.engine)
            print("  ✅ Tables created")
            return
        
        # Get existing columns
        existing_columns = [col['name'] for col in inspector.get_columns('threats')]
        print(f"\n  📋 Existing columns: {len(existing_columns)}")
        
        # Fields to add
        fields_to_add = [
            {
                'name': 'mcp_workflow_phase',
                'type': 'VARCHAR(64)',
                'nullable': True,
                'description': 'MCP workflow phase (Task Planning, Tool Invocation, Response Handling, Cross-Phase)'
            },
            {
                'name': 'msb_attack_type',
                'type': 'VARCHAR(128)',
                'nullable': True,
                'description': 'MSB attack type (PI, PM, NC, OP, UI, FE, RI, Mixed)'
            },
            {
                'name': 'mcp_upd_phase',
                'type': 'VARCHAR(64)',
                'nullable': True,
                'description': 'MCP-UPD attack phase (Parasitic Ingestion, Privacy Collection, Privacy Disclosure)'
            },
            {
                'name': 'mcp_upd_tools',
                'type': 'JSON',
                'nullable': False,
                'default': "'[]'",
                'description': 'MCP-UPD tool types (EIT, PAT, NAT)'
            },
            {
                'name': 'mpma_attack_type',
                'type': 'VARCHAR(128)',
                'nullable': True,
                'description': 'MPMA attack type (DPMA, GAPMA)'
            },
            {
                'name': 'gapma_strategy',
                'type': 'VARCHAR(64)',
                'nullable': True,
                'description': 'GAPMA strategy (Authoritative, Emotional, Exaggerated, Subliminal)'
            },
            {
                'name': 'asr_score',
                'type': 'REAL',
                'nullable': True,
                'description': 'Attack Success Rate (0.0-1.0)'
            },
            {
                'name': 'pua_score',
                'type': 'REAL',
                'nullable': True,
                'description': 'Performance Under Attack (0.0-1.0)'
            },
            {
                'name': 'nrp_score',
                'type': 'REAL',
                'nullable': True,
                'description': 'Net Resilient Performance = PUA * (1 - ASR)'
            }
        ]
        
        added_count = 0
        skipped_count = 0
        
        # Add each field if it doesn't exist
        for field in fields_to_add:
            field_name = field['name']
            
            if field_name in existing_columns:
                print(f"  ⏭️  Field '{field_name}' already exists, skipping")
                skipped_count += 1
                continue
            
            try:
                # Build ALTER TABLE statement
                is_sqlite = 'sqlite' in db.database_url.lower()
                
                if is_sqlite:
                    # SQLite syntax
                    if field['type'] == 'JSON':
                        # SQLite doesn't have native JSON, use TEXT
                        alter_sql = f"ALTER TABLE threats ADD COLUMN {field_name} TEXT"
                        if 'default' in field:
                            # SQLite default for JSON should be '[]' as string
                            default_val = field['default'].strip("'\"")
                            alter_sql += f" DEFAULT '{default_val}'"
                    else:
                        alter_sql = f"ALTER TABLE threats ADD COLUMN {field_name} {field['type']}"
                        if 'default' in field:
                            alter_sql += f" DEFAULT {field['default']}"
                else:
                    # PostgreSQL syntax
                    alter_sql = f"ALTER TABLE threats ADD COLUMN {field_name} {field['type']}"
                    if not field.get('nullable', True):
                        alter_sql += " NOT NULL"
                    if 'default' in field:
                        alter_sql += f" DEFAULT {field['default']}"
                
                session.execute(text(alter_sql))
                session.commit()
                
                print(f"  ✅ Added field '{field_name}' ({field['description']})")
                added_count += 1
                
            except Exception as e:
                session.rollback()
                print(f"  ⚠️  Failed to add field '{field_name}': {e}")
                # Continue with other fields
        
        print(f"\n  📊 Migration Summary:")
        print(f"     - Fields added: {added_count}")
        print(f"     - Fields skipped (already exist): {skipped_count}")
        print(f"     - Total fields: {len(fields_to_add)}")
        
        if added_count > 0:
            print("\n  ✅ Migration completed successfully!")
        else:
            print("\n  ℹ️  All fields already exist. Database is up to date.")
        
    except Exception as e:
        session.rollback()
        print(f"\n  ❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        session.close()


if __name__ == '__main__':
    migrate()

