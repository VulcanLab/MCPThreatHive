"""
Migration: Add MCPSecBench classification fields to Threat model

This migration adds fields to support the MCPSecBench 4x17 threat matrix classification.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db_manager import DatabaseManager
from sqlalchemy import text, inspect


def migrate():
    """Add MCPSecBench fields to threats table"""
    print("Starting MCPSecBench fields migration...")
    
    db = DatabaseManager()
    engine = db.engine
    
    try:
        with engine.connect() as conn:
            # Check if table exists
            inspector = inspect(engine)
            if 'threats' not in inspector.get_table_names():
                print("  'threats' table does not exist. Please create tables first.")
                return
            
            # Get existing columns
            existing_columns = [col['name'] for col in inspector.get_columns('threats')]
            print(f"  Existing columns: {len(existing_columns)}")
            
            # Fields to add
            fields_to_add = [
                {
                    'name': 'mcp_surface',
                    'type': 'VARCHAR(64)',
                    'nullable': True,
                    'description': 'MCPSecBench attack surface'
                },
                {
                    'name': 'mcpsecbench_attack_type',
                    'type': 'VARCHAR(128)',
                    'nullable': True,
                    'description': 'MCPSecBench attack type (17 standard types)'
                },
                {
                    'name': 'mcpsecbench_severity',
                    'type': 'INTEGER',
                    'nullable': True,
                    'description': 'MCPSecBench severity score (0-10)'
                },
                {
                    'name': 'graph_pattern_data',
                    'type': 'JSON',
                    'nullable': False,
                    'default': "'{}'",
                    'description': 'Graph pattern information for knowledge graph'
                },
                {
                    'name': 'test_template_data',
                    'type': 'JSON',
                    'nullable': False,
                    'default': "'{}'",
                    'description': 'Test template information for scanner integration'
                }
            ]
            
            # Add each field if it doesn't exist
            for field in fields_to_add:
                if field['name'] not in existing_columns:
                    print(f"  Adding {field['name']} column...")
                    
                    if field['type'] == 'JSON':
                        # SQLite uses TEXT for JSON
                        if 'sqlite' in str(engine.url).lower():
                            sql_type = 'TEXT'
                            default = field.get('default', "'{}'")
                        else:
                            sql_type = 'JSON'
                            default = field.get('default', "'{}'")
                    else:
                        sql_type = field['type']
                        default = ''
                    
                    nullable = 'NULL' if field.get('nullable', True) else 'NOT NULL'
                    default_clause = f"DEFAULT {default}" if default else ''
                    
                    sql = f"""
                    ALTER TABLE threats 
                        ADD COLUMN {field['name']} {sql_type} {nullable} {default_clause}
                    """
                    
                    conn.execute(text(sql))
                    conn.commit()
                    print(f"  Added {field['name']} column")
                else:
                    print(f"  {field['name']} column already exists, skipping")
            
            print("\nMCPSecBench fields migration completed!")
            
    except Exception as e:
        print(f"\nMigration failed: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == '__main__':
    migrate()
