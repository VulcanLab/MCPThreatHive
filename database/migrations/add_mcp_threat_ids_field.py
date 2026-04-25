"""
Migration: Add mcp_threat_ids field to Threat model

This migration adds the mcp_threat_ids field to support MCP Threat ID classification (MCP-01 to MCP-38).
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from database.db_manager import DatabaseManager
from sqlalchemy import text, inspect


def migrate():
    """Add mcp_threat_ids field to threats table"""
    print("🔄 Starting mcp_threat_ids field migration...")
    
    db = DatabaseManager()
    engine = db.engine
    
    try:
        with engine.connect() as conn:
            # Check if table exists
            inspector = inspect(engine)
            if 'threats' not in inspector.get_table_names():
                print("  ⚠️  'threats' table does not exist. Please create tables first.")
                return
            
            # Get existing columns
            existing_columns = [col['name'] for col in inspector.get_columns('threats')]
            print(f"  📋 Existing columns: {len(existing_columns)}")
            
            # Check if column already exists
            if 'mcp_threat_ids' in existing_columns:
                print("  ⏭️  mcp_threat_ids column already exists, skipping")
                return
            
            print("  ➕ Adding mcp_threat_ids column...")
            
            # SQLite uses TEXT for JSON, PostgreSQL uses JSON
            if 'sqlite' in str(engine.url).lower():
                sql_type = 'TEXT'
                default = "'[]'"
            else:
                sql_type = 'JSON'
                default = "'[]'"
            
            sql = f"""
            ALTER TABLE threats 
                ADD COLUMN mcp_threat_ids {sql_type} NULL DEFAULT {default}
            """
            
            conn.execute(text(sql))
            conn.commit()
            print("  ✅ Added mcp_threat_ids column")
            
            print("\n✅ mcp_threat_ids field migration completed!")
            
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == '__main__':
    migrate()

