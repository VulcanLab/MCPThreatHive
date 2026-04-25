#!/usr/bin/env python3
"""
Database Migration: Add threat_knowledge, detection_rules, baseline_results tables.

Fields are aligned with database/models.py. Uses simple CREATE TABLE IF NOT EXISTS
to stay compatible with SQLite/PostgreSQL.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy import text
from sqlalchemy import inspect as sqlalchemy_inspect
from database.db_manager import get_db_manager


def _table_exists(inspector, table_name: str) -> bool:
    try:
        return inspector.has_table(table_name)
    except Exception:
        tables = inspector.get_table_names()
        return table_name in tables


def migrate():
    db = get_db_manager()
    engine = db.engine
    inspector = sqlalchemy_inspect(engine)

    print("🔄 Starting migration: threat_knowledge, detection_rules, baseline_results")

    with engine.begin() as conn:
        # threat_knowledge
        if not _table_exists(inspector, "threat_knowledge"):
            print("  ➕ Creating table threat_knowledge")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS threat_knowledge (
                    id VARCHAR(64) PRIMARY KEY,
                    project_id VARCHAR(64),
                    title VARCHAR(256) NOT NULL,
                    description TEXT,
                    surface VARCHAR(128),
                    attack_type VARCHAR(128),
                    impact TEXT,
                    severity VARCHAR(32) DEFAULT 'medium',
                    cve VARCHAR(64),
                    cwe VARCHAR(64),
                    detections JSON,
                    mitigations JSON,
                    ioc JSON,
                    references JSON,
                    tags JSON,
                    status VARCHAR(32) DEFAULT 'active',
                    version VARCHAR(32) DEFAULT '1.0.0',
                    source VARCHAR(256),
                    source_url VARCHAR(1024),
                    created_at DATETIME,
                    updated_at DATETIME
                )
            """))
        else:
            print("  ⏭️  threat_knowledge already exists")

        # detection_rules
        if not _table_exists(inspector, "detection_rules"):
            print("  ➕ Creating table detection_rules")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS detection_rules (
                    id VARCHAR(64) PRIMARY KEY,
                    project_id VARCHAR(64),
                    name VARCHAR(256) NOT NULL,
                    description TEXT,
                    rule_type VARCHAR(32) DEFAULT 'static',
                    target_component VARCHAR(128),
                    severity VARCHAR(32) DEFAULT 'medium',
                    status VARCHAR(32) DEFAULT 'draft',
                    source_threat_id VARCHAR(64),
                    rule_json JSON,
                    tags JSON,
                    created_at DATETIME,
                    updated_at DATETIME
                )
            """))
        else:
            print("  ⏭️  detection_rules already exists")

        # baseline_results
        if not _table_exists(inspector, "baseline_results"):
            print("  ➕ Creating table baseline_results")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS baseline_results (
                    id VARCHAR(64) PRIMARY KEY,
                    project_id VARCHAR(64),
                    target VARCHAR(512),
                    target_type VARCHAR(64),
                    baseline_version VARCHAR(32) DEFAULT '1.0.0',
                    passed_count INTEGER DEFAULT 0,
                    failed_count INTEGER DEFAULT 0,
                    score FLOAT DEFAULT 0.0,
                    status VARCHAR(32) DEFAULT 'completed',
                    findings JSON,
                    meta_data JSON,
                    created_at DATETIME,
                    updated_at DATETIME
                )
            """))
        else:
            print("  ⏭️  baseline_results already exists")

    print("✅ Migration completed.")


if __name__ == "__main__":
    migrate()

