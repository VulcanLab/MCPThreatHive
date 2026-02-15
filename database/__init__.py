"""
MCP Threat Platform - Database Module

Provides persistent storage with SQLite (dev) / PostgreSQL (prod)
"""

from .models import (
    Base, User, Project, Asset, Threat, Control, 
    AttackEvidence, DataFlow, CanvasState, CustomTemplate,
    IntelSource, IntelItem, LLMConfig, SystemConfig, RiskPlanning
)
from .db_manager import DatabaseManager

__all__ = [
    'Base', 'User', 'Project', 'Asset', 'Threat', 'Control',
    'AttackEvidence', 'DataFlow', 'CanvasState', 'CustomTemplate',
    'IntelSource', 'IntelItem', 'LLMConfig', 'SystemConfig', 'RiskPlanning',
    'DatabaseManager'
]


