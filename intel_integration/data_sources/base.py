"""
MCP Threat Platform - Base Data Source

Abstract base class for all intel data sources.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum


class SourceType(Enum):
    """Types of intelligence sources"""
    GITHUB = "github"
    CVE = "cve"
    NVD = "nvd"
    RSS = "rss"
    TWITTER = "twitter"
    WEB_SEARCH = "web_search"
    ARXIV = "arxiv"
    HACKER_NEWS = "hacker_news"
    MANUAL = "manual"


@dataclass
class IntelItem:
    """
    Raw intelligence item from any source.
    
    This is the common format before AI processing.
    """
    # Unique identifier
    id: str = ""
    
    # Basic content
    title: str = ""
    content: str = ""
    summary: str = ""
    url: str = ""
    
    # Source metadata
    source_type: SourceType = SourceType.MANUAL
    source_name: str = ""
    source_url: str = ""
    author: str = ""
    
    # Timestamps
    published_at: Optional[datetime] = None
    collected_at: datetime = field(default_factory=datetime.utcnow)
    
    # Raw data (for debugging)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # Processing status
    is_processed: bool = False
    is_relevant: bool = False
    relevance_score: float = 0.0
    
    # Tags and categories (from source)
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Generate ID if not provided"""
        if not self.id:
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique ID from content hash"""
        content = f"{self.title}:{self.url}:{self.source_type.value}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'summary': self.summary,
            'url': self.url,
            'source_type': self.source_type.value,
            'source_name': self.source_name,
            'source_url': self.source_url,
            'author': self.author,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'collected_at': self.collected_at.isoformat() if self.collected_at else None,
            'is_processed': self.is_processed,
            'is_relevant': self.is_relevant,
            'relevance_score': self.relevance_score,
            'tags': self.tags,
            'categories': self.categories
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntelItem':
        """Create from dictionary"""
        return cls(
            id=data.get('id', ''),
            title=data.get('title', ''),
            content=data.get('content', ''),
            summary=data.get('summary', ''),
            url=data.get('url', ''),
            source_type=SourceType(data.get('source_type', 'manual')),
            source_name=data.get('source_name', ''),
            source_url=data.get('source_url', ''),
            author=data.get('author', ''),
            published_at=datetime.fromisoformat(data['published_at']) if data.get('published_at') else None,
            is_processed=data.get('is_processed', False),
            is_relevant=data.get('is_relevant', False),
            relevance_score=data.get('relevance_score', 0.0),
            tags=data.get('tags', []),
            categories=data.get('categories', []),
            raw_data=data.get('raw_data', {})
        )


class DataSource(ABC):
    """
    Abstract base class for all intelligence data sources.
    
    Each source implements collect() to gather raw intel items.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize data source.
        
        Args:
            config: Source-specific configuration
        """
        self.config = config or {}
        self.source_type: SourceType = SourceType.MANUAL
        self.source_name: str = "Unknown Source"
        self.enabled: bool = True
        self.last_run: Optional[datetime] = None
        self.items_collected: int = 0
    
    @abstractmethod
    async def collect(self, keywords: List[str], max_items: int = 50) -> List[IntelItem]:
        """
        Collect intelligence items from this source.
        
        Args:
            keywords: Search keywords to use
            max_items: Maximum number of items to collect
            
        Returns:
            List of collected IntelItem objects
        """
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        """
        Validate that required configuration is present.
        
        Returns:
            True if configuration is valid
        """
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get source status information"""
        return {
            'source_type': self.source_type.value,
            'source_name': self.source_name,
            'enabled': self.enabled,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'items_collected': self.items_collected,
            'config_valid': self.validate_config()
        }
    
    def _create_item(self, **kwargs) -> IntelItem:
        """Helper to create IntelItem with source info"""
        return IntelItem(
            source_type=self.source_type,
            source_name=self.source_name,
            **kwargs
        )

