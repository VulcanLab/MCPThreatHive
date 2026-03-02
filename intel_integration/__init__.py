"""
MCP Threat Platform - Intelligence Integration

Complete intelligence gathering and processing system.

Features:
- AI-powered keyword generation (no hardcoded queries)
- Universal web search via DuckDuckGo
- Multiple data sources (GitHub, CVE, RSS)
- AI processing and filtering
- Automated threat schema conversion
"""

from .ai_keyword_generator import AIKeywordGenerator
from .ai_processor import AIIntelProcessor, ProcessedIntel
from .intel_pipeline import (
    IntelPipeline,
    PipelineConfig,
    PipelineResult,
    ScheduledIntelPipeline,
    run_intel_pipeline,
    run_intel_pipeline_sync
)
from .data_sources import (
    DataSource,
    IntelItem,
    SourceType,
    GitHubSource,
    CVESource,
    RSSSource,
    WebSearchSource
)
from .document_chunker import (
    DynamicChunker,
    ChunkingStrategy,
    TextChunk,
    chunk_intel_content
)
from .ensemble_retriever import (
    EnsembleRetriever,
    RetrievalStrategy,
    RetrievalResult,
    create_retriever_from_content
)

__all__ = [
    # AI Components
    'AIKeywordGenerator',
    'AIIntelProcessor',
    'ProcessedIntel',
    
    # Pipeline
    'IntelPipeline',
    'PipelineConfig',
    'PipelineResult',
    'ScheduledIntelPipeline',
    'run_intel_pipeline',
    'run_intel_pipeline_sync',
    
    # Data Sources
    'DataSource',
    'IntelItem',
    'SourceType',
    'GitHubSource',
    'CVESource',
    'RSSSource',
    'WebSearchSource',
    
    # Document Processing
    'DynamicChunker',
    'ChunkingStrategy',
    'TextChunk',
    'chunk_intel_content',
    'EnsembleRetriever',
    'RetrievalStrategy',
    'RetrievalResult',
    'create_retriever_from_content'
]
