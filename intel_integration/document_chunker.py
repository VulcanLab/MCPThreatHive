"""
MCP Threat Platform - Dynamic Sliding Window Chunking

Implements dynamic chunking mechanism for efficient document processing.
This module implements intelligent text chunking with overlapping windows to preserve context.
"""

from __future__ import annotations

import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ChunkingStrategy(Enum):
    """Chunking strategies for different document types"""
    FIXED = "fixed"  # Fixed-size chunks
    SEMANTIC = "semantic"  # Semantic boundaries (sentences, paragraphs)
    SLIDING_WINDOW = "sliding_window"  # Dynamic sliding window with overlap
    ADAPTIVE = "adaptive"  # Adaptive based on content structure


@dataclass
class TextChunk:
    """Represents a chunk of text with metadata"""
    content: str
    chunk_id: str
    start_index: int
    end_index: int
    chunk_index: int
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class DynamicChunker:
    """
    Dynamic Sliding Window Chunker
    
    Intelligently chunks documents with:
    - Overlapping windows to preserve context
    - Semantic boundary detection
    - Adaptive chunk sizing
    - Metadata preservation
    """
    
    def __init__(
        self,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
        strategy: ChunkingStrategy = ChunkingStrategy.SLIDING_WINDOW,
        min_chunk_size: int = 100,
        max_chunk_size: int = 2000
    ):
        """
        Initialize chunker.
        
        Args:
            chunk_size: Target chunk size in characters
            chunk_overlap: Overlap between chunks in characters
            strategy: Chunking strategy to use
            min_chunk_size: Minimum chunk size
            max_chunk_size: Maximum chunk size
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.strategy = strategy
        self.min_chunk_size = min_chunk_size
        self.max_chunk_size = max_chunk_size
    
    def chunk_text(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[TextChunk]:
        """
        Chunk text using the configured strategy.
        
        Args:
            text: Text to chunk
            metadata: Optional metadata to attach to chunks
            
        Returns:
            List of TextChunk objects
        """
        if not text or len(text.strip()) == 0:
            return []
        
        if self.strategy == ChunkingStrategy.SLIDING_WINDOW:
            return self._sliding_window_chunk(text, metadata)
        elif self.strategy == ChunkingStrategy.SEMANTIC:
            return self._semantic_chunk(text, metadata)
        elif self.strategy == ChunkingStrategy.ADAPTIVE:
            return self._adaptive_chunk(text, metadata)
        else:
            return self._fixed_chunk(text, metadata)
    
    def _sliding_window_chunk(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[TextChunk]:
        """Sliding window chunking with overlap"""
        chunks = []
        text_length = len(text)
        start = 0
        chunk_index = 0
        
        while start < text_length:
            # Calculate end position
            end = min(start + self.chunk_size, text_length)
            
            # Extract chunk
            chunk_content = text[start:end]
            
            # Try to break at sentence boundary if not at end
            if end < text_length:
                # Look for sentence endings within the last 20% of chunk
                boundary_zone = chunk_content[int(len(chunk_content) * 0.8):]
                sentence_end = self._find_sentence_boundary(boundary_zone)
                
                if sentence_end > 0:
                    # Adjust end to sentence boundary
                    actual_end = start + int(len(chunk_content) * 0.8) + sentence_end
                    chunk_content = text[start:actual_end]
                    end = actual_end
            
            # Ensure minimum chunk size
            if len(chunk_content.strip()) < self.min_chunk_size and start > 0:
                # Merge with previous chunk if too small
                if chunks:
                    chunks[-1].content += " " + chunk_content
                    chunks[-1].end_index = end
                    start = end - self.chunk_overlap
                    continue
            
            # Create chunk
            chunk = TextChunk(
                content=chunk_content.strip(),
                chunk_id=f"chunk_{chunk_index}",
                start_index=start,
                end_index=end,
                chunk_index=chunk_index,
                metadata=metadata or {}
            )
            chunks.append(chunk)
            
            # Move start position with overlap
            start = end - self.chunk_overlap
            chunk_index += 1
            
            # Prevent infinite loop
            if start >= end:
                break
        
        return chunks
    
    def _semantic_chunk(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[TextChunk]:
        """Chunk at semantic boundaries (paragraphs, sections)"""
        chunks = []
        
        # Split by paragraphs first
        paragraphs = re.split(r'\n\s*\n+', text)
        
        current_chunk = []
        current_size = 0
        chunk_index = 0
        start_index = 0
        
        for para in paragraphs:
            para = para.strip()
            if not para:
                continue
            
            para_size = len(para)
            
            # If adding this paragraph exceeds chunk size, finalize current chunk
            if current_size + para_size > self.chunk_size and current_chunk:
                chunk_content = "\n\n".join(current_chunk)
                end_index = start_index + len(chunk_content)
                
                chunk = TextChunk(
                    content=chunk_content,
                    chunk_id=f"chunk_{chunk_index}",
                    start_index=start_index,
                    end_index=end_index,
                    chunk_index=chunk_index,
                    metadata=metadata or {}
                )
                chunks.append(chunk)
                
                # Start new chunk with overlap
                overlap_text = "\n\n".join(current_chunk[-2:]) if len(current_chunk) >= 2 else current_chunk[-1]
                current_chunk = [overlap_text[-self.chunk_overlap:], para] if len(overlap_text) > self.chunk_overlap else [para]
                current_size = sum(len(p) for p in current_chunk)
                start_index = end_index - self.chunk_overlap
                chunk_index += 1
            else:
                current_chunk.append(para)
                current_size += para_size
        
        # Add final chunk
        if current_chunk:
            chunk_content = "\n\n".join(current_chunk)
            end_index = start_index + len(chunk_content)
            
            chunk = TextChunk(
                content=chunk_content,
                chunk_id=f"chunk_{chunk_index}",
                start_index=start_index,
                end_index=end_index,
                chunk_index=chunk_index,
                metadata=metadata or {}
            )
            chunks.append(chunk)
        
        return chunks
    
    def _adaptive_chunk(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[TextChunk]:
        """Adaptive chunking based on content structure"""
        # Detect content type
        has_paragraphs = '\n\n' in text
        has_sections = re.search(r'^#{1,3}\s+', text, re.MULTILINE) is not None
        
        if has_sections:
            # Use section-based chunking
            return self._section_based_chunk(text, metadata)
        elif has_paragraphs:
            # Use paragraph-based chunking
            return self._semantic_chunk(text, metadata)
        else:
            # Fall back to sliding window
            return self._sliding_window_chunk(text, metadata)
    
    def _section_based_chunk(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[TextChunk]:
        """Chunk based on markdown-style sections"""
        chunks = []
        
        # Split by section headers
        sections = re.split(r'(^#{1,3}\s+.+$)', text, flags=re.MULTILINE)
        
        current_section = []
        chunk_index = 0
        start_index = 0
        
        for i, section in enumerate(sections):
            if not section.strip():
                continue
            
            # Check if it's a header
            if re.match(r'^#{1,3}\s+', section):
                # If we have content, finalize previous section
                if current_section and i > 0:
                    chunk_content = "".join(current_section)
                    end_index = start_index + len(chunk_content)
                    
                    chunk = TextChunk(
                        content=chunk_content.strip(),
                        chunk_id=f"chunk_{chunk_index}",
                        start_index=start_index,
                        end_index=end_index,
                        chunk_index=chunk_index,
                        metadata={**(metadata or {}), 'section_header': current_section[0] if current_section else None}
                    )
                    chunks.append(chunk)
                    
                    start_index = end_index
                    chunk_index += 1
                
                current_section = [section]
            else:
                current_section.append(section)
        
        # Add final section
        if current_section:
            chunk_content = "".join(current_section)
            end_index = start_index + len(chunk_content)
            
            chunk = TextChunk(
                content=chunk_content.strip(),
                chunk_id=f"chunk_{chunk_index}",
                start_index=start_index,
                end_index=end_index,
                chunk_index=chunk_index,
                metadata={**(metadata or {}), 'section_header': current_section[0] if current_section else None}
            )
            chunks.append(chunk)
        
        return chunks
    
    def _fixed_chunk(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[TextChunk]:
        """Simple fixed-size chunking"""
        chunks = []
        text_length = len(text)
        chunk_index = 0
        
        for start in range(0, text_length, self.chunk_size - self.chunk_overlap):
            end = min(start + self.chunk_size, text_length)
            chunk_content = text[start:end]
            
            chunk = TextChunk(
                content=chunk_content.strip(),
                chunk_id=f"chunk_{chunk_index}",
                start_index=start,
                end_index=end,
                chunk_index=chunk_index,
                metadata=metadata or {}
            )
            chunks.append(chunk)
            chunk_index += 1
        
        return chunks
    
    def _find_sentence_boundary(self, text: str) -> int:
        """Find the first sentence boundary in text"""
        # Look for sentence endings
        patterns = [
            r'[.!?]\s+[A-Z]',  # Sentence ending followed by capital
            r'[.!?]\s*\n',      # Sentence ending at line break
            r'[.!?]\s*$',       # Sentence ending at end of text
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.end()
        
        return -1


def chunk_intel_content(
    content: str,
    title: str = "",
    url: str = "",
    chunk_size: int = 1000,
    chunk_overlap: int = 200
) -> List[TextChunk]:
    """
    Convenience function to chunk intelligence content.
    
    Args:
        content: Text content to chunk
        title: Document title
        url: Source URL
        chunk_size: Target chunk size
        chunk_overlap: Overlap between chunks
        
    Returns:
        List of TextChunk objects
    """
    chunker = DynamicChunker(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        strategy=ChunkingStrategy.SLIDING_WINDOW
    )
    
    metadata = {
        'title': title,
        'url': url,
        'chunk_size': chunk_size,
        'chunk_overlap': chunk_overlap
    }
    
    return chunker.chunk_text(content, metadata)

