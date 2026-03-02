"""
MCP Threat Platform - Ensemble Retriever

Implements ensemble retrieval mechanism for efficient querying
of both fine-grained and coarse-grained information within documents.

This module implements multiple retrieval strategies and combines their results.
"""

from __future__ import annotations

import re
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
import hashlib

from .document_chunker import TextChunk, DynamicChunker


class RetrievalStrategy(Enum):
    """Different retrieval strategies"""
    KEYWORD = "keyword"  # Keyword-based search
    SEMANTIC = "semantic"  # Semantic similarity
    BM25 = "bm25"  # BM25 ranking
    HYBRID = "hybrid"  # Combination of multiple strategies


@dataclass
class RetrievalResult:
    """Result from document retrieval"""
    chunk: TextChunk
    score: float
    strategy: str
    relevance_reason: str = ""
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class EnsembleRetriever:
    """
    Ensemble Retriever for querying documents.
    
    Combines multiple retrieval strategies:
    - Keyword matching (fine-grained)
    - Semantic similarity (coarse-grained)
    - BM25 ranking
    - Hybrid approach
    """
    
    def __init__(
        self,
        chunks: List[TextChunk],
        use_semantic: bool = True,
        use_bm25: bool = True,
        top_k: int = 5
    ):
        """
        Initialize ensemble retriever.
        
        Args:
            chunks: List of text chunks to search
            use_semantic: Whether to use semantic similarity
            use_bm25: Whether to use BM25 ranking
            top_k: Number of top results to return
        """
        self.chunks = chunks
        self.use_semantic = use_semantic
        self.use_bm25 = use_bm25
        self.top_k = top_k
        
        # Build keyword index
        self._build_keyword_index()
        
        # Build BM25 index if enabled
        if self.use_bm25:
            self._build_bm25_index()
    
    def _build_keyword_index(self):
        """Build keyword-based index for fast lookup"""
        self.keyword_index = {}
        
        for chunk in self.chunks:
            # Extract keywords (simple word-based)
            words = re.findall(r'\b\w+\b', chunk.content.lower())
            for word in words:
                if len(word) > 2:  # Ignore very short words
                    if word not in self.keyword_index:
                        self.keyword_index[word] = []
                    self.keyword_index[word].append(chunk.chunk_id)
    
    def _build_bm25_index(self):
        """Build BM25 index for ranking"""
        # Simple BM25 implementation
        self.bm25_index = {}
        self.doc_freq = {}
        self.total_docs = len(self.chunks)
        
        for chunk in self.chunks:
            words = re.findall(r'\b\w+\b', chunk.content.lower())
            word_freq = {}
            
            for word in words:
                if len(word) > 2:
                    word_freq[word] = word_freq.get(word, 0) + 1
                    self.doc_freq[word] = self.doc_freq.get(word, 0) + 1
            
            self.bm25_index[chunk.chunk_id] = word_freq
    
    def retrieve(
        self,
        query: str,
        strategy: RetrievalStrategy = RetrievalStrategy.HYBRID
    ) -> List[RetrievalResult]:
        """
        Retrieve relevant chunks for a query.
        
        Args:
            query: Search query
            strategy: Retrieval strategy to use
            
        Returns:
            List of RetrievalResult objects sorted by relevance
        """
        if strategy == RetrievalStrategy.HYBRID:
            return self._hybrid_retrieve(query)
        elif strategy == RetrievalStrategy.KEYWORD:
            return self._keyword_retrieve(query)
        elif strategy == RetrievalStrategy.SEMANTIC:
            return self._semantic_retrieve(query)
        elif strategy == RetrievalStrategy.BM25:
            return self._bm25_retrieve(query)
        else:
            return self._keyword_retrieve(query)
    
    def _keyword_retrieve(self, query: str) -> List[RetrievalResult]:
        """Keyword-based retrieval (fine-grained)"""
        query_words = re.findall(r'\b\w+\b', query.lower())
        query_words = [w for w in query_words if len(w) > 2]
        
        chunk_scores = {}
        
        for word in query_words:
            if word in self.keyword_index:
                for chunk_id in self.keyword_index[word]:
                    chunk_scores[chunk_id] = chunk_scores.get(chunk_id, 0) + 1
        
        # Normalize scores
        max_score = max(chunk_scores.values()) if chunk_scores else 1
        
        results = []
        for chunk in self.chunks:
            if chunk.chunk_id in chunk_scores:
                score = chunk_scores[chunk.chunk_id] / max_score
                results.append(RetrievalResult(
                    chunk=chunk,
                    score=score,
                    strategy="keyword",
                    relevance_reason=f"Matched {chunk_scores[chunk.chunk_id]} query terms"
                ))
        
        # Sort by score descending
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:self.top_k]
    
    def _semantic_retrieve(self, query: str) -> List[RetrievalResult]:
        """Semantic similarity retrieval (coarse-grained)"""
        # Simple semantic matching based on word overlap and context
        query_words = set(re.findall(r'\b\w+\b', query.lower()))
        query_words = {w for w in query_words if len(w) > 2}
        
        results = []
        
        for chunk in self.chunks:
            chunk_words = set(re.findall(r'\b\w+\b', chunk.content.lower()))
            chunk_words = {w for w in chunk_words if len(w) > 2}
            
            # Calculate Jaccard similarity
            intersection = len(query_words & chunk_words)
            union = len(query_words | chunk_words)
            similarity = intersection / union if union > 0 else 0
            
            # Boost score for longer matches
            if similarity > 0:
                # Check for phrase matches
                query_phrases = self._extract_phrases(query)
                chunk_text_lower = chunk.content.lower()
                
                phrase_bonus = 0
                for phrase in query_phrases:
                    if phrase.lower() in chunk_text_lower:
                        phrase_bonus += 0.2
                
                final_score = min(similarity + phrase_bonus, 1.0)
                
                results.append(RetrievalResult(
                    chunk=chunk,
                    score=final_score,
                    strategy="semantic",
                    relevance_reason=f"Semantic similarity: {similarity:.2f}"
                ))
        
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:self.top_k]
    
    def _bm25_retrieve(self, query: str) -> List[RetrievalResult]:
        """BM25 ranking retrieval"""
        if not self.use_bm25:
            return []
        
        query_words = re.findall(r'\b\w+\b', query.lower())
        query_words = [w for w in query_words if len(w) > 2]
        
        k1 = 1.5  # BM25 parameter
        b = 0.75  # BM25 parameter
        avg_doc_length = sum(len(c.content) for c in self.chunks) / len(self.chunks) if self.chunks else 1
        
        results = []
        
        for chunk in self.chunks:
            score = 0.0
            doc_length = len(chunk.content)
            word_freq = self.bm25_index.get(chunk.chunk_id, {})
            
            for word in query_words:
                if word in word_freq:
                    tf = word_freq[word]
                    df = self.doc_freq.get(word, 1)
                    idf = max(0, (self.total_docs - df + 0.5) / (df + 0.5))
                    
                    # BM25 formula
                    numerator = idf * tf * (k1 + 1)
                    denominator = tf + k1 * (1 - b + b * (doc_length / avg_doc_length))
                    score += numerator / denominator
            
            if score > 0:
                results.append(RetrievalResult(
                    chunk=chunk,
                    score=score,
                    strategy="bm25",
                    relevance_reason=f"BM25 score: {score:.2f}"
                ))
        
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:self.top_k]
    
    def _hybrid_retrieve(self, query: str) -> List[RetrievalResult]:
        """Hybrid retrieval combining multiple strategies"""
        # Get results from different strategies
        keyword_results = self._keyword_retrieve(query)
        semantic_results = self._semantic_retrieve(query)
        bm25_results = self._bm25_retrieve(query) if self.use_bm25 else []
        
        # Combine results with weighted scores
        combined_scores = {}
        
        # Weight different strategies
        keyword_weight = 0.3
        semantic_weight = 0.4
        bm25_weight = 0.3 if self.use_bm25 else 0
        
        # Normalize and combine keyword results
        for result in keyword_results:
            chunk_id = result.chunk.chunk_id
            combined_scores[chunk_id] = {
                'score': result.score * keyword_weight,
                'chunk': result.chunk,
                'reasons': [f"Keyword: {result.relevance_reason}"]
            }
        
        # Add semantic results
        for result in semantic_results:
            chunk_id = result.chunk.chunk_id
            if chunk_id in combined_scores:
                combined_scores[chunk_id]['score'] += result.score * semantic_weight
                combined_scores[chunk_id]['reasons'].append(f"Semantic: {result.relevance_reason}")
            else:
                combined_scores[chunk_id] = {
                    'score': result.score * semantic_weight,
                    'chunk': result.chunk,
                    'reasons': [f"Semantic: {result.relevance_reason}"]
                }
        
        # Add BM25 results
        if bm25_results:
            # Normalize BM25 scores
            max_bm25 = max(r.score for r in bm25_results) if bm25_results else 1
            for result in bm25_results:
                chunk_id = result.chunk.chunk_id
                normalized_score = result.score / max_bm25 if max_bm25 > 0 else 0
                if chunk_id in combined_scores:
                    combined_scores[chunk_id]['score'] += normalized_score * bm25_weight
                    combined_scores[chunk_id]['reasons'].append(f"BM25: {result.relevance_reason}")
                else:
                    combined_scores[chunk_id] = {
                        'score': normalized_score * bm25_weight,
                        'chunk': result.chunk,
                        'reasons': [f"BM25: {result.relevance_reason}"]
                    }
        
        # Convert to RetrievalResult objects
        results = []
        for chunk_id, data in combined_scores.items():
            results.append(RetrievalResult(
                chunk=data['chunk'],
                score=data['score'],
                strategy="hybrid",
                relevance_reason="; ".join(data['reasons'])
            ))
        
        # Sort by combined score
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:self.top_k]
    
    def _extract_phrases(self, text: str, min_length: int = 2, max_length: int = 4) -> List[str]:
        """Extract meaningful phrases from text"""
        words = re.findall(r'\b\w+\b', text.lower())
        phrases = []
        
        for i in range(len(words) - min_length + 1):
            for length in range(min_length, min(max_length + 1, len(words) - i + 1)):
                phrase = ' '.join(words[i:i+length])
                if len(phrase) > 5:  # Minimum phrase length
                    phrases.append(phrase)
        
        return phrases


def create_retriever_from_content(
    content: str,
    title: str = "",
    url: str = "",
    chunk_size: int = 1000,
    chunk_overlap: int = 200
) -> EnsembleRetriever:
    """
    Convenience function to create retriever from content.
    
    Args:
        content: Text content
        title: Document title
        url: Source URL
        chunk_size: Chunk size
        chunk_overlap: Chunk overlap
        
    Returns:
        EnsembleRetriever instance
    """
    from .document_chunker import chunk_intel_content
    
    chunks = chunk_intel_content(content, title, url, chunk_size, chunk_overlap)
    return EnsembleRetriever(chunks, use_semantic=True, use_bm25=True)

