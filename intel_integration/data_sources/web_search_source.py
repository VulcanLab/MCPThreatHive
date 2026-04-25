#!/usr/bin/env python3
"""
Universal Web Search Source using DuckDuckGo

This module provides a flexible web search capability using DuckDuckGo
as the search engine. It's not limited to specific websites - AI generates
queries and DuckDuckGo searches the entire web.

Features:
- Universal web search (not limited to specific sites)
- Text search for general content
- News search for recent developments
- Multiple search modes
- Rate limiting and error handling
- Proxy support (including Tor)
"""

from __future__ import annotations

import os
import time
import random
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import warnings

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*duckduckgo_search.*")
warnings.filterwarnings("ignore", message=".*has been renamed.*")

from .base import DataSource, IntelItem, SourceType

# Initialize DDGS
DDGS = None
DDGS_AVAILABLE = False

try:
    # Try ddgs package (newer, recommended)
    from ddgs import DDGS as _DDGS
    DDGS = _DDGS
    DDGS_AVAILABLE = True
except ImportError:
    try:
        # Fallback to duckduckgo_search package
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from duckduckgo_search import DDGS as _DDGS
            DDGS = _DDGS
            DDGS_AVAILABLE = True
    except ImportError:
        DDGS_AVAILABLE = False


class WebSearchSource(DataSource):
    """
    Universal web search using DuckDuckGo.
    
    This is the primary search mechanism - AI generates queries,
    DuckDuckGo searches the entire web, and results are processed.
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        proxy: Optional[str] = None,
        timeout: int = 20,
        max_results_per_query: int = 10,
        include_news: bool = True
    ):
        """
        Initialize web search source.
        
        Args:
            config: Configuration dictionary
            proxy: Proxy URL (http/https/socks5, or "tb" for Tor Browser)
            timeout: Request timeout in seconds
            max_results_per_query: Max results per search query
            include_news: Include news search in addition to text search
        """
        super().__init__(config)
        self.source_type = SourceType.WEB_SEARCH
        self.source_name = "DuckDuckGo Web Search"
        
        # Get proxy from environment if not provided
        if not proxy:
            proxy = os.getenv("DDGS_PROXY")
        
        # Support Tor Browser alias
        if proxy == "tb":
            proxy = "socks5://127.0.0.1:9150"
        
        self.proxy = proxy
        self.timeout = timeout
        self.max_results_per_query = max_results_per_query
        self.include_news = include_news
        
        # Rate limiting
        self.last_request_time = 0
        self.min_delay = 1.5  # Minimum delay between requests (seconds)
        
        # Statistics
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
    
    def validate_config(self) -> bool:
        """Check if DDGS is available"""
        return DDGS_AVAILABLE
    
    def _get_ddgs(self) -> DDGS:
        """
        Get DDGS instance with current settings.
        
        Returns:
            DDGS instance
        """
        if not DDGS_AVAILABLE:
            raise ImportError(
                "ddgs package not available. "
                "Install with: pip install ddgs"
            )
        
        # DDGS initialization - new ddgs library doesn't need proxy in constructor
        # Proxy is handled at request level if needed
        return DDGS()
    
    def _rate_limit(self):
        """Apply rate limiting between requests."""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < self.min_delay:
            sleep_time = self.min_delay - elapsed + random.uniform(0.1, 0.5)
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def search_text(
        self,
        query: str,
        max_results: Optional[int] = None,
        region: str = "wt-wt",  # Worldwide
        safesearch: str = "moderate",
        timelimit: Optional[str] = None  # d=day, w=week, m=month, y=year
    ) -> List[Dict[str, Any]]:
        """
        Perform text search.
        
        Args:
            query: Search query
            max_results: Maximum number of results
            region: Region for search (default: worldwide)
            safesearch: Safe search level
            timelimit: Time limit for results
            
        Returns:
            List of search results
        """
        max_results = max_results or self.max_results_per_query
        results = []
        
        try:
            self._rate_limit()
            self.total_requests += 1
            
            ddgs = self._get_ddgs()
            
            # Use text() method for search (ddgs library)
            # Returns a list of dictionaries with 'title', 'href', 'body'
            search_results = list(ddgs.text(
                query,
                max_results=max_results
            ))
            
            # Process results
            for result in search_results:
                # Filter out results without body/content
                if not result.get("body"):
                    continue
                
                results.append({
                    "title": result.get("title", ""),
                    "url": result.get("href", result.get("link", "")),
                    "snippet": result.get("body", ""),
                    "source": "duckduckgo_text",
                    "query": query,
                    "timestamp": datetime.now().isoformat()
                })
            
            self.successful_requests += 1
            
        except Exception as e:
            self.failed_requests += 1
            error_msg = str(e)
            if "Ratelimit" in error_msg:
                print(f"[WebSearch] ⚠️ Rate limit hit for '{query[:30]}...'. Backing off...")
                time.sleep(5) # Wait 5 seconds
            elif "timed out" in error_msg:
                print(f"[WebSearch] Text search timed out for '{query[:30]}...'")
            elif "dns error" in error_msg or "nodename nor servname" in error_msg:
                print(f"[WebSearch] DNS/Connection error for '{query[:30]}...'")
            else:
                # Truncate long error messages
                if len(error_msg) > 100:
                    error_msg = error_msg[:97] + "..."
                print(f"[WebSearch] Text search failed for '{query[:30]}...': {error_msg}")
        
        return results
    
    def search_news(
        self,
        query: str,
        max_results: Optional[int] = None,
        region: str = "wt-wt",
        safesearch: str = "moderate",
        timelimit: Optional[str] = "m"  # Default: last month
    ) -> List[Dict[str, Any]]:
        """
        Perform news search for recent content.
        
        Args:
            query: Search query
            max_results: Maximum number of results
            region: Region for search
            safesearch: Safe search level
            timelimit: Time limit (d=day, w=week, m=month)
            
        Returns:
            List of news results
        """
        max_results = max_results or self.max_results_per_query
        results = []
        
        try:
            self._rate_limit()
            self.total_requests += 1
            
            ddgs = self._get_ddgs()
            
            # Use news() method (ddgs library)
            news_results = list(ddgs.news(
                query,
                max_results=max_results
            ))
            
            # Process results - ddgs returns dicts with 'title', 'url', 'body', etc.
            for result in news_results:
                results.append({
                    "title": result.get("title", ""),
                    "url": result.get("url", result.get("link", "")),
                    "snippet": result.get("body", result.get("excerpt", "")),
                    "source": "duckduckgo_news",
                    "date": result.get("date", ""),
                    "publisher": result.get("source", ""),
                    "query": query,
                    "timestamp": datetime.now().isoformat()
                })
            
            self.successful_requests += 1
            
        except Exception as e:
            self.failed_requests += 1
            error_msg = str(e)
            if "Ratelimit" in error_msg:
                print(f"[WebSearch] ⚠️ Rate limit hit for '{query[:30]}...'. Backing off...")
                time.sleep(5) # Wait 5 seconds
            elif "timed out" in error_msg:
                print(f"[WebSearch] News search timed out for '{query[:30]}...'")
            elif "dns error" in error_msg or "nodename nor servname" in error_msg:
                print(f"[WebSearch] DNS/Connection error for '{query[:30]}...'")
            else:
                # Truncate long error messages
                if len(error_msg) > 100:
                    error_msg = error_msg[:97] + "..."
                print(f"[WebSearch] News search failed for '{query[:30]}...': {error_msg}")
        
        return results
    
    async def collect(self, keywords: List[str], max_items: int = 50) -> List[IntelItem]:
        """
        Collect intelligence items from web search.
        
        This is the async method required by DataSource interface.
        AI generates queries, DuckDuckGo searches the entire web.
        
        Args:
            keywords: List of search queries (generated by AI or user-provided)
            max_items: Maximum total items to return
            
        Returns:
            List of IntelItem objects
        """
        self.last_run = datetime.now(timezone.utc)
        items = []
        
        if not DDGS_AVAILABLE:
            print("[WebSearch] DuckDuckGo package not available")
            return items
        
        seen_urls = set()
        
        # Calculate items per query
        items_per_query = max(3, max_items // max(1, len(keywords) * 2))
        
        for query in keywords:
            if len(items) >= max_items:
                break
            
            # Run synchronous search in thread to avoid blocking
            try:
                # Check if event loop is still running
                loop = asyncio.get_running_loop()
                if loop.is_closed():
                    print(f"[WebSearch] Event loop closed, stopping collection")
                    break
                
                text_results = await asyncio.to_thread(
                    self.search_text, query, items_per_query
                )
                
                for result in text_results:
                    url = result.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        item = self._create_item(
                            title=result.get("title", ""),
                            content=result.get("snippet", ""),
                            summary=result.get("snippet", "")[:200],
                            url=url,
                            tags=["web_search", result.get("query", "")[:30]],
                            categories=["web_search"],
                            raw_data=result
                        )
                        items.append(item)
            except RuntimeError as e:
                if "cannot schedule new futures after shutdown" in str(e) or "Event loop is closed" in str(e):
                    print(f"[WebSearch] Event loop shutdown detected, stopping collection")
                    break
                raise
            
            # News search (if enabled)
            if self.include_news and len(items) < max_items:
                try:
                    # Check if event loop is still running
                    loop = asyncio.get_running_loop()
                    if loop.is_closed():
                        print(f"[WebSearch] Event loop closed, stopping news collection")
                        break
                    
                    news_results = await asyncio.to_thread(
                        self.search_news, query, items_per_query // 2
                    )
                    
                    for result in news_results:
                        url = result.get("url", "")
                        if url and url not in seen_urls:
                            seen_urls.add(url)
                            item = self._create_item(
                                title=result.get("title", ""),
                                content=result.get("snippet", ""),
                                summary=result.get("snippet", "")[:200],
                                url=url,
                                author=result.get("publisher", ""),
                                tags=["news", result.get("query", "")[:30]],
                                categories=["news"],
                                raw_data=result
                            )
                            items.append(item)
                except RuntimeError as e:
                    if "cannot schedule new futures after shutdown" in str(e) or "Event loop is closed" in str(e):
                        print(f"[WebSearch] Event loop shutdown detected, stopping news collection")
                        break
                    raise
        
        self.items_collected = len(items)
        return items[:max_items]
    
    def get_status(self) -> Dict[str, Any]:
        """Get source status and statistics."""
        base_status = super().get_status()
        base_status.update({
            "available": DDGS_AVAILABLE,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (
                self.successful_requests / self.total_requests * 100
                if self.total_requests > 0 else 0
            ),
            "proxy_enabled": bool(self.proxy),
            "include_news": self.include_news
        })
        return base_status


class DuckDuckGoSearch:
    """
    Standalone DuckDuckGo search class for direct usage.
    
    This is a simplified interface similar to ollama-internet-search-tool.
    """
    
    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 20
    ):
        """Initialize DuckDuckGo search client."""
        self.source = WebSearchSource(
            proxy=proxy,
            timeout=timeout
        )
    
    def search(
        self,
        query: str,
        max_results: int = 10,
        include_news: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Search DuckDuckGo.
        
        Args:
            query: Search query
            max_results: Maximum results
            include_news: Include news search
            
        Returns:
            List of search results
        """
        results = self.source.search_text(query, max_results=max_results)
        
        if include_news:
            news = self.source.search_news(query, max_results=max_results // 2)
            results.extend(news)
        
        return results
    
    def search_text(self, query: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """Perform text search."""
        return self.source.search_text(query, max_results=max_results)
    
    def search_news(self, query: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """Perform news search."""
        return self.source.search_news(query, max_results=max_results)
