"""
MCP Threat Platform - RSS Feed Data Source

Collects security content from RSS feeds:
- Security blogs
- ArXiv papers
- News feeds
"""

from __future__ import annotations

import asyncio
import aiohttp
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from html import unescape
import re

from .base import DataSource, IntelItem, SourceType


class RSSSource(DataSource):
    """
    RSS/Atom feed intelligence source.
    
    Collects content from configured security RSS feeds.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.source_type = SourceType.RSS
        self.source_name = "RSS Feeds"
        
        config = config or {}
        
        # Default security RSS feeds
        self.feeds = config.get('feeds', [
            # ArXiv CS Security
            {
                "name": "ArXiv CS.CR",
                "url": "http://export.arxiv.org/rss/cs.CR",
                "type": "arxiv"
            },
            # ArXiv AI
            {
                "name": "ArXiv CS.AI",
                "url": "http://export.arxiv.org/rss/cs.AI",
                "type": "arxiv"
            },
            # Security blogs
            {
                "name": "Krebs on Security",
                "url": "https://krebsonsecurity.com/feed/",
                "type": "blog"
            },
            {
                "name": "The Hacker News",
                "url": "https://feeds.feedburner.com/TheHackersNews",
                "type": "news"
            },
            {
                "name": "Schneier on Security",
                "url": "https://www.schneier.com/feed/atom/",
                "type": "blog"
            }
        ])
    
    def validate_config(self) -> bool:
        """Check if feeds are configured"""
        return len(self.feeds) > 0
    
    async def collect(self, keywords: List[str], max_items: int = 50) -> List[IntelItem]:
        """
        Collect from RSS feeds and filter by keywords.
        
        Args:
            keywords: Keywords to filter content
            max_items: Maximum items to collect
            
        Returns:
            List of IntelItem objects
        """
        self.last_run = datetime.now(timezone.utc)
        items = []
        
        async with aiohttp.ClientSession() as session:
            # Collect from all feeds in parallel
            tasks = [
                self._fetch_feed(session, feed, keywords, max_items // len(self.feeds))
                for feed in self.feeds
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    items.extend(result)
                elif isinstance(result, Exception):
                    print(f"[RSS] Feed error: {result}")
        
        self.items_collected = len(items)
        return items[:max_items]
    
    async def _fetch_feed(
        self,
        session: aiohttp.ClientSession,
        feed: Dict[str, str],
        keywords: List[str],
        max_items: int
    ) -> List[IntelItem]:
        """Fetch and parse a single RSS feed"""
        items = []
        
        try:
            async with session.get(feed['url'], timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    # Parse RSS/Atom
                    parsed_items = self._parse_feed(content, feed)
                    
                    # Filter by keywords
                    for item in parsed_items:
                        if self._matches_keywords(item, keywords):
                            items.append(item)
                        
                        if len(items) >= max_items:
                            break
                            
        except asyncio.TimeoutError:
            print(f"[RSS] Timeout fetching {feed['name']}")
        except Exception as e:
            print(f"[RSS] Error fetching {feed['name']}: {e}")
        
        return items
    
    def _parse_feed(self, content: str, feed: Dict[str, str]) -> List[IntelItem]:
        """Parse RSS/Atom feed content"""
        items = []
        
        try:
            root = ET.fromstring(content)
            
            # Handle different feed formats
            if root.tag == '{http://www.w3.org/2005/Atom}feed' or 'Atom' in root.tag:
                items = self._parse_atom(root, feed)
            else:
                items = self._parse_rss(root, feed)
                
        except ET.ParseError as e:
            print(f"[RSS] Parse error for {feed['name']}: {e}")
        
        return items
    
    def _parse_rss(self, root: ET.Element, feed: Dict[str, str]) -> List[IntelItem]:
        """Parse RSS 2.0 format"""
        items = []
        
        channel = root.find('channel')
        if channel is None:
            return items
        
        for item in channel.findall('item'):
            try:
                title = item.find('title')
                description = item.find('description')
                link = item.find('link')
                pub_date = item.find('pubDate')
                author = item.find('author') or item.find('{http://purl.org/dc/elements/1.1/}creator')
                
                # Parse categories
                categories = []
                for cat in item.findall('category'):
                    if cat.text:
                        categories.append(cat.text)
                
                # Parse date
                published_at = None
                if pub_date is not None and pub_date.text:
                    published_at = self._parse_date(pub_date.text)
                
                intel_item = self._create_item(
                    title=self._clean_html(title.text) if title is not None and title.text else "",
                    content=self._clean_html(description.text) if description is not None and description.text else "",
                    summary=self._clean_html(title.text) if title is not None and title.text else "",
                    url=link.text if link is not None and link.text else "",
                    source_url=feed['url'],
                    author=author.text if author is not None and author.text else "",
                    published_at=published_at,
                    tags=[feed.get('type', 'rss')],
                    categories=categories
                )
                intel_item.source_name = feed['name']
                items.append(intel_item)
                
            except Exception as e:
                print(f"[RSS] Error parsing item: {e}")
        
        return items
    
    def _parse_atom(self, root: ET.Element, feed: Dict[str, str]) -> List[IntelItem]:
        """Parse Atom format"""
        items = []
        ns = {'atom': 'http://www.w3.org/2005/Atom'}
        
        for entry in root.findall('atom:entry', ns) or root.findall('{http://www.w3.org/2005/Atom}entry'):
            try:
                title = entry.find('atom:title', ns) or entry.find('{http://www.w3.org/2005/Atom}title')
                summary = entry.find('atom:summary', ns) or entry.find('{http://www.w3.org/2005/Atom}summary')
                content = entry.find('atom:content', ns) or entry.find('{http://www.w3.org/2005/Atom}content')
                link = entry.find('atom:link', ns) or entry.find('{http://www.w3.org/2005/Atom}link')
                published = entry.find('atom:published', ns) or entry.find('{http://www.w3.org/2005/Atom}published')
                updated = entry.find('atom:updated', ns) or entry.find('{http://www.w3.org/2005/Atom}updated')
                author_elem = entry.find('atom:author/atom:name', ns) or entry.find('{http://www.w3.org/2005/Atom}author/{http://www.w3.org/2005/Atom}name')
                
                # Get link href
                link_url = ""
                if link is not None:
                    link_url = link.get('href', '')
                
                # Parse date
                published_at = None
                date_elem = published or updated
                if date_elem is not None and date_elem.text:
                    published_at = self._parse_date(date_elem.text)
                
                # Get content
                content_text = ""
                if content is not None and content.text:
                    content_text = self._clean_html(content.text)
                elif summary is not None and summary.text:
                    content_text = self._clean_html(summary.text)
                
                intel_item = self._create_item(
                    title=self._clean_html(title.text) if title is not None and title.text else "",
                    content=content_text,
                    summary=self._clean_html(summary.text) if summary is not None and summary.text else "",
                    url=link_url,
                    source_url=feed['url'],
                    author=author_elem.text if author_elem is not None and author_elem.text else "",
                    published_at=published_at,
                    tags=[feed.get('type', 'atom')],
                    categories=[]
                )
                intel_item.source_name = feed['name']
                items.append(intel_item)
                
            except Exception as e:
                print(f"[RSS] Error parsing Atom entry: {e}")
        
        return items
    
    def _clean_html(self, text: str) -> str:
        """Remove HTML tags and unescape entities"""
        if not text:
            return ""
        
        # Unescape HTML entities
        text = unescape(text)
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Clean whitespace
        text = ' '.join(text.split())
        
        return text.strip()
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse various date formats"""
        formats = [
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        
        return None
    
    def _matches_keywords(self, item: IntelItem, keywords: List[str]) -> bool:
        """Check if item matches any keyword"""
        if not keywords:
            return True
        
        text = f"{item.title} {item.content} {item.summary}".lower()
        return any(kw.lower() in text for kw in keywords)

