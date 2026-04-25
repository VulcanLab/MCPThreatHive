"""
MCP Threat Platform - GitHub Data Source

Collects security-related content from GitHub:
- Security advisories
- Issues with security labels
- Code search for vulnerabilities
- Repositories with security content
"""

from __future__ import annotations

import os
import asyncio
import aiohttp
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from .base import DataSource, IntelItem, SourceType


class GitHubSource(DataSource):
    """
    GitHub intelligence source.
    
    Collects security-related content from GitHub API.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.source_type = SourceType.GITHUB
        self.source_name = "GitHub Security"
        
        config = config or {}
        
        # Configuration
        self.api_token = config.get('token') or os.getenv('GITHUB_TOKEN')
        self.api_base = "https://api.github.com"
        
        # Target repositories (configurable)
        self.target_repos = config.get('repos', [
            "anthropics/anthropic-cookbook",
            "modelcontextprotocol/servers",
            "modelcontextprotocol/specification"
        ])
        
        # Search labels
        self.security_labels = config.get('security_labels', [
            "security",
            "vulnerability",
            "injection",
            "bug",
            "CVE"
        ])
    
    def validate_config(self) -> bool:
        """Check if GitHub token is available"""
        return bool(self.api_token)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API headers"""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers
    
    async def collect(self, keywords: List[str], max_items: int = 50) -> List[IntelItem]:
        """
        Collect intelligence from GitHub.
        
        Args:
            keywords: Keywords to search for
            max_items: Maximum items to collect
            
        Returns:
            List of IntelItem objects
        """
        self.last_run = datetime.now(timezone.utc)
        items = []
        
        async with aiohttp.ClientSession(headers=self._get_headers()) as session:
            # Collect from multiple sources in parallel
            tasks = [
                self._search_security_advisories(session, keywords, max_items // 3),
                self._search_issues(session, keywords, max_items // 3),
                self._search_code(session, keywords, max_items // 3),
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    items.extend(result)
                elif isinstance(result, Exception):
                    print(f"[GitHub] Error: {result}")
        
        self.items_collected = len(items)
        return items[:max_items]
    
    async def _search_security_advisories(
        self, 
        session: aiohttp.ClientSession, 
        keywords: List[str],
        max_items: int
    ) -> List[IntelItem]:
        """Search GitHub security advisories"""
        items = []
        
        # Build query
        keyword_query = " OR ".join(keywords)
        query = f"{keyword_query} type:reviewed"
        
        url = f"{self.api_base}/advisories"
        params = {
            "q": query,
            "per_page": min(max_items, 30)
        }
        
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for advisory in data:
                        item = self._parse_advisory(advisory)
                        if item:
                            items.append(item)
        except Exception as e:
            print(f"[GitHub] Advisory search error: {e}")
        
        return items
    
    async def _search_issues(
        self, 
        session: aiohttp.ClientSession, 
        keywords: List[str],
        max_items: int
    ) -> List[IntelItem]:
        """Search GitHub issues with security labels"""
        items = []
        
        # Search across target repos and general
        keyword_query = " ".join(keywords)
        
        for repo in self.target_repos:
            query = f"repo:{repo} is:issue {keyword_query}"
            url = f"{self.api_base}/search/issues"
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": min(max_items // len(self.target_repos), 10)
            }
            
            try:
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for issue in data.get('items', []):
                            item = self._parse_issue(issue)
                            if item:
                                items.append(item)
            except Exception as e:
                print(f"[GitHub] Issue search error for {repo}: {e}")
        
        # Also search general security issues
        general_query = f"{keyword_query} label:security is:issue"
        url = f"{self.api_base}/search/issues"
        params = {
            "q": general_query,
            "sort": "updated",
            "order": "desc",
            "per_page": 10
        }
        
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for issue in data.get('items', []):
                        item = self._parse_issue(issue)
                        if item:
                            items.append(item)
        except Exception as e:
            print(f"[GitHub] General issue search error: {e}")
        
        return items
    
    async def _search_code(
        self, 
        session: aiohttp.ClientSession, 
        keywords: List[str],
        max_items: int
    ) -> List[IntelItem]:
        """Search GitHub code for security patterns"""
        items = []
        
        # Search for security-related code patterns
        security_patterns = [
            "prompt injection MCP",
            "tool poisoning MCP",
            "security vulnerability MCP"
        ]
        
        for pattern in security_patterns:
            url = f"{self.api_base}/search/code"
            params = {
                "q": pattern,
                "per_page": min(max_items // len(security_patterns), 5)
            }
            
            try:
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for code_result in data.get('items', []):
                            item = self._parse_code_result(code_result)
                            if item:
                                items.append(item)
            except Exception as e:
                print(f"[GitHub] Code search error: {e}")
        
        return items
    
    def _parse_advisory(self, data: Dict[str, Any]) -> Optional[IntelItem]:
        """Parse security advisory into IntelItem"""
        try:
            return self._create_item(
                title=data.get('summary', 'Security Advisory'),
                content=data.get('description', ''),
                summary=data.get('summary', ''),
                url=data.get('html_url', ''),
                author=data.get('publisher', {}).get('login', ''),
                published_at=datetime.fromisoformat(data['published_at'].replace('Z', '+00:00')) if data.get('published_at') else None,
                tags=[data.get('severity', 'unknown')],
                categories=['security_advisory'],
                raw_data=data
            )
        except Exception as e:
            print(f"[GitHub] Error parsing advisory: {e}")
            return None
    
    def _parse_issue(self, data: Dict[str, Any]) -> Optional[IntelItem]:
        """Parse issue into IntelItem"""
        try:
            labels = [l.get('name', '') for l in data.get('labels', [])]
            return self._create_item(
                title=data.get('title', ''),
                content=data.get('body', '') or '',
                summary=data.get('title', ''),
                url=data.get('html_url', ''),
                author=data.get('user', {}).get('login', ''),
                published_at=datetime.fromisoformat(data['created_at'].replace('Z', '+00:00')) if data.get('created_at') else None,
                tags=labels,
                categories=['github_issue'],
                raw_data=data
            )
        except Exception as e:
            print(f"[GitHub] Error parsing issue: {e}")
            return None
    
    def _parse_code_result(self, data: Dict[str, Any]) -> Optional[IntelItem]:
        """Parse code search result into IntelItem"""
        try:
            repo = data.get('repository', {})
            return self._create_item(
                title=f"Code: {data.get('name', '')} in {repo.get('full_name', '')}",
                content=f"Path: {data.get('path', '')}\nRepository: {repo.get('full_name', '')}",
                summary=f"Security-related code found in {repo.get('full_name', '')}",
                url=data.get('html_url', ''),
                author=repo.get('owner', {}).get('login', ''),
                tags=[repo.get('language', 'unknown')],
                categories=['code_search'],
                raw_data=data
            )
        except Exception as e:
            print(f"[GitHub] Error parsing code result: {e}")
            return None

