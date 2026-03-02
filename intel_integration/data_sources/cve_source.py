"""
MCP Threat Platform - CVE/NVD Data Source

Collects vulnerability information from:
- NIST NVD (National Vulnerability Database)
- CVE database
"""

from __future__ import annotations

import os
import asyncio
import aiohttp
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from .base import DataSource, IntelItem, SourceType


class CVESource(DataSource):
    """
    CVE/NVD intelligence source.
    
    Collects vulnerability data from NVD API.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.source_type = SourceType.CVE
        self.source_name = "NVD/CVE Database"
        
        config = config or {}
        
        # NVD API configuration
        self.api_key = config.get('api_key') or os.getenv('NVD_API_KEY')
        self.api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Search within recent days
        self.days_back = config.get('days_back', 90)
        
        # Keywords for AI/LLM related CVEs
        self.default_keywords = [
            "llm",
            "language model",
            "prompt injection",
            "ai",
            "artificial intelligence",
            "machine learning",
            "chatbot",
            "natural language"
        ]
    
    def validate_config(self) -> bool:
        """NVD API works without key but rate limited"""
        return True
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API headers"""
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers
    
    async def collect(self, keywords: List[str], max_items: int = 50) -> List[IntelItem]:
        """
        Collect CVE/vulnerability data.
        
        Args:
            keywords: Keywords to search for
            max_items: Maximum items to collect
            
        Returns:
            List of IntelItem objects
        """
        self.last_run = datetime.now(timezone.utc)
        items = []
        
        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=self.days_back)
        
        # Use provided keywords or defaults
        search_keywords = keywords if keywords else self.default_keywords
        
        async with aiohttp.ClientSession(headers=self._get_headers()) as session:
            # Search for each keyword
            for keyword in search_keywords[:5]:  # Limit to avoid rate limiting
                try:
                    # Check if event loop is still running
                    loop = asyncio.get_running_loop()
                    if loop.is_closed():
                        print(f"[CVE] Event loop closed, stopping collection")
                        break
                    
                    keyword_items = await self._search_cves(
                        session, 
                        keyword,
                        start_date,
                        end_date,
                        max_items // len(search_keywords[:5])
                    )
                    items.extend(keyword_items)
                    
                    # Rate limiting (NVD requires delays between requests)
                    await asyncio.sleep(0.6 if not self.api_key else 0.1)
                    
                except RuntimeError as e:
                    if "cannot schedule new futures after shutdown" in str(e) or "Event loop is closed" in str(e):
                        print(f"[CVE] Event loop shutdown detected, stopping collection")
                        break
                    raise
                except Exception as e:
                    print(f"[CVE] Error searching for '{keyword}': {e}")
        
        # Deduplicate by CVE ID
        seen_cves = set()
        unique_items = []
        for item in items:
            cve_id = item.raw_data.get('cve', {}).get('id', item.id)
            if cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_items.append(item)
        
        self.items_collected = len(unique_items)
        return unique_items[:max_items]
    
    async def _search_cves(
        self,
        session: aiohttp.ClientSession,
        keyword: str,
        start_date: datetime,
        end_date: datetime,
        max_results: int
    ) -> List[IntelItem]:
        """Search NVD for CVEs matching keyword"""
        items = []
        
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": min(max_results, 100)
        }
        
        try:
            async with session.get(self.api_base, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        item = self._parse_cve(vuln)
                        if item:
                            items.append(item)
                            
                elif resp.status == 403:
                    print("[CVE] Rate limited by NVD API")
                else:
                    print(f"[CVE] API error: {resp.status}")
                    
        except Exception as e:
            print(f"[CVE] Request error: {e}")
        
        return items
    
    def _parse_cve(self, data: Dict[str, Any]) -> Optional[IntelItem]:
        """Parse CVE data into IntelItem"""
        try:
            cve = data.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Get description (prefer English)
            descriptions = cve.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')
            
            # Get CVSS score
            metrics = cve.get('metrics', {})
            cvss_score = None
            severity = "unknown"
            
            # Try CVSS 3.1 first, then 3.0, then 2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'unknown').lower()
                    break
            
            # Get references
            references = cve.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references[:5]]
            
            # Get weaknesses (CWE)
            weaknesses = cve.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value', ''))
            
            # Published date
            published = cve.get('published')
            published_at = None
            if published:
                try:
                    published_at = datetime.fromisoformat(published.replace('Z', '+00:00'))
                except:
                    pass
            
            return self._create_item(
                title=f"{cve_id}: {description[:100]}..." if len(description) > 100 else f"{cve_id}: {description}",
                content=description,
                summary=f"CVE {cve_id} - Severity: {severity.upper()}" + (f" (CVSS: {cvss_score})" if cvss_score else ""),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_at=published_at,
                tags=[severity, cve_id] + cwe_ids,
                categories=['cve', 'vulnerability'],
                raw_data={
                    'cve': cve,
                    'cvss_score': cvss_score,
                    'severity': severity,
                    'references': ref_urls,
                    'cwe_ids': cwe_ids
                }
            )
            
        except Exception as e:
            print(f"[CVE] Error parsing CVE: {e}")
            return None

