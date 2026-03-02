"""
MCP Threat Platform - Intelligence Pipeline

Complete automated pipeline for threat intelligence:
1. AI generates search queries (no hardcoded keywords)
2. DuckDuckGo searches the entire web
3. AI processes and filters results
4. Convert to threat schema
5. Store in database
6. Generate threat cards

Key Design Principles:
- No hardcoded keywords - AI generates all search queries
- Universal search - not limited to specific websites
- Flexible configuration - everything is customizable
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .ai_keyword_generator import AIKeywordGenerator
from .data_sources import (
    DataSource, IntelItem,
    GitHubSource, CVESource, RSSSource, WebSearchSource
)
from .ai_processor import AIIntelProcessor, ProcessedIntel


@dataclass
class PipelineConfig:
    """Pipeline configuration - all settings are customizable"""
    
    # Source toggles
    enable_github: bool = False  # Requires API token
    enable_cve: bool = True
    enable_rss: bool = True
    enable_web_search: bool = True  # Primary search method
    
    # AI Query Generation
    use_ai_keywords: bool = True  # Use AI to generate search queries
    ai_keyword_focus: str = "MCP server client proxy attack techniques vulnerabilities exploits security incidents"
    ai_queries_count: int = 20  # Number of AI-generated queries
    
    # Fallback keywords (used if AI is disabled) - Focused on MCP attacks, exploits, and security events
    fallback_keywords: List[str] = field(default_factory=lambda: [
        "MCP server vulnerability exploit",
        "MCP client attack technique",
        "MCP proxy security issue",
        "MCP tool injection attack",
        "MCP server CVE vulnerability",
        "MCP client exploit POC",
        "MCP proxy bypass attack",
        "Model Context Protocol security incident",
        "MCP server privilege escalation",
        "MCP client data exfiltration",
        "MCP proxy SSRF attack",
        "MCP tool poisoning exploit",
        "MCP server authentication bypass",
        "MCP client sandbox escape",
        "MCP security vulnerability report"
    ])
    
    # Processing configuration
    use_ai_processing: bool = True
    relevance_threshold: float = 0.6
    max_items_per_source: int = 30
    
    # Rate limiting
    min_delay_between_requests: float = 1.5
    
    # Output
    output_dir: Optional[Path] = None
    save_to_file: bool = False


@dataclass
class PipelineResult:
    """Results from a pipeline run"""
    run_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Query generation
    queries_generated: List[str] = field(default_factory=list)
    
    # Collection stats
    sources_used: List[str] = field(default_factory=list)
    items_collected: int = 0
    items_processed: int = 0
    items_relevant: int = 0
    threats_generated: int = 0
    
    # Results
    threats: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'run_id': self.run_id,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'queries_generated': self.queries_generated,
            'sources_used': self.sources_used,
            'items_collected': self.items_collected,
            'items_processed': self.items_processed,
            'items_relevant': self.items_relevant,
            'threats_generated': self.threats_generated,
            'errors': self.errors
        }


class IntelPipeline:
    """
    Complete intelligence pipeline with AI-powered query generation.
    
    This is the main entry point for threat intelligence gathering.
    It uses AI to generate search queries and DuckDuckGo to search the web.
    """
    
    def __init__(
        self,
        config: Optional[PipelineConfig] = None,
        llm_client=None,
        db_manager=None,
        model: Optional[str] = None,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        provider: Optional[str] = None
    ):
        """
        Initialize pipeline.
        
        Args:
            config: Pipeline configuration (uses defaults if not provided)
            llm_client: LLM client for AI processing
            db_manager: Database manager for storage
            model: LLM model name
            api_base: LLM API base URL
            api_key: LLM API key
            provider: LLM provider name (e.g. 'ollama', 'gemini', 'litellm')
        """
        self.config = config or PipelineConfig()
        self.llm_client = llm_client
        self.db_manager = db_manager
        
        # AI Keyword Generator
        self.keyword_generator = AIKeywordGenerator(
            model=model,
            api_base=api_base,
            api_key=api_key,
            provider=provider
        )
        
        # Initialize sources
        self.sources: Dict[str, DataSource] = {}
        self._init_sources()
        
        # AI Processor
        self.processor = AIIntelProcessor(
            llm_client=llm_client,
            config={
                'relevance_threshold': self.config.relevance_threshold
            },
            model=model,
            api_base=api_base,
            api_key=api_key,
            provider=provider
        )
    
    def _init_sources(self):
        """Initialize data sources based on configuration"""
        if self.config.enable_github:
            self.sources['github'] = GitHubSource()
        
        if self.config.enable_cve:
            self.sources['cve'] = CVESource()
        
        if self.config.enable_rss:
            self.sources['rss'] = RSSSource()
        
        if self.config.enable_web_search:
            self.sources['web_search'] = WebSearchSource(
                max_results_per_query=10,
                include_news=True
            )
    
    def _generate_search_queries(
        self,
        custom_keywords: Optional[List[str]] = None,
        focus: Optional[str] = None
    ) -> List[str]:
        """
        Generate search queries using AI.
        
        Args:
            custom_keywords: User-provided keywords to include
            focus: Custom focus area (uses config default if not provided)
            
        Returns:
            List of search queries
        """
        queries = []
        
        # Use AI to generate queries
        if self.config.use_ai_keywords:
            try:
                focus_area = focus or self.config.ai_keyword_focus
                print(f"   🤖 AI generating queries for: {focus_area[:50]}...")
                
                ai_queries = self.keyword_generator.generate_mcp_search_queries(
                    focus=focus_area,
                    num_queries=self.config.ai_queries_count
                )
                
                if ai_queries:
                    queries.extend(ai_queries)
                    print(f"   ✓ AI generated {len(ai_queries)} search queries")
                else:
                    print(f"   ⚠️ AI query generation returned empty list")
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                print(f"   ⚠️ AI query generation failed: {e}")
                print(f"   ⚠️ Error trace: {error_trace[:300]}")
        
        # Add custom keywords
        if custom_keywords:
            queries.extend(custom_keywords)
        
        # Fallback if no queries generated
        if not queries:
            print("   ⚠️ Using fallback keywords")
            queries = self.config.fallback_keywords.copy()
        
        # Clean, filter, and deduplicate queries
        seen = set()
        unique_queries = []
        for q in queries:
            if not q:
                continue
            # Clean the query
            q = str(q).strip()
            # Filter out invalid queries
            if (len(q) <= 2 or  # Too short
                q.startswith('\\') or  # Just escape char
                q == ',' or  # Just comma
                re.match(r'^[,\\s]+$', q) or  # Just punctuation/whitespace
                q.startswith(',') or  # Starts with comma
                q.endswith('\\')):  # Ends with escape
                continue
            # Deduplicate
            if q not in seen:
                seen.add(q)
                unique_queries.append(q)
        
        return unique_queries
    
    async def run(
        self,
        keywords: Optional[List[str]] = None,
        focus: Optional[str] = None
    ) -> PipelineResult:
        """
        Run the complete pipeline.
        
        Args:
            keywords: Optional custom keywords to include
            focus: Optional custom focus area for AI query generation
            
        Returns:
            PipelineResult with statistics and generated threats
        """
        result = PipelineResult(
            run_id=str(uuid.uuid4())[:8],
            started_at=datetime.now(timezone.utc)
        )
        
        print(f"\n{'='*60}")
        print(f"🚀 MCP Threat Intel Pipeline - Run {result.run_id}")
        print(f"{'='*60}")
        
        try:
            # Step 1: Generate search queries
            print("\n🔑 Step 1: Generating search queries...")
            queries = self._generate_search_queries(keywords, focus)
            result.queries_generated = queries
            print(f"   Total queries: {len(queries)}")
            
            # Show some example queries
            for q in queries[:5]:
                print(f"   • {q[:60]}{'...' if len(q) > 60 else ''}")
            if len(queries) > 5:
                print(f"   • ... and {len(queries) - 5} more")
            
            # Step 2: Collect from all sources (with dynamic query expansion)
            print("\n📡 Step 2: Collecting intelligence...")
            target_count = self.config.max_items_per_source * len(self.sources)
            
            # Dynamic Collection Loop
            all_items = []
            seen_urls = set()
            current_queries = queries
            
            # Initialize extractors once
            extractor = None
            rule_generator = None
            if self.db_manager:
                try:
                    from core.threat_pattern_extractor import ThreatPatternExtractor
                    from core.rule_generator import DetectionRuleGenerator
                    extractor = ThreatPatternExtractor()
                    rule_generator = DetectionRuleGenerator()
                except ImportError:
                    pass

            # Try up to 3 iterations to reach target count
            for iteration in range(3):
                if iteration > 0:
                    print(f"\n🔄 Iteration {iteration + 1}: Expanding search to reach target ({len(all_items)}/{target_count})...")
                
                # Collect batch
                batch_target = target_count - len(all_items)
                if batch_target <= 0:
                    break
                    
                batch_items = await self._collect_all_with_dedup(current_queries, batch_target)
                
                # Add unique items and PROCESS IMMEDIATELY
                new_batch_items = []
                for item in batch_items:
                    if item.url and item.url not in seen_urls:
                        seen_urls.add(item.url)
                        all_items.append(item)
                        new_batch_items.append(item)
                
                if new_batch_items:
                    print(f"   ✓ Collected {len(new_batch_items)} new items in iteration {iteration + 1}")
                    
                    # === IMMEDIATE PROCESSING ===
                    print(f"   🧠 Processing {len(new_batch_items)} new items immediately...")
                    processed_batch = await self.processor.process_batch(
                        new_batch_items,
                        use_ai=self.config.use_ai_processing,
                        use_gemini_filter=True
                    )
                    
                    # Update stats
                    result.items_processed += len(new_batch_items)
                    result.items_relevant += len(processed_batch)
                    
                    # Convert to threats and save IMMEDIATELY
                    if processed_batch:
                        new_threats = [item.to_threat_dict() for item in processed_batch]
                        result.threats.extend(new_threats)
                        result.threats_generated += len(new_threats)
                        
                        # Save to DB if manager exists
                        if self.db_manager:
                            try:
                                # This ensures the frontend sees new threats instantly
                                print(f"   💾 Saving {len(new_threats)} threats to database...")
                                
                                # Store processed intel items (updates AI summaries)
                                await self._store_processed_intel_items(processed_batch, new_batch_items)
                                
                                # Store threats (updates Threat table)
                                await self._store_threats(new_threats)
                                
                                # Extract threat patterns and update knowledge base IMMEDIATELY
                                if extractor:
                                    print(f"   🔍 Extracting patterns from {len(processed_batch)} items...")
                                    for item in processed_batch:
                                        try:
                                            # Combine content for pattern extraction
                                            text = f"{item.original.title}\n{item.summary}\n{item.original.summary or ''}"
                                            if len(text.strip()) < 50:
                                                continue
                                            
                                            # Extract pattern
                                            pattern = extractor.extract_patterns(text, source_url=item.original.url)
                                            if not pattern or not pattern.get('threat_name'):
                                                continue
                                            
                                            # Check if already exists in knowledge base
                                            existing = self.db_manager.get_threat_knowledge(
                                                filters={"title": pattern.get('threat_name')},
                                                limit=1
                                            )
                                            if existing:
                                                continue
                                            
                                            # Store in knowledge base
                                            cve_list = pattern.get('cve_ids', [])
                                            cve_val = cve_list[0] if cve_list and isinstance(cve_list, list) else None
                                            cwe_list = pattern.get('cwe_ids', [])
                                            cwe_val = cwe_list[0] if cwe_list and isinstance(cwe_list, list) else None
                                            
                                            knowledge_data = {
                                                "title": pattern.get('threat_name', 'Unknown Threat'),
                                                "description": pattern.get('description', ''),
                                                "surface": pattern.get('attack_surface', 'server_side'),
                                                "attack_type": pattern.get('attack_type', 'unknown'),
                                                "ioc": pattern.get('indicators', []),
                                                "cve": cve_val,
                                                "cwe": cwe_val,
                                                "detections": pattern.get('detection_methods', []),
                                                "mitigations": pattern.get('mitigation', []),
                                                "severity": pattern.get('severity', 'medium'),
                                                "source": "intel_pipeline",
                                                "source_url": item.original.url,
                                                "status": "active",
                                                "tags": ["intel-pipeline", "auto-generated", pattern.get('attack_type', 'unknown')],
                                                "references": [{
                                                    "type": "pipeline_metadata",
                                                    "extracted_at": pattern.get('extracted_at'),
                                                    "source_title": item.original.title,
                                                    "source_url": item.original.url
                                                }]
                                            }
                                            
                                            self.db_manager.create_threat_knowledge(knowledge_data, project_id='default-project')
                                            
                                            # Generate rules if rule_generator exists
                                            if rule_generator:
                                                pass # Rule generation logic can remain if needed, or be skipped for speed
                                                
                                        except Exception as e:
                                            print(f"   ⚠️ Error extracting pattern from item: {e}")
                                            
                            except Exception as e:
                                print(f"   ⚠️ Error saving batch to database: {e}")
                
                # Check if we need more
                if len(all_items) >= target_count:
                    print(f"   ✅ Target count reached ({len(all_items)} items)")
                    break
                
                # Refine queries for next iteration
                if iteration < 2 and len(all_items) > 0:
                    print("   🧠 Analyzing results to generate better queries...")
                    current_queries = self.keyword_generator.refine_queries(
                        current_queries,
                        [{'title': i.title, 'url': i.url} for i in all_items[-10:]],
                        focus or self.config.ai_keyword_focus
                    )
                    print(f"   ✓ Generated {len(current_queries)} refined queries for next pass")
                    for q in current_queries[:3]:
                        print(f"     • {q}")
                elif iteration < 2:
                    print("   ⚠️ No results found. Generating fallback broad queries...")
                    current_queries = [
                        "MCP protocol security",
                        "Model Context Protocol vulnerability",
                        "MCP server exploit github",
                        "MCP security research",
                        "LLM tool injection attack"
                    ]
            
            result.items_collected = len(all_items)
            result.sources_used = list(self.sources.keys())
            print(f"\n   ✓ Final Collection: {result.items_collected} unique items from {len(result.sources_used)} sources")
            
            # (Skipping original Steps 3, 4, 4.5 as they are now done incrementally)
            print("\n✅ Pipeline processing completed incrementally.")

            
            # Step 5: Store intel items and threats in database (if available)

            
            # Step 6: Save to file (optional)
            if self.config.save_to_file and self.config.output_dir:
                print("\n📁 Step 6: Saving to file...")
                filepath = self._save_results(result)
                print(f"   ✓ Saved to {filepath}")
            
            # Step 7: Learn from results (improve future queries)
            # Query refinement is now handled incrementally inside the loop
            pass
            
        except Exception as e:
            result.errors.append(str(e))
            print(f"\n❌ Pipeline error: {e}")
            import traceback
            traceback.print_exc()
        
        result.completed_at = datetime.now(timezone.utc)
        
        # Print summary
        duration = (result.completed_at - result.started_at).total_seconds()
        print(f"\n{'='*60}")
        print(f"✅ Pipeline completed in {duration:.1f}s")
        print(f"   Queries: {len(result.queries_generated)}")
        print(f"   Collected: {result.items_collected}")
        print(f"   Relevant: {result.items_relevant}")
        print(f"   Threats: {result.threats_generated}")
        if result.errors:
            print(f"   Errors: {len(result.errors)}")
        print(f"{'='*60}\n")
        
        return result
    
    async def run_stride_focused(
        self,
        stride_categories: Optional[List[str]] = None
    ) -> PipelineResult:
        """
        Run pipeline focused on specific STRIDE categories.
        
        Args:
            stride_categories: List of STRIDE categories to focus on
            
        Returns:
            PipelineResult with generated threats
        """
        categories = stride_categories or [
            "Spoofing",
            "Tampering", 
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege"
        ]
        
        all_queries = []
        
        for category in categories:
            queries = self.keyword_generator.generate_stride_queries(
                stride_category=category,
                num_queries=5
            )
            all_queries.extend(queries)
        
        return await self.run(keywords=all_queries)
    
    async def run_attack_focused(
        self,
        attack_techniques: Optional[List[str]] = None
    ) -> PipelineResult:
        """
        Run pipeline focused on specific attack techniques.
        
        Args:
            attack_techniques: List of attack techniques to research
            
        Returns:
            PipelineResult with generated threats
        """
        techniques = attack_techniques or [
            "prompt injection",
            "tool poisoning",
            "context manipulation",
            "sandbox bypass",
            "data exfiltration"
        ]
        
        all_queries = []
        
        for technique in techniques:
            queries = self.keyword_generator.generate_attack_technique_queries(
                technique=technique,
                num_queries=5
            )
            all_queries.extend(queries)
        
        return await self.run(keywords=all_queries)
    
    async def _collect_all(self, queries: List[str]) -> List[IntelItem]:
        """Collect from all enabled sources"""
        all_items = []
        
        for name, source in self.sources.items():
            if not source.enabled:
                continue
            
            if not source.validate_config():
                print(f"   ⚠️ {name}: Invalid configuration, skipping")
                continue
            
            try:
                # Check if event loop is still running
                try:
                    loop = asyncio.get_running_loop()
                    if loop.is_closed():
                        print(f"   ⚠️ {name}: Event loop closed, skipping")
                        continue
                except RuntimeError:
                    print(f"   ⚠️ {name}: No event loop, skipping")
                    continue
                
                items = await asyncio.wait_for(
                    source.collect(queries, self.config.max_items_per_source),
                    timeout=90
                )
                all_items.extend(items)
                print(f"   📥 {name}: {len(items)} items")
            except RuntimeError as e:
                if "cannot schedule new futures after shutdown" in str(e) or "Event loop is closed" in str(e):
                    print(f"   ⚠️ {name}: Event loop shutdown, stopping collection")
                    break
                print(f"   ⚠️ {name}: Runtime error - {e}")
            except asyncio.TimeoutError:
                print(f"   ⏰ {name}: Timeout")
            except Exception as e:
                print(f"   ⚠️ {name}: Error - {e}")
        
        return all_items
    
    async def _collect_all_with_dedup(self, queries: List[str], target_count: int) -> List[IntelItem]:
        """Collect from all enabled sources with deduplication, ensuring target count"""
        from database.models import IntelItem as DBIntelItem
        
        # Get existing URLs from database to avoid duplicates
        existing_urls = set()
        if self.db_manager:
            session = self.db_manager.get_session()
            try:
                existing_items = session.query(DBIntelItem).all()
                existing_urls = {item.url for item in existing_items if item.url}
            finally:
                session.close()
        
        all_items = []
        seen_urls = set(existing_urls)  # Track URLs we've seen in this collection
        max_attempts = 3  # Maximum collection attempts per source
        items_per_source = target_count // max(len(self.sources), 1)
        
        for name, source in self.sources.items():
            if not source.enabled:
                continue
            
            if not source.validate_config():
                print(f"   ⚠️ {name}: Invalid configuration, skipping")
                continue
            
            # Collect items from this source, trying multiple times if needed
            collected_from_source = 0
            attempt = 0
            
            while collected_from_source < items_per_source and attempt < max_attempts:
                try:
                    # Check if event loop is still running
                    try:
                        loop = asyncio.get_running_loop()
                        if loop.is_closed():
                            print(f"   ⚠️ {name}: Event loop closed, stopping retry")
                            break
                    except RuntimeError:
                        print(f"   ⚠️ {name}: No event loop, stopping retry")
                        break
                    
                    # Calculate how many more items we need
                    needed = items_per_source - collected_from_source
                    # Request more items to account for duplicates
                    request_count = int(needed * 1.5) + 10
                    
                    items = await asyncio.wait_for(
                        source.collect(queries, request_count),
                        timeout=90
                    )
                    
                    # Filter out duplicates
                    new_items = []
                    for item in items:
                        if item.url and item.url not in seen_urls:
                            seen_urls.add(item.url)
                            new_items.append(item)
                            collected_from_source += 1
                            
                            # Stop if we've reached target for this source
                            if collected_from_source >= items_per_source:
                                break
                    
                    all_items.extend(new_items)
                    
                    if new_items:
                        print(f"   📥 {name}: {len(new_items)} new items (attempt {attempt + 1})")
                    
                    # If we got enough unique items, move to next source
                    if collected_from_source >= items_per_source:
                        break
                    
                    # If we got some items but not enough, try again
                    if len(new_items) > 0:
                        attempt += 1
                        await asyncio.sleep(2)  # Brief delay before retry
                    else:
                        # No new items found, stop trying this source
                        break
                        
                except RuntimeError as e:
                    if "cannot schedule new futures after shutdown" in str(e) or "Event loop is closed" in str(e):
                        print(f"   ⚠️ {name}: Event loop shutdown, stopping retry")
                        break
                    print(f"   ⚠️ {name}: Runtime error - {e} (attempt {attempt + 1})")
                    attempt += 1
                except asyncio.TimeoutError:
                    print(f"   ⏰ {name}: Timeout (attempt {attempt + 1})")
                    attempt += 1
                except Exception as e:
                    print(f"   ⚠️ {name}: Error - {e} (attempt {attempt + 1})")
                    attempt += 1
            
            if collected_from_source > 0:
                print(f"   ✓ {name}: Total {collected_from_source} unique items collected")
        
        # If we still don't have enough items, try collecting more from all sources
        if len(all_items) < target_count:
            print(f"   ℹ️ Collected {len(all_items)}/{target_count} items, attempting to collect more...")
            additional_needed = target_count - len(all_items)
            
            for name, source in self.sources.items():
                if not source.enabled or len(all_items) >= target_count:
                    break
                
                # Check if event loop is still running
                try:
                    loop = asyncio.get_running_loop()
                    if loop.is_closed():
                        print(f"   ⚠️ {name}: Event loop closed, stopping additional collection")
                        break
                except RuntimeError:
                    print(f"   ⚠️ {name}: No event loop, stopping additional collection")
                    break
                
                try:
                    items = await asyncio.wait_for(
                        source.collect(queries, additional_needed * 2),
                        timeout=90
                    )
                    
                    new_items = []
                    for item in items:
                        if item.url and item.url not in seen_urls:
                            seen_urls.add(item.url)
                            new_items.append(item)
                            if len(all_items) + len(new_items) >= target_count:
                                break
                    
                    all_items.extend(new_items)
                    if new_items:
                        print(f"   📥 {name}: Additional {len(new_items)} items")
                    
                except Exception as e:
                    import traceback
                    print(f"   ⚠️ {name}: Additional collection error - {repr(e)}")
                    # traceback.print_exc() # Uncomment for debugging
        
        return all_items[:target_count]  # Return up to target count
    
    async def _store_processed_intel_items(
        self,
        processed_items: List,
        raw_items: List[IntelItem]
    ) -> int:
        """Store processed intel items with AI summaries"""
        from database.models import IntelItem as DBIntelItem
        from .ai_processor import ProcessedIntel
        
        # Create mapping from original item to processed item
        processed_map = {p.original.id: p for p in processed_items if isinstance(p, ProcessedIntel)}
        
        stored = 0
        skipped = 0
        updated = 0
        
        for item in raw_items:
            try:
                session = self.db_manager.get_session()
                try:
                    # Use URL as primary deduplication key
                    if item.url:
                        existing = session.query(DBIntelItem).filter(
                            DBIntelItem.url == item.url
                        ).first()
                        
                        if existing:
                            # Update existing item with AI summary if available
                            processed = processed_map.get(item.id)
                            if processed and processed.ai_summary:
                                existing.ai_summary = processed.ai_summary
                                existing.ai_relevance_score = processed.relevance_score
                                existing.is_relevant = processed.is_relevant
                                existing.is_processed = True
                                existing.ai_threat_type = processed.stride_category
                                existing.ai_stride_category = processed.stride_category
                                session.commit()
                                updated += 1
                            else:
                                skipped += 1
                            continue
                    
                    # Get processed data if available
                    processed = processed_map.get(item.id)
                    
                    # Create new intel item
                    item_data = {
                        'id': item.id,
                        'title': item.title,
                        'content': item.content or item.summary or '',
                        'url': item.url,
                        'source_type': item.source_type.value,
                        'source_date': item.published_at,
                        'author': item.author,
                        'ai_relevance_score': processed.relevance_score if processed else item.relevance_score,
                        'is_relevant': processed.is_relevant if processed else item.is_relevant,
                        'is_processed': True if processed else item.is_processed,
                        'ai_summary': processed.ai_summary if processed else None,
                        'ai_threat_type': processed.stride_category if processed else None,
                        'ai_stride_category': processed.stride_category if processed else None,
                        'raw_data': item.to_dict()
                    }
                    
                    self.db_manager.create_intel_item(item_data)
                    stored += 1
                finally:
                    session.close()
                    
            except Exception as e:
                print(f"   ⚠️ Failed to store intel item: {e}")
        
        if skipped > 0:
            print(f"   ℹ️ Skipped {skipped} duplicate items (safety check)")
        if updated > 0:
            print(f"   ℹ️ Updated {updated} existing items with AI summaries")
        
        return stored
    
    async def _store_threats(self, threats: List[Dict[str, Any]]) -> int:
        """Store threats in database with deduplication"""
        from database.models import Threat
        stored = 0
        skipped = 0
        
        for threat_data in threats:
            try:
                # Check if threat already exists
                session = self.db_manager.get_session()
                exists = False
                try:
                    # Check by source URL first (most reliable)
                    if threat_data.get('source_url'):
                        existing = session.query(Threat).filter(
                            Threat.source_url == threat_data['source_url'],
                            Threat.project_id == 'default-project'
                        ).first()
                        if existing:
                            exists = True
                    
                    # Fallback to name check
                    if not exists and threat_data.get('name'):
                        existing = session.query(Threat).filter(
                            Threat.name == threat_data['name'],
                            Threat.project_id == 'default-project'
                        ).first()
                        if existing:
                            exists = True
                finally:
                    session.close()
                
                if exists:
                    skipped += 1
                    continue
                
                self.db_manager.create_threat(threat_data, project_id='default-project')
                stored += 1
            except Exception as e:
                print(f"   ⚠️ Failed to store threat: {e}")
        
        if skipped > 0:
            print(f"   ℹ️ Skipped {skipped} duplicate threats")
        
        return stored
    
    def _save_results(self, result: PipelineResult) -> Path:
        """Save results to file"""
        output_dir = self.config.output_dir or Path("data/intel_results")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = output_dir / f"intel_run_{result.run_id}_{timestamp}.json"
        
        data = {
            'metadata': result.to_dict(),
            'threats': result.threats
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def get_source_status(self) -> Dict[str, Any]:
        """Get status of all sources"""
        return {
            name: source.get_status()
            for name, source in self.sources.items()
        }


class ScheduledIntelPipeline:
    """
    Scheduled intelligence pipeline.
    
    Runs the pipeline on a schedule (e.g., hourly, daily).
    """
    
    def __init__(
        self,
        pipeline: IntelPipeline,
        interval_hours: int = 24
    ):
        self.pipeline = pipeline
        self.interval_hours = interval_hours
        self.running = False
        self._task = None
    
    async def start(self):
        """Start the scheduled pipeline"""
        self.running = True
        self._task = asyncio.create_task(self._run_loop())
        print(f"🕐 Scheduled pipeline started (every {self.interval_hours}h)")
    
    async def stop(self):
        """Stop the scheduled pipeline"""
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print("🛑 Scheduled pipeline stopped")
    
    async def _run_loop(self):
        """Main scheduling loop"""
        while self.running:
            try:
                await self.pipeline.run()
            except Exception as e:
                print(f"❌ Scheduled run error: {e}")
            
            # Wait for next run
            await asyncio.sleep(self.interval_hours * 3600)


# ==================== Convenience Functions ====================

async def run_intel_pipeline(
    keywords: Optional[List[str]] = None,
    focus: Optional[str] = None,
    use_ai: bool = True,
    use_ai_keywords: bool = True,
    db_manager=None,
    llm_client=None
) -> PipelineResult:
    """
    Run the intel pipeline with default configuration.
    
    Args:
        keywords: Custom keywords to include
        focus: Focus area for AI query generation
        use_ai: Whether to use AI processing
        use_ai_keywords: Whether to use AI for keyword generation
        db_manager: Database manager for storage
        llm_client: LLM client for AI processing
        
    Returns:
        PipelineResult with generated threats
    """
    config = PipelineConfig(
        use_ai_processing=use_ai,
        use_ai_keywords=use_ai_keywords
    )
    
    pipeline = IntelPipeline(
        config=config,
        llm_client=llm_client,
        db_manager=db_manager
    )
    
    return await pipeline.run(keywords=keywords, focus=focus)


def run_intel_pipeline_sync(
    keywords: Optional[List[str]] = None,
    focus: Optional[str] = None,
    use_ai: bool = True,
    use_ai_keywords: bool = True,
    db_manager=None,
    llm_client=None
) -> PipelineResult:
    """Synchronous wrapper for run_intel_pipeline"""
    return asyncio.run(
        run_intel_pipeline(
            keywords=keywords,
            focus=focus,
            use_ai=use_ai,
            use_ai_keywords=use_ai_keywords,
            db_manager=db_manager,
            llm_client=llm_client
        )
    )


# Quick test function
async def quick_test():
    """Quick test of the pipeline"""
    config = PipelineConfig(
        use_ai_keywords=True,
        use_ai_processing=False,  # Disable AI processing for quick test
        enable_github=False,
        enable_cve=False,
        enable_rss=False,
        enable_web_search=True,
        ai_queries_count=5,
        max_items_per_source=10
    )
    
    pipeline = IntelPipeline(config=config)
    result = await pipeline.run()
    
    print("\n📋 Sample Results:")
    for threat in result.threats[:3]:
        print(f"  - {threat.get('name', 'Unknown')[:60]}")
        print(f"    URL: {threat.get('source_url', 'N/A')[:50]}")


if __name__ == "__main__":
    asyncio.run(quick_test())
