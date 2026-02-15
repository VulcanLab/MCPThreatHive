"""
Threat Hunting Module

Automated threat hunting that:
1. Periodically collects intelligence
2. Extracts threat patterns
3. Generates detection rules
4. Updates knowledge base
5. Discovers new threats
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path

from database.db_manager import get_db_manager
from core.threat_pattern_extractor import ThreatPatternExtractor
from core.rule_generator import DetectionRuleGenerator
from intel_integration.intel_pipeline import IntelPipeline, PipelineConfig
from intel_integration.intel_connector import IntelConnector


class ThreatHuntingEngine:
    """
    Automated threat hunting engine.
    
    Performs:
    - Intelligence gathering
    - Threat pattern extraction
    - Detection rule generation
    - Knowledge base updates
    """
    
    def __init__(self, project_id: str = 'default-project'):
        self.project_id = project_id
        self.db = get_db_manager()
        self.pattern_extractor = ThreatPatternExtractor()
        self.rule_generator = DetectionRuleGenerator()
        self.intel_pipeline = IntelPipeline(
            config=PipelineConfig(
                max_items_per_source=20,
                use_ai_processing=True,
                save_to_file=False
            ),
            db_manager=self.db
        )
        self.intel_connector = IntelConnector()
    
    async def hunt(
        self,
        topics: Optional[List[str]] = None,
        auto_generate_rules: bool = True,
        auto_update_knowledge: bool = True
    ) -> Dict[str, Any]:
        """
        Execute threat hunting run.
        
        Args:
            topics: Optional list of hunting topics
            auto_generate_rules: Automatically generate detection rules
            auto_update_knowledge: Automatically update threat knowledge base
            
        Returns:
            Hunting results dictionary
        """
        if topics is None:
            topics = [
                "MCP security vulnerability",
                "MCP prompt injection attack",
                "MCP tool poisoning",
                "MCP server exploit",
                "MCP authentication bypass"
            ]
        
        results = {
            "hunt_id": f"hunt-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "started_at": datetime.now().isoformat(),
            "topics": topics,
            "intel_items_collected": 0,
            "patterns_extracted": 0,
            "rules_generated": 0,
            "knowledge_updated": 0,
            "new_threats_discovered": 0,
            "errors": []
        }
        
        try:
            # Step 1: Gather intelligence
            print(f"[ThreatHunting] Starting hunt: {results['hunt_id']}")
            print(f"[ThreatHunting] Topics: {', '.join(topics)}")
            
            intel_items = []
            for topic in topics:
                try:
                    items = self.intel_connector.run_intel_gathering(
                        topic=topic,
                        max_items=20
                    )
                    intel_items.extend(items)
                except Exception as e:
                    results["errors"].append(f"Error gathering intel for '{topic}': {e}")
            
            results["intel_items_collected"] = len(intel_items)
            print(f"[ThreatHunting] Collected {len(intel_items)} intel items")
            
            # Step 2: Extract threat patterns
            patterns = []
            for item in intel_items:
                try:
                    text = f"{item.get('title', '')}\n{item.get('summary', '')}\n{item.get('full_content', item.get('snippet', ''))}"
                    if len(text.strip()) < 50:
                        continue
                    
                    pattern = self.pattern_extractor.extract_patterns(
                        text,
                        source_url=item.get('url')
                    )
                    
                    if pattern and pattern.get('threat_name'):
                        patterns.append({
                            "pattern": pattern,
                            "source": item
                        })
                except Exception as e:
                    results["errors"].append(f"Error extracting pattern: {e}")
            
            results["patterns_extracted"] = len(patterns)
            print(f"[ThreatHunting] Extracted {len(patterns)} threat patterns")
            
            # Step 3: Generate detection rules
            generated_rules = []
            if auto_generate_rules:
                for pattern_data in patterns:
                    try:
                        pattern = pattern_data["pattern"]
                        rules = self.rule_generator.generate_rules_from_pattern(
                            pattern,
                            rule_types=["static", "dynamic"]
                        )
                        
                        for rule_json in rules:
                            rule_data = {
                                "name": f"{pattern.get('threat_name', 'Unknown')} - {rule_json.get('type', 'static')}",
                                "description": f"Auto-generated {rule_json.get('type')} rule from threat hunting",
                                "rule_type": rule_json.get("type", "static"),
                                "rule_json": rule_json,
                                "target_component": pattern.get('attack_surface', 'server_side'),
                                "severity": pattern.get('severity', 'medium'),
                                "status": "draft",
                                "tags": ["threat-hunting", "auto-generated", pattern.get('attack_type', 'unknown'), f"hunt:{results['hunt_id']}"]
                            }
                            
                            rule = self.db.create_detection_rule(rule_data, project_id=self.project_id)
                            generated_rules.append(rule.to_dict())
                    except Exception as e:
                        results["errors"].append(f"Error generating rule: {e}")
            
            results["rules_generated"] = len(generated_rules)
            print(f"[ThreatHunting] Generated {len(generated_rules)} detection rules")
            
            # Step 4: Update threat knowledge base
            knowledge_updated = 0
            if auto_update_knowledge:
                for pattern_data in patterns:
                    try:
                        pattern = pattern_data["pattern"]
                        source = pattern_data["source"]
                        
                        # Check if threat already exists
                        existing = self.db.get_threat_knowledge(
                            filters={"title": pattern.get('threat_name')},
                            limit=1
                        )
                        
                        if existing:
                            continue  # Skip if already exists
                        
                        knowledge_data = {
                            "title": pattern.get('threat_name', 'Unknown Threat'),
                            "description": pattern.get('description', ''),
                            "attack_surface": pattern.get('attack_surface', 'server_side'),
                            "attack_type": pattern.get('attack_type', 'unknown'),
                            "indicators": json.dumps(pattern.get('indicators', [])),
                            "cve_ids": json.dumps(pattern.get('cve_ids', [])),
                            "cwe_ids": json.dumps(pattern.get('cwe_ids', [])),
                            "detection_methods": json.dumps(pattern.get('detection_methods', [])),
                            "mitigation": json.dumps(pattern.get('mitigation', [])),
                            "severity": pattern.get('severity', 'medium'),
                            "stride_category": pattern.get('stride_category', 'Tampering'),
                            "source": "threat_hunting",
                            "source_url": source.get('url'),
                            "status": "active",
                            "tags": json.dumps(["threat-hunting", "auto-generated", pattern.get('attack_type', 'unknown')]),
                            "references": json.dumps([{
                                "type": "hunt_metadata",
                                "hunt_id": results["hunt_id"],
                                "extracted_at": pattern.get('extracted_at'),
                                "source_title": source.get('title')
                            }])
                        }
                        
                        entry = self.db.create_threat_knowledge(knowledge_data, project_id=self.project_id)
                        knowledge_updated += 1
                    except Exception as e:
                        results["errors"].append(f"Error updating knowledge: {e}")
            
            results["knowledge_updated"] = knowledge_updated
            results["new_threats_discovered"] = knowledge_updated
            print(f"[ThreatHunting] Updated {knowledge_updated} threat knowledge entries")
            
            results["completed_at"] = datetime.now().isoformat()
            results["success"] = True
            
            print(f"[ThreatHunting] Hunt completed: {results['hunt_id']}")
            
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Hunt failed: {e}")
            import traceback
            results["traceback"] = traceback.format_exc()
            print(f"[ThreatHunting] Hunt failed: {e}")
        
        return results
    
    def get_hunt_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get threat hunting history from knowledge base metadata"""
        try:
            entries = self.db.get_threat_knowledge(
                filters={"source": "threat_hunting"},
                limit=limit
            )
            
            hunts = {}
            for entry in entries:
                # Try to extract hunt_id from source or tags
                hunt_id = None
                if entry.source and "hunt_" in entry.source:
                    # Extract hunt_id from source like "threat_hunting_hunt_12345"
                    parts = entry.source.split("_")
                    if len(parts) >= 3:
                        hunt_id = "_".join(parts[2:])
                elif entry.tags and isinstance(entry.tags, list):
                    # Try to find hunt_id in tags
                    for tag in entry.tags:
                        if isinstance(tag, str) and tag.startswith("hunt_"):
                            hunt_id = tag
                            break
                
                if not hunt_id:
                    # Generate a hunt_id from created_at date if no explicit hunt_id
                    if entry.created_at:
                        hunt_id = f"hunt_{entry.created_at.strftime('%Y%m%d')}"
                    else:
                        hunt_id = "hunt_unknown"
                
                if hunt_id not in hunts:
                    hunts[hunt_id] = {
                        "hunt_id": hunt_id,
                        "threats_discovered": 0,
                        "first_seen": entry.created_at.isoformat() if entry.created_at else None,
                        "last_seen": entry.updated_at.isoformat() if entry.updated_at else None
                    }
                hunts[hunt_id]["threats_discovered"] += 1
                if entry.created_at:
                    if not hunts[hunt_id]["first_seen"] or entry.created_at.isoformat() < hunts[hunt_id]["first_seen"]:
                        hunts[hunt_id]["first_seen"] = entry.created_at.isoformat()
            
            return list(hunts.values())
        except Exception as e:
            print(f"[ThreatHunting] Error getting history: {e}")
            import traceback
            traceback.print_exc()
            return []


async def run_threat_hunting(
    topics: Optional[List[str]] = None,
    project_id: str = 'default-project',
    auto_generate_rules: bool = True,
    auto_update_knowledge: bool = True
) -> Dict[str, Any]:
    """Convenience function to run threat hunting"""
    engine = ThreatHuntingEngine(project_id=project_id)
    return await engine.hunt(
        topics=topics,
        auto_generate_rules=auto_generate_rules,
        auto_update_knowledge=auto_update_knowledge
    )

