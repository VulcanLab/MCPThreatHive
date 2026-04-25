"""
MCP Threat Classifier
Maps threats to MCP Threat IDs (MCP-01 to MCP-38)
Also maps to OWASP Top 10 for LLM Applications and OWASP Agentic Top 10
"""

from typing import Optional, List, Dict, Any
import re


# OWASP Top 10 for LLM Applications (2025)
OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data & Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "Insecure Plugins",
    "LLM08": "Vector & Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP Top 10 for Agentic AI (2026)
OWASP_AGENTIC_TOP10 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# MCP Threat ID to OWASP LLM Top 10 mapping
MCP_TO_OWASP_LLM = {
    "MCP-01": ["LLM02", "LLM06"],  # Identity Spoofing -> Sensitive Info, Excessive Agency
    "MCP-02": ["LLM02"],  # Credential Theft -> Sensitive Info
    "MCP-03": ["LLM05"],  # Replay Attacks -> Improper Output Handling
    "MCP-04": ["LLM06"],  # Privilege Escalation -> Excessive Agency
    "MCP-05": ["LLM06"],  # Excessive Permissions -> Excessive Agency
    "MCP-06": ["LLM08"],  # Multitenancy Failure -> Vector & Embedding Weaknesses
    "MCP-07": ["LLM05"],  # Command Injection -> Improper Output Handling
    "MCP-08": ["LLM05"],  # Path Traversal -> Improper Output Handling
    "MCP-09": ["LLM01", "LLM05"],  # Web Vulnerabilities -> Prompt Injection, Improper Output Handling
    "MCP-10": ["LLM03"],  # Tool Description Poisoning -> Supply Chain Vulnerabilities
    "MCP-11": ["LLM04"],  # Full Schema Poisoning -> Data & Model Poisoning
    "MCP-12": ["LLM04"],  # Resource Content Poisoning -> Data & Model Poisoning
    "MCP-13": ["LLM03"],  # Tool Shadowing -> Supply Chain Vulnerabilities
    "MCP-14": ["LLM03"],  # Cross-Server Tool Shadowing -> Supply Chain Vulnerabilities
    "MCP-15": ["LLM01"],  # Preference Manipulation -> Prompt Injection
    "MCP-16": ["LLM03"],  # Rug Pull -> Supply Chain Vulnerabilities
    "MCP-17": ["LLM06"],  # Parasitic Toolchain -> Excessive Agency
    "MCP-18": ["LLM03"],  # Shadow MCP Servers -> Supply Chain Vulnerabilities
    "MCP-19": ["LLM01"],  # Direct Prompt Injection -> Prompt Injection
    "MCP-20": ["LLM01", "LLM04"],  # Indirect Prompt Injection -> Prompt Injection, Data & Model Poisoning
    "MCP-21": ["LLM09"],  # Overreliance on LLM Safeguards -> Misinformation
    "MCP-22": ["LLM06"],  # Insecure HITL Bypass -> Excessive Agency
    "MCP-23": ["LLM06"],  # Approval Fatigue -> Excessive Agency
    "MCP-24": ["LLM02"],  # Data Exfiltration -> Sensitive Information Disclosure
    "MCP-25": ["LLM02"],  # Privacy Inversion -> Sensitive Information Disclosure
    "MCP-26": ["LLM03"],  # Supply Chain Compromise -> Supply Chain Vulnerabilities
    "MCP-27": ["LLM03"],  # Missing Integrity -> Supply Chain Vulnerabilities
    "MCP-28": ["LLM07"],  # MITM -> Insecure Plugins
    "MCP-29": ["LLM07"],  # Protocol Gaps -> Insecure Plugins
    "MCP-30": ["LLM05"],  # stdio Handling -> Improper Output Handling
    "MCP-31": ["LLM03"],  # DNS Rebinding -> Supply Chain Vulnerabilities
    "MCP-32": ["LLM06"],  # Lateral Movement -> Excessive Agency
    "MCP-33": ["LLM10"],  # Resource Exhaustion -> Unbounded Consumption
    "MCP-34": ["LLM03"],  # Tool Manifest Recon -> Supply Chain Vulnerabilities
    "MCP-35": ["LLM09"],  # Agent Logic Drift -> Misinformation
    "MCP-36": ["LLM01"],  # Multi-Agent Hijacking -> Prompt Injection
    "MCP-37": ["LLM05"],  # Sandbox Escape -> Improper Output Handling
    "MCP-38": ["LLM06"],  # No Observability -> Excessive Agency
}

# MCP Threat ID to OWASP Agentic Top 10 mapping (2026)
MCP_TO_OWASP_AGENTIC = {
    "MCP-01": ["ASI03", "ASI07"],  # Identity Spoofing -> Identity & Privilege Abuse, Insecure Inter-Agent Communication
    "MCP-02": ["ASI03"],           # Credential Theft -> Identity & Privilege Abuse
    "MCP-03": ["ASI09"],           # Replay Attacks -> Human-Agent Trust Exploitation
    "MCP-04": ["ASI02", "ASI03"], # Privilege Escalation -> Tool Misuse & Exploitation, Identity & Privilege Abuse
    "MCP-05": ["ASI02", "ASI05"], # Excessive Permissions -> Tool Misuse & Exploitation, Unexpected Code Execution
    "MCP-06": ["ASI08"],           # Multitenancy Failure -> Cascading Failures
    "MCP-07": ["ASI05"],           # Command Injection -> Unexpected Code Execution (RCE)
    "MCP-08": ["ASI05"],           # Path Traversal -> Unexpected Code Execution
    "MCP-09": ["ASI01", "ASI09"], # Web Vulnerabilities -> Agent Goal Hijack, Human-Agent Trust Exploitation
    "MCP-10": ["ASI04"],           # Tool Description Poisoning -> Agentic Supply Chain Vulnerabilities
    "MCP-11": ["ASI06"],           # Full Schema Poisoning -> Memory & Context Poisoning
    "MCP-12": ["ASI06"],           # Resource Content Poisoning -> Memory & Context Poisoning
    "MCP-13": ["ASI04"],           # Tool Shadowing -> Agentic Supply Chain Vulnerabilities
    "MCP-14": ["ASI04"],           # Cross-Server Tool Shadowing -> Agentic Supply Chain Vulnerabilities
    "MCP-15": ["ASI01"],           # Preference Manipulation -> Agent Goal Hijack
    "MCP-16": ["ASI04", "ASI10"], # Rug Pull -> Agentic Supply Chain Vulnerabilities, Rogue Agents
    "MCP-17": ["ASI02"],           # Parasitic Toolchain -> Tool Misuse & Exploitation
    "MCP-18": ["ASI04"],           # Shadow MCP Servers -> Agentic Supply Chain Vulnerabilities
    "MCP-19": ["ASI01"],           # Direct Prompt Injection -> Agent Goal Hijack
    "MCP-20": ["ASI06"],           # Indirect Prompt Injection -> Memory & Context Poisoning
    "MCP-21": ["ASI09"],           # Overreliance on LLM Safeguards -> Human-Agent Trust Exploitation
    "MCP-22": ["ASI09"],           # Insecure HITL Bypass -> Human-Agent Trust Exploitation
    "MCP-23": ["ASI09"],           # Approval Fatigue -> Human-Agent Trust Exploitation
    "MCP-24": ["ASI02"],           # Data Exfiltration -> Tool Misuse & Exploitation
    "MCP-25": ["ASI06"],           # Privacy Inversion -> Memory & Context Poisoning
    "MCP-26": ["ASI04"],           # Supply Chain Compromise -> Agentic Supply Chain Vulnerabilities
    "MCP-27": ["ASI04"],           # Missing Integrity -> Agentic Supply Chain Vulnerabilities
    "MCP-28": ["ASI07"],           # MITM -> Insecure Inter-Agent Communication
    "MCP-29": ["ASI07"],           # Protocol Gaps -> Insecure Inter-Agent Communication
    "MCP-30": ["ASI05"],           # stdio Handling -> Unexpected Code Execution
    "MCP-31": ["ASI04"],           # DNS Rebinding -> Agentic Supply Chain Vulnerabilities
    "MCP-32": ["ASI08"],           # Lateral Movement -> Cascading Failures
    "MCP-33": ["ASI08"],           # Resource Exhaustion -> Cascading Failures
    "MCP-34": ["ASI04"],           # Tool Manifest Recon -> Agentic Supply Chain Vulnerabilities
    "MCP-35": ["ASI10"],           # Agent Logic Drift -> Rogue Agents
    "MCP-36": ["ASI07"],           # Multi-Agent Hijacking -> Insecure Inter-Agent Communication
    "MCP-37": ["ASI05"],           # Sandbox Escape -> Unexpected Code Execution
    "MCP-38": ["ASI10"],           # No Observability -> Rogue Agents
}

# MCP Threat ID to name mapping
MCP_THREAT_MAP = {
    "MCP-01": "Identity Spoofing / Improper Authentication",
    "MCP-02": "Credential Theft / Token Theft",
    "MCP-03": "Replay Attacks / Session Hijacking",
    "MCP-04": "Privilege Escalation & Confused Deputy",
    "MCP-05": "Excessive Permissions / Overexposure",
    "MCP-06": "Improper Multitenancy & Isolation Failure",
    "MCP-07": "Command Injection",
    "MCP-08": "File System Exposure / Path Traversal",
    "MCP-09": "Traditional Web Vulnerabilities (SSRF, XSS)",
    "MCP-10": "Tool Description Poisoning",
    "MCP-11": "Full Schema Poisoning (FSP)",
    "MCP-12": "Resource Content Poisoning",
    "MCP-13": "Tool Shadowing / Name Spoofing",
    "MCP-14": "Cross-Server Tool Shadowing",
    "MCP-15": "Preference Manipulation Attack (PMPA)",
    "MCP-16": "Rug Pull / Dynamic Behavior Change",
    "MCP-17": "Parasitic Toolchain / Connector Chaining",
    "MCP-18": "Shadow MCP Servers",
    "MCP-19": "Prompt Injection (Direct)",
    "MCP-20": "Prompt Injection (Indirect via Data)",
    "MCP-21": "Overreliance on LLM Safeguards",
    "MCP-22": "Insecure Human-in-the-Loop Bypass",
    "MCP-23": "Consent / Approval Fatigue",
    "MCP-24": "Data Exfiltration via Tool Output",
    "MCP-25": "Privacy Inversion / Data Aggregation Leakage",
    "MCP-26": "Supply Chain Compromise",
    "MCP-27": "Missing Integrity Verification",
    "MCP-28": "Man-in-the-Middle / Transport Tampering",
    "MCP-29": "Protocol Gaps / Weak Transport Security",
    "MCP-30": "Insecure stdio Descriptor Handling",
    "MCP-31": "MCP Endpoint / DNS Rebinding",
    "MCP-32": "Unrestricted Network Access & Lateral Movement",
    "MCP-33": "Resource Exhaustion / Denial of Wallet",
    "MCP-34": "Tool Manifest Reconnaissance",
    "MCP-35": "Planning / Agent Logic Drift",
    "MCP-36": "Multi-Agent Context Hijacking",
    "MCP-37": "Sandbox Escape",
    "MCP-38": "Invisible Agent Activity / No Observability",
}

# OWASP LLM Top 10 keyword patterns for classification
OWASP_LLM_KEYWORDS = {
    "LLM01": ["prompt injection", "jailbreak", "crafted input", "manipulating llm", "prompt attack", "instruction injection", "system prompt", "ignore previous"],
    "LLM02": ["insecure output", "output handling", "unvalidated output", "code execution", "xss", "sql injection", "command injection", "output sanitization"],
    "LLM03": ["training data", "data poisoning", "poisoned data", "tampered training", "model training", "fine-tuning attack", "backdoor model"],
    "LLM04": ["denial of service", "dos", "resource exhaustion", "model dos", "overload", "excessive tokens", "context flooding"],
    "LLM05": ["supply chain", "third-party", "dependency", "malicious package", "compromised component", "upstream", "plugin vulnerability"],
    "LLM06": ["sensitive information", "data leak", "pii", "credential exposure", "information disclosure", "privacy leak", "confidential data"],
    "LLM07": ["insecure plugin", "plugin design", "tool vulnerability", "insufficient access control", "remote code execution", "rce", "plugin exploit"],
    "LLM08": ["excessive agency", "autonomous action", "unchecked autonomy", "unintended action", "agent authority", "autonomous decision"],
    "LLM09": ["overreliance", "blind trust", "uncritical acceptance", "human oversight", "verification failure", "hallucination trust"],
    "LLM10": ["model theft", "model extraction", "intellectual property", "proprietary model", "model stealing", "weight extraction"],
}

# OWASP Agentic Top 10 (2026) keyword patterns for classification
OWASP_AGENTIC_KEYWORDS = {
    "ASI01": ["goal hijack", "agent goal", "behavior hijacking", "decision manipulation", "agent takeover", "goal hijacking", "agent control", "agent redirected"],
    "ASI02": ["tool misuse", "tool exploitation", "tool chaining", "api abuse", "function abuse", "unintended tool use", "tool hijack", "parasitic tool"],
    "ASI03": ["identity abuse", "privilege abuse", "credential theft", "impersonation", "privilege escalation", "unauthorized access", "token theft", "identity spoofing"],
    "ASI04": ["supply chain", "malicious package", "registry poison", "tool description poisoning", "tool shadowing", "server shadow", "agentic supply chain", "dependency attack"],
    "ASI05": ["unexpected code execution", "rce", "remote code execution", "sandbox escape", "container escape", "path traversal", "stdio hijack", "breakout"],
    "ASI06": ["memory poisoning", "context poisoning", "indirect prompt injection", "resource content poisoning", "schema poisoning", "knowledge poisoning", "data aggregation leakage", "privacy inversion"],
    "ASI07": ["inter-agent", "insecure communication", "multi-agent", "agent communication", "context hijacking", "transport tampering", "protocol gap", "mitm", "man-in-the-middle"],
    "ASI08": ["cascading failure", "resource exhaustion", "denial of service", "dos attack", "cost attack", "denial of wallet", "lateral movement", "multitenancy failure"],
    "ASI09": ["human-agent trust", "approval fatigue", "consent fatigue", "hitl bypass", "human-in-the-loop bypass", "overreliance", "blindly approve", "safeguard bypass"],
    "ASI10": ["rogue agent", "agent logic drift", "planning drift", "logic drift", "no observability", "no audit", "rogue", "invisible activity", "unmonitored agent"],
}

# Keyword patterns for MCP threat classification
THREAT_KEYWORDS = {
    "MCP-01": ["identity spoofing", "improper authentication", "weak authentication", "absent authentication", "impersonate"],
    "MCP-02": ["credential theft", "token theft", "oauth token", "api key", "secret", "stolen"],
    "MCP-03": ["replay attack", "session hijacking", "intercepted token", "session identifier", "reused"],
    "MCP-04": ["privilege escalation", "confused deputy", "unauthorized elevated permissions", "delegation abuse"],
    "MCP-05": ["excessive permissions", "overexposure", "overly broad permissions", "overprivileged"],
    "MCP-06": ["multitenancy", "isolation failure", "cross-tenant", "tenant isolation"],
    "MCP-07": ["command injection", "rce", "remote code execution", "shell command", "subprocess", "os.system", "exec"],
    "MCP-08": ["path traversal", "directory traversal", "file system exposure", "../", "..\\", "unauthorized file access"],
    "MCP-09": ["ssrf", "xss", "cross-site scripting", "server-side request forgery", "web vulnerability"],
    "MCP-10": ["tool description poisoning", "tool metadata", "hidden instruction", "tool description"],
    "MCP-11": ["full schema poisoning", "fsp", "schema poisoning", "tool schema", "structural poisoning"],
    "MCP-12": ["resource content poisoning", "indirect prompt injection", "poisoned document", "poisoned database"],
    "MCP-13": ["tool shadowing", "name spoofing", "tool name collision", "mimic legitimate"],
    "MCP-14": ["cross-server tool shadowing", "server override", "intercept tool call"],
    "MCP-15": ["preference manipulation", "pmpa", "tool metadata bias", "llm decision"],
    "MCP-16": ["rug pull", "dynamic behavior change", "silent update", "tool redefinition"],
    "MCP-17": ["parasitic toolchain", "connector chaining", "tool chaining", "bypass control"],
    "MCP-18": ["shadow mcp server", "unauthorized server", "covert abuse"],
    "MCP-19": ["prompt injection", "direct prompt injection", "user input override", "system intent"],
    "MCP-20": ["indirect prompt injection", "hidden prompt", "external data", "retrieved content"],
    "MCP-21": ["overreliance", "llm safeguard", "safety filter", "bypass safeguard"],
    "MCP-22": ["human-in-the-loop", "hitl", "consent mechanism", "approval bypass"],
    "MCP-23": ["approval fatigue", "consent fatigue", "blindly approve"],
    "MCP-24": ["data exfiltration", "tool output", "covert leak", "sensitive data leak"],
    "MCP-25": ["privacy inversion", "data aggregation", "cross-tool data", "aggregation leakage"],
    "MCP-26": ["supply chain", "malicious package", "dependency", "compromised package"],
    "MCP-27": ["integrity verification", "signature", "sbom", "attestation", "missing signature"],
    "MCP-28": ["man-in-the-middle", "mitm", "transport tampering", "tls", "interception"],
    "MCP-29": ["protocol gap", "weak transport", "missing auth", "csrf", "dos"],
    "MCP-30": ["stdio", "descriptor handling", "process hijacking", "stream hijacking"],
    "MCP-31": ["dns rebinding", "mcp endpoint", "dns rebind", "localhost bypass"],
    "MCP-32": ["network access", "lateral movement", "internal system", "pivot"],
    "MCP-33": ["resource exhaustion", "denial of wallet", "dos", "excessive call", "cost"],
    "MCP-34": ["tool manifest", "reconnaissance", "enumerate", "tool schema", "plan attack"],
    "MCP-35": ["planning drift", "agent logic drift", "reasoning manipulation", "unsafe decision"],
    "MCP-36": ["multi-agent", "context hijacking", "shared context", "context poisoning"],
    "MCP-37": ["sandbox escape", "container escape", "host system", "breakout"],
    "MCP-38": ["invisible activity", "no observability", "no log", "forensic traceability", "audit"],
}


class MCPThreatClassifier:
    """Classify threats to MCP Threat IDs based on content analysis"""
    
    @staticmethod
    def classify_threat(
        threat_name: str,
        threat_description: str,
        attack_vector: Optional[str] = None,
        stride_category: Optional[str] = None,
        msb_attack_type: Optional[str] = None,
        mcp_workflow_phase: Optional[str] = None
    ) -> List[str]:
        """
        Classify a threat to one or more MCP Threat IDs
        
        Returns:
            List of MCP Threat IDs (e.g., ["MCP-19", "MCP-20"])
        """
        matched_ids = []
        text_to_analyze = f"{threat_name} {threat_description} {attack_vector or ''} {stride_category or ''} {msb_attack_type or ''} {mcp_workflow_phase or ''}".lower()
        
        # Score each threat ID based on keyword matches
        scores = {}
        for threat_id, keywords in THREAT_KEYWORDS.items():
            score = 0
            for keyword in keywords:
                if keyword.lower() in text_to_analyze:
                    score += 1
            if score > 0:
                scores[threat_id] = score
        
        # Return top matches (at least 1 keyword match)
        if scores:
            # Sort by score descending
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            # Get top matches (at least 2 score or top 3)
            top_score = sorted_scores[0][1]
            for threat_id, score in sorted_scores:
                if score >= max(2, top_score * 0.5):  # At least 2 matches or 50% of top score
                    matched_ids.append(threat_id)
        
        # If no matches, try heuristic matching based on attack types
        if not matched_ids:
            matched_ids = MCPThreatClassifier._heuristic_classify(
                threat_name, threat_description, attack_vector, stride_category, msb_attack_type, mcp_workflow_phase
            )
        
        return matched_ids if matched_ids else []
    
    @staticmethod
    def _heuristic_classify(
        threat_name: str,
        threat_description: str,
        attack_vector: Optional[str],
        stride_category: Optional[str],
        msb_attack_type: Optional[str],
        mcp_workflow_phase: Optional[str]
    ) -> List[str]:
        """Heuristic classification based on attack types and workflow phases"""
        matched_ids = []
        text = f"{threat_name} {threat_description}".lower()
        
        # Prompt injection detection
        if "prompt injection" in text or (msb_attack_type and "prompt injection" in msb_attack_type.lower()):
            if "indirect" in text or "external data" in text or "retrieved" in text:
                matched_ids.append("MCP-20")
            else:
                matched_ids.append("MCP-19")
        
        # Tool poisoning
        if "tool poisoning" in text or "tool description" in text or (msb_attack_type and "tool poisoning" in msb_attack_type.lower()):
            matched_ids.append("MCP-10")
        
        # Command injection
        if "command injection" in text or "rce" in text or "code execution" in text:
            matched_ids.append("MCP-07")
        
        # Path traversal
        if "path traversal" in text or "directory traversal" in text or "../" in text:
            matched_ids.append("MCP-08")
        
        # Privilege escalation
        if "privilege escalation" in text or "confused deputy" in text:
            matched_ids.append("MCP-04")
        
        # Data exfiltration
        if "data exfiltration" in text or "data leak" in text or "sensitive data" in text:
            matched_ids.append("MCP-24")
        
        # Supply chain
        if "supply chain" in text or "dependency" in text or "package" in text:
            matched_ids.append("MCP-26")
        
        # Sandbox escape
        if "sandbox escape" in text or "container escape" in text:
            matched_ids.append("MCP-37")
        
        # Session/transport
        if stride_category and stride_category.lower() in ["spoofing", "tampering"]:
            if "session" in text or "transport" in text:
                matched_ids.append("MCP-28")
            elif "authentication" in text or "credential" in text:
                matched_ids.append("MCP-01")
        
        return matched_ids
    
    @staticmethod
    def get_threat_name(threat_id: str) -> Optional[str]:
        """Get threat name by ID"""
        return MCP_THREAT_MAP.get(threat_id)
    
    @staticmethod
    def get_all_threat_ids() -> List[str]:
        """Get all MCP threat IDs"""
        return list(MCP_THREAT_MAP.keys())
    
    @staticmethod
    def get_threats_by_domain(domain: int) -> List[str]:
        """Get threat IDs for a specific domain (1-7)"""
        domain_mapping = {
            1: ["MCP-01", "MCP-02", "MCP-03", "MCP-28", "MCP-29", "MCP-30", "MCP-31"],
            2: ["MCP-04", "MCP-05", "MCP-06", "MCP-21", "MCP-22", "MCP-23", "MCP-32"],
            3: ["MCP-07", "MCP-08", "MCP-09", "MCP-37"],
            4: ["MCP-10", "MCP-11", "MCP-12", "MCP-15", "MCP-17", "MCP-19", "MCP-20", "MCP-35", "MCP-36"],
            5: ["MCP-13", "MCP-14", "MCP-16", "MCP-18", "MCP-26", "MCP-27"],
            6: ["MCP-24", "MCP-25"],
            7: ["MCP-33", "MCP-34", "MCP-38"],
        }
        return domain_mapping.get(domain, [])
    
    @staticmethod
    def get_owasp_llm_mapping(threat_id: str) -> List[str]:
        """Get OWASP LLM Top 10 IDs for a MCP threat ID"""
        return MCP_TO_OWASP_LLM.get(threat_id, [])
    
    @staticmethod
    def get_owasp_agentic_mapping(threat_id: str) -> List[str]:
        """Get OWASP Agentic Top 10 IDs for a MCP threat ID"""
        return MCP_TO_OWASP_AGENTIC.get(threat_id, [])
    
    @staticmethod
    def get_owasp_llm_name(owasp_id: str) -> Optional[str]:
        """Get OWASP LLM Top 10 name by ID"""
        return OWASP_LLM_TOP10.get(owasp_id)
    
    @staticmethod
    def get_owasp_agentic_name(owasp_id: str) -> Optional[str]:
        """Get OWASP Agentic Top 10 name by ID"""
        return OWASP_AGENTIC_TOP10.get(owasp_id)
    
    @staticmethod
    def get_full_owasp_mapping(threat_id: str) -> Dict[str, Any]:
        """Get full OWASP mapping for a MCP threat ID"""
        llm_ids = MCP_TO_OWASP_LLM.get(threat_id, [])
        agentic_ids = MCP_TO_OWASP_AGENTIC.get(threat_id, [])
        
        return {
            "mcp_threat_id": threat_id,
            "mcp_threat_name": MCP_THREAT_MAP.get(threat_id, threat_id),
            "owasp_llm": [
                {"id": oid, "name": OWASP_LLM_TOP10.get(oid, oid)}
                for oid in llm_ids
            ],
            "owasp_agentic": [
                {"id": oid, "name": OWASP_AGENTIC_TOP10.get(oid, oid)}
                for oid in agentic_ids
            ]
        }
    
    @staticmethod
    def get_all_owasp_mappings() -> Dict[str, Any]:
        """Get all MCP to OWASP mappings"""
        return {
            "owasp_llm_top10": OWASP_LLM_TOP10,
            "owasp_agentic_top10": OWASP_AGENTIC_TOP10,
            "mcp_to_owasp_llm": MCP_TO_OWASP_LLM,
            "mcp_to_owasp_agentic": MCP_TO_OWASP_AGENTIC,
            "mappings": {
                threat_id: MCPThreatClassifier.get_full_owasp_mapping(threat_id)
                for threat_id in MCP_THREAT_MAP.keys()
            }
        }
    
    @staticmethod
    def get_threats_by_owasp_llm(owasp_id: str) -> List[str]:
        """Get MCP threat IDs that map to a specific OWASP LLM Top 10 ID"""
        result = []
        for threat_id, llm_ids in MCP_TO_OWASP_LLM.items():
            if owasp_id in llm_ids:
                result.append(threat_id)
        return result
    
    @staticmethod
    def get_threats_by_owasp_agentic(owasp_id: str) -> List[str]:
        """Get MCP threat IDs that map to a specific OWASP Agentic Top 10 ID"""
        result = []
        for threat_id, agentic_ids in MCP_TO_OWASP_AGENTIC.items():
            if owasp_id in agentic_ids:
                result.append(threat_id)
        return result
    
    @staticmethod
    def classify_to_owasp_llm(
        title: str,
        description: str,
        content: str = ""
    ) -> List[str]:
        """
        Classify content to OWASP LLM Top 10 categories based on keyword matching
        
        Args:
            title: Title of the threat/intel
            description: Description
            content: Additional content
            
        Returns:
            List of OWASP LLM IDs (e.g., ["LLM01", "LLM06"])
        """
        text_to_analyze = f"{title} {description} {content}".lower()
        
        scores = {}
        for owasp_id, keywords in OWASP_LLM_KEYWORDS.items():
            score = 0
            for keyword in keywords:
                if keyword.lower() in text_to_analyze:
                    score += 1
            if score > 0:
                scores[owasp_id] = score
        
        # Return matches with at least 1 keyword match
        if scores:
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            # Return all with score >= 1
            return [oid for oid, score in sorted_scores if score >= 1]
        
        return []
    
    @staticmethod
    def classify_to_owasp_agentic(
        title: str,
        description: str,
        content: str = ""
    ) -> List[str]:
        """
        Classify content to OWASP Agentic Top 10 categories based on keyword matching
        
        Args:
            title: Title of the threat/intel
            description: Description
            content: Additional content
            
        Returns:
            List of OWASP Agentic IDs (e.g., ["ASI01", "ASI02"])
        """
        text_to_analyze = f"{title} {description} {content}".lower()
        
        scores = {}
        for owasp_id, keywords in OWASP_AGENTIC_KEYWORDS.items():
            score = 0
            for keyword in keywords:
                if keyword.lower() in text_to_analyze:
                    score += 1
            if score > 0:
                scores[owasp_id] = score
        
        # Return matches with at least 1 keyword match
        if scores:
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            # Return all with score >= 1
            return [oid for oid, score in sorted_scores if score >= 1]
        
        return []
    
    @staticmethod
    def classify_to_all_frameworks(
        title: str,
        description: str,
        content: str = "",
        attack_vector: str = "",
        stride_category: str = ""
    ) -> Dict[str, Any]:
        """
        Classify content to all three frameworks: MCP, OWASP LLM, OWASP Agentic
        
        This is the main method for AI-powered classification that can assign
        a threat/intel to multiple categories across all frameworks.
        
        Args:
            title: Title of the threat/intel
            description: Description
            content: Additional content (e.g., ai_summary)
            attack_vector: Attack vector if known
            stride_category: STRIDE category if known
            
        Returns:
            Dictionary with classifications for all three frameworks
        """
        # Classify to MCP threats
        mcp_ids = MCPThreatClassifier.classify_threat(
            threat_name=title,
            threat_description=description,
            attack_vector=attack_vector,
            stride_category=stride_category
        )
        
        # Classify to OWASP LLM
        owasp_llm_ids = MCPThreatClassifier.classify_to_owasp_llm(
            title=title,
            description=description,
            content=content
        )
        
        # Classify to OWASP Agentic
        owasp_agentic_ids = MCPThreatClassifier.classify_to_owasp_agentic(
            title=title,
            description=description,
            content=content
        )
        
        # Also add OWASP mappings from MCP classifications
        for mcp_id in mcp_ids:
            # Add mapped OWASP LLM IDs
            for llm_id in MCP_TO_OWASP_LLM.get(mcp_id, []):
                if llm_id not in owasp_llm_ids:
                    owasp_llm_ids.append(llm_id)
            # Add mapped OWASP Agentic IDs
            for agentic_id in MCP_TO_OWASP_AGENTIC.get(mcp_id, []):
                if agentic_id not in owasp_agentic_ids:
                    owasp_agentic_ids.append(agentic_id)
        
        return {
            "mcp_threat_ids": mcp_ids,
            "mcp_threats": [
                {"id": tid, "name": MCP_THREAT_MAP.get(tid, tid)}
                for tid in mcp_ids
            ],
            "owasp_llm_ids": owasp_llm_ids,
            "owasp_llm": [
                {"id": oid, "name": OWASP_LLM_TOP10.get(oid, oid)}
                for oid in owasp_llm_ids
            ],
            "owasp_agentic_ids": owasp_agentic_ids,
            "owasp_agentic": [
                {"id": oid, "name": OWASP_AGENTIC_TOP10.get(oid, oid)}
                for oid in owasp_agentic_ids
            ],
            "summary": {
                "mcp_count": len(mcp_ids),
                "owasp_llm_count": len(owasp_llm_ids),
                "owasp_agentic_count": len(owasp_agentic_ids),
                "total_classifications": len(mcp_ids) + len(owasp_llm_ids) + len(owasp_agentic_ids)
            }
        }

