"""
MCP Knowledge Base Data
Contains hardcoded knowledge about MCP security threats, controls, and abuse cases.
"""

INITIAL_THREATS = [
    {
        "id": "mcp-server-tampering",
        "component": "MCP Server",
        "threat_category": "Tampering",
        "description": "Attacker modifies server configuration or responses to inject malicious content.",
        "maestro_layers": ["L1", "L3"],
        "mitigation_controls": [
            "Implement integrity checks for configuration",
            "Sign server responses",
            "Use TLS for all communication"
        ],
        "stride_category": "Tampering",
        "risk_score": 8.0
    },
    {
        "id": "mcp-client-spoofing",
        "component": "MCP Client",
        "threat_category": "Spoofing",
        "description": "Malicious client impersonates a legitimate client to access resources.",
        "maestro_layers": ["L2", "L4"],
        "mitigation_controls": [
            "Enforce mutual TLS (mTLS)",
            "Validate client certificates",
            "Implement strong API authentication"
        ],
        "stride_category": "Spoofing",
        "risk_score": 7.5
    },
    {
        "id": "mcp-host-privilege-escalation",
        "component": "Host Environment",
        "threat_category": "Elevation of Privilege",
        "description": "Attacker exploits vulnerabilities in the host environment to gain elevated privileges.",
        "maestro_layers": ["L4", "L6"],
        "mitigation_controls": [
            "Run MCP servers in sandboxed environments",
            "Follow principle of least privilege",
            "Regularly patch host operating system"
        ],
        "stride_category": "Elevation of Privilege",
        "risk_score": 9.0
    },
    {
        "id": "mcp-data-disclosure",
        "component": "Data",
        "threat_category": "Information Disclosure",
        "description": "Sensitive data leaked through MCP tool outputs or logs.",
        "maestro_layers": ["L2", "L5"],
        "mitigation_controls": [
            "Implement data masking/redaction",
            "Encrypt sensitive data at rest and in transit",
            "Audit tool outputs for PII"
        ],
        "stride_category": "Information Disclosure",
        "risk_score": 8.5
    },
    {
        "id": "mcp-tool-injection",
        "component": "Tools & Prompts",
        "threat_category": "Tampering",
        "description": "Attacker injects malicious commands into tool arguments via prompt injection.",
        "maestro_layers": ["L1", "L3"],
        "mitigation_controls": [
            "Validate and sanitize all tool inputs",
            "Implement human-in-the-loop approval for sensitive actions",
            "Use system prompts to constrain model behavior"
        ],
        "stride_category": "Tampering",
        "risk_score": 9.5
    }
]

INITIAL_CONTROLS = [
    {
        "id": "mcp-control-transport",
        "name": "Transport Security",
        "description": "Security controls for network transport layer.",
        "category": "Transport",
        "control_measures": [
            "TLS 1.3 encryption",
            "Certificate pinning",
            "mTLS for server-client authentication"
        ]
    },
    {
        "id": "mcp-control-auth",
        "name": "Authentication",
        "description": "Controls for verifying identity of clients and servers.",
        "category": "Authentication",
        "control_measures": [
            "API Key rotation",
            "OAuth 2.0 / OIDC support",
            "Strong password policies"
        ]
    },
    {
        "id": "mcp-control-audit",
        "name": "Audit Logging",
        "description": "Controls for logging and monitoring MCP activities.",
        "category": "Audit",
        "control_measures": [
            "Centralized log aggregation",
            "Audit trail for all privileged actions",
            "Real-time alerting for anomalies"
        ]
    },
    {
        "id": "mcp-control-sandbox",
        "name": "Sandboxing",
        "description": "Controls for isolating MCP components.",
        "category": "Isolation",
        "control_measures": [
            "Docker containerization",
            "Seccomp profiles",
            "Network segmentation"
        ]
    },
    {
        "id": "mcp-control-input-validation",
        "name": "Input Validation",
        "description": "Controls for validating inputs to tools and prompts.",
        "category": "Validation",
        "control_measures": [
            "Schema-based input validation",
            "Allow-listing of characters",
            "Input length limits"
        ]
    }
]

INITIAL_ABUSE_CASES = [
    {
        "id": "mcp-abuse-prompt-injection",
        "title": "Prompt Injection via Tool Arguments",
        "description": "Attacker crafts a prompt that trick the LLM into generating malicious tool arguments, executing unauthorized commands.",
        "threat_actor": "External Attacker",
        "entry_point": "User Prompt"
    },
    {
        "id": "mcp-abuse-exfiltration",
        "title": "Data Exfiltration via Side Channel",
        "description": "Attacker uses a tool to read sensitive files and output them to a public endpoint or log.",
        "threat_actor": "Insider / Malicious Prompt",
        "entry_point": "File System Access Tool"
    },
    {
        "id": "mcp-abuse-dos",
        "title": "Denial of Service via Resource Exhaustion",
        "description": "Attacker sends complex queries that cause the MCP server to consume excessive CPU or memory, crashing the service.",
        "threat_actor": "External Attacker",
        "entry_point": "API Endpoint"
    }
]
