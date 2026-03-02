"""
MAESTRO Layer Definitions

Defines the seven-layer architecture for Agentic AI threat modeling.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum


class MaestroLayerNumber(int, Enum):
    """MAESTRO layer numbers"""
    FOUNDATION_MODELS = 1
    DATA_OPERATIONS = 2
    AGENT_FRAMEWORKS = 3
    DEPLOYMENT_INFRASTRUCTURE = 4
    EVALUATION_OBSERVABILITY = 5
    SECURITY_COMPLIANCE = 6
    AGENT_ECOSYSTEM = 7


@dataclass
class MaestroLayer:
    """Represents a MAESTRO layer"""
    number: int
    name: str
    short_name: str
    description: str
    threat_categories: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'number': self.number,
            'name': self.name,
            'short_name': self.short_name,
            'description': self.description,
            'threat_categories': self.threat_categories,
            'examples': self.examples
        }


# MAESTRO Seven-Layer Architecture
MAESTRO_LAYERS: Dict[int, MaestroLayer] = {
    1: MaestroLayer(
        number=1,
        name="Foundation Models",
        short_name="L1",
        description="The core AI model on which an agent is built. This can be a large language model (LLM) or other forms of AI.",
        threat_categories=[
            "Adversarial Examples",
            "Model Stealing",
            "Backdoor Attacks",
            "Membership Inference Attacks",
            "Data Poisoning (Training Phase)",
            "Reprogramming Attacks",
            "Denial of Service (DoS) Attacks"
        ],
        examples=["LLM", "Multimodal Models", "Foundation Models"]
    ),
    2: MaestroLayer(
        number=2,
        name="Data Operations",
        short_name="L2",
        description="Where data is processed, prepared, and stored for the AI agents, including databases, vector stores, RAG pipelines, and more.",
        threat_categories=[
            "Data Poisoning",
            "Data Exfiltration",
            "Model Inversion/Extraction",
            "Denial of Service on Data Infrastructure",
            "Data Tampering",
            "Compromised RAG Pipelines"
        ],
        examples=["Databases", "Vector Stores", "RAG Pipelines", "Data Processing"]
    ),
    3: MaestroLayer(
        number=3,
        name="Agent Frameworks",
        short_name="L3",
        description="The frameworks used to build the AI agents, for example toolkits for conversational AI, or frameworks that integrate data.",
        threat_categories=[
            "Compromised Framework Components",
            "Backdoor Attacks",
            "Input Validation Attacks",
            "Supply Chain Attacks",
            "Denial of Service on Framework APIs",
            "Framework Evasion"
        ],
        examples=["AutoGen", "CrewAI", "LangGraph", "LlamaIndex", "MCP"]
    ),
    4: MaestroLayer(
        number=4,
        name="Deployment and Infrastructure",
        short_name="L4",
        description="The infrastructure on which the AI agents run (e.g., cloud, on-premise).",
        threat_categories=[
            "Compromised Container Images",
            "Orchestration Attacks",
            "Infrastructure-as-Code (IaC) Manipulation",
            "Denial of Service (DoS) Attacks",
            "Resource Hijacking",
            "Lateral Movement"
        ],
        examples=["Kubernetes", "Docker", "Cloud Infrastructure", "On-Premise Servers"]
    ),
    5: MaestroLayer(
        number=5,
        name="Evaluation and Observability",
        short_name="L5",
        description="How AI agents are evaluated and monitored, including tools and processes for tracking performance and detecting anomalies.",
        threat_categories=[
            "Manipulation of Evaluation Metrics",
            "Compromised Observability Tools",
            "Denial of Service on Evaluation Infrastructure",
            "Evasion of Detection",
            "Data Leakage through Observability",
            "Poisoning Observability Data"
        ],
        examples=["Monitoring Tools", "Evaluation Metrics", "Logging Systems", "Performance Tracking"]
    ),
    6: MaestroLayer(
        number=6,
        name="Security and Compliance",
        short_name="L6",
        description="A vertical layer that cuts across all other layers, ensuring that security and compliance controls are integrated into all AI agent operations.",
        threat_categories=[
            "Security Agent Data Poisoning",
            "Evasion of Security AI Agents",
            "Compromised Security AI Agents",
            "Regulatory Non-Compliance by AI Security Agents",
            "Bias in Security AI Agents",
            "Lack of Explainability in Security AI Agents",
            "Model Extraction of AI Security Agents"
        ],
        examples=["Security Controls", "Compliance Frameworks", "Policy Enforcement", "Audit Systems"]
    ),
    7: MaestroLayer(
        number=7,
        name="Agent Ecosystem",
        short_name="L7",
        description="The ecosystem layer represents the marketplace where AI agents interface with real-world applications and users.",
        threat_categories=[
            "Compromised Agents",
            "Agent Impersonation",
            "Agent Identity Attack",
            "Agent Tool Misuse",
            "Agent Goal Manipulation",
            "Marketplace Manipulation",
            "Integration Risks",
            "Horizontal/Vertical Solution Vulnerabilities",
            "Repudiation",
            "Compromised Agent Registry",
            "Malicious Agent Discovery",
            "Agent Pricing Model Manipulation",
            "Inaccurate Agent Capability Description"
        ],
        examples=["Agent Marketplace", "Business Applications", "User Interfaces", "Agent Registry"]
    )
}


def get_layer_by_number(layer_number: int) -> MaestroLayer:
    """Get a MAESTRO layer by its number"""
    return MAESTRO_LAYERS.get(layer_number)


def get_all_layers() -> List[MaestroLayer]:
    """Get all MAESTRO layers"""
    return list(MAESTRO_LAYERS.values())


def get_layer_by_name(name: str) -> MaestroLayer:
    """Get a MAESTRO layer by its name"""
    for layer in MAESTRO_LAYERS.values():
        if layer.name.lower() == name.lower() or layer.short_name.lower() == name.lower():
            return layer
    return None

