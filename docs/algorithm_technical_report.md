# MCP Threat Platform: Technical Architecture & Algorithms

## 1. AI-Driven Risk Planning & Threat Generation

The core of the platform is the `EnhancedMCPThreatGenerator` (`core/enhanced_threat_generator.py`), which orchestrates the transformation of unstructured intelligence into structured threat models using a scientifically grounded batch processing approach.

### 1.1 Context-Aware LLM Batch Processing

We implement a **batch-based LLM inference strategy** to maximize model throughput while avoiding known token limit and HTTP timeout issues in generative pipelines:

- **Batching with Size Constraints**: Processing threats in fixed batches of **3 items** (`BATCH_SIZE = 3` in `core/intel_kg_builder.py`) is a deliberate **prompt window management strategy** to avoid overloading the model’s attention buffers and to prevent HTTP timeouts during extensive chain-of-thought reasoning. This alignment with recent research emphasizes smaller, controlled prompt chunks for higher accuracy.
- **Prompt Volume Control**: Before dispatching, the system computes serialized token counts. If `len(prompt) > 50,000` characters, strict truncation is applied to ensure valid requests.
- **Dynamic Token Budgeting**: We dynamically assign `max_tokens` based on expected output size using a heuristic (`tokens ≈ n_items * 10`) to optimize resource usage while preventing truncation artifacts.

### 1.2 JSON Repair and Structured Output Validation

Language model outputs (especially generative JSON) are prone to malformed structures due to length limits or grammar drift. To address this, we implement a **deterministic repair pipeline** (`api/server.py`) combining:

1. **Fast Path**: Attempt direct parse (`json.loads()`).
2. **Finite-State JSON Repair Machine**: A stack-based FSM scans for the last valid object delimiter `},` or `]`, maintaining a stack of open braces `{` and brackets `[`, and synthetically appends missing closing characters to force validity.
3. **Targeted Regex Extraction**: If structural repair fails, a specific regex `r'\{\s*"threat_id"[^}]+(?:"test_cases"\s*:\s*\[[^\]]*\])?[^}]*\}'` is used to extract surviving individual objects from the broken stream.

### 1.3 Prompt Engineering with Reasoning Control

The system prompt (`core/enhanced_threat_generator.py`) enforces a **Chain-of-Thought (CoT)** process with guided decision trees:

- **Explicit Logical Prompts**: The model is instructed to generate intermediate classification fields (e.g., `mcp_workflow_phase`, `msb_attack_type`) _before_ deriving the final risk assessment.
- **Verification Enforcement**: The model must cross-verify the `risk_score` (0.0-10.0) against the `risk_level` categorical bucket logic (Critical >= 9.0, High >= 7.0) defined in the schema. This schema-aware prompting reduces hallucination and enforces semantic constraints.

### 1.4 Dynamic Query Expansion (Iterative Search)

To prevent "zero-result" failures in intelligence gathering, the `IntelPipeline` implements an **Iterative Query Refinement Loop**:

1. **Initial Search**: Execute query (e.g., "MCP vulnerability").
2. **Result Check**: If `count < MIN_RESULTS` (default 5):
3. **Query Relaxation**: The system automatically strips restrictive terms (e.g., specific versions, "CVE-2024") and retries with broader keywords ("MCP security", "Model Context Protocol").
4. **Source Rotation**: If web search fails, it falls back to specific security feeds or broader domain searches.
   This ensures a high recall rate even for niche or emerging threat topics.

## 2. Neuro-Symbolic Knowledge Graph Construction

The Knowledge Graph engine (`core/intel_kg_builder.py`) utilizes a **Hybrid Extraction Pipeline** that fuses probabilistic AI models with deterministic symbolic logic to maximize correctness and robustness.

### 2.1 Hybrid Extraction Algorithms

We integrate **probabilistic AI extraction** with **deterministic symbolic parsing**:

1. **LLM-Based Extraction (Probabilistic)**: Using structured schema annotations, we extract entities of well-defined types: `Threat`, `Vulnerability`, `Technique`, `Component`, `Asset`, and relations (`AFFECTS`, `EXPLOITS`, etc.).
2. **Symbolic Regex Fallback (Deterministic)**: Where AI extraction scores low confidence or yields no output, rule-based regex patterns are applied to salvage critical entities.
   - **Attack Definitions**:
     - `(prompt\s+injection|jailbreak|ignore\s+previous\s+instructions)`
     - `(tool\s+poisoning|malicious\s+tool)`
     - `(data\s+exfiltration|leakage)`
   - **Asset Logic**:
     - `CVE-\d{4}-\d{4,}` (Standard CVE format)
     - `CWE-\d{1,4}` (Common Weakness Enumeration)
       This mirrors hybrid pipelines where rule-based extraction constrains and validates text generation.

### 2.2 Advanced Entity Resolution (Multi-Signal Scoring)

To prevent graph fragmentation while preserving semantic hierarchy (e.g., distinguishing "Prompt Injection" from "Indirect Prompt Injection" rather than merging them), we employ a **Multi-Signal Semantic Scoring System**:

1. **Stage 1: Exact Canonical Match (O(1))**:
   - Fast lookup against normalized canonical names (e.g., "model context protocol" → "MCP").
2. **Stage 2: Multi-Signal Scoring Model**:
   Instead of a single similarity metric, we compute a weighted score based on multiple semantic signals:
   - **Token Overlap**: $\frac{|T_A \cap T_B|}{\min(|T_A|, |T_B|)}$ (+2.0 if $\ge 0.7$, +1.0 if $\ge 0.5$).
   - **Type Symmetry**: +1.0 if `entity_type` matches.
   - **Substring Relationship**: +0.5 if one name is contained within the other.
   - **Semantic Modifiers**: **-1.5** penalty if the longer name contains modifiers like "indirect", "stored", or "blind". This signal specifically prevents the merging of parent/child concepts.

3. **Stage 3: Decision Logic**:
   - **Merge (Score $\ge 3.0$)**: High confidence that entities are synonyms. Metrics are merged and descriptions consolidated.
   - **Subclass (2.0 $\le$ Score $< 3.0$)**: Entities are semantically related but distinct (e.g., a variant). A **`SUBCLASS_OF`** relationship is created to build a taxonomic hierarchy.
   - **New Node (Score $< 2.0$)**: Entities are treated as distinct concepts.

### 2.3 Intelligent Instance Routing

The system distinguishes between **abstract classes** (e.g., "Tool Poisoning") and **concrete instances** (e.g., "CVE-2024-1234").

- **Instance Detection**: Uses a weighted scoring of regex patterns (CVE/CWE), numeric ID fragments, and type metadata.
- **Orphan Prevention**: Instead of merging an instance into a class, the system calculates the token overlap between the instance's description and all abstract class nodes.
- **Relational Linking**: The instance is kept as a unique node and linked via an **`INSTANCE_OF`** relation to the most relevant threat class, preserving the "Concept-to-Case" traceability essential for threat intelligence.

---

## 3. Threat Classification & Scoring Methodologies

The `MCPThreatClassifier` (`core/mcp_threat_classifier.py`) and `MCPThreatMapper` provide the implementation for risk quantification, utilizing a hybrid model of weighted keywords and AI verification.

### 3.1 Weighted Keyword Classification w/ Threshold Filtering

We use a **weighted keyword match model** inspired by probabilistic extraction and schema evaluation:

- **Aggregated Features**: Features are aggregated as counts over domain-specific keyword lexicons (`THREAT_KEYWORDS`).
- **Scoring**: `Score = Count(Matches)`.
- **Threshold Rule**: A threshold rule (`Score >= max(2, Top_Score * 0.5)`) ensures only strong signals are accepted, discarding weak single-keyword matches.
- **Heuristic Back-off**: If zero keywords match, a heuristic decision tree checks `stride_category` and `msb_attack_type` to assign a tentative ID (e.g., "Privilege Escalation" category -> `MCP-04`).

### 3.2 AI-Evaluated Scoring

While DREAD describes the classic 5-factor scoring model (Sum 0-50), our implementation uses an **AI-Synthesized Risk Score** (0-10 scale) to adapt DREAD for modern generative analysis:

1. **Holistic Synthesis**: Instead of asking the LLM to output 5 separate numbers (which often leads to arithmetic hallucinations), we instruct the model to _consider_ the 5 DREAD factors (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) implicitly during its "Chain of Thought".
2. **Unified Output**: The model outputs a single **Risk Score (0.0 - 10.0)** that represents the synthesized severity.
3. **Mapping Logic**:
   - **Critical**: Score $\ge 9.0$ (Must involve RCE, Data Exfiltration, or Critical Asset Compromise)
   - **High**: Score $7.0 - 8.9$ (Significant impact but difficult exploit, or moderate impact with easy exploit)
   - **Medium**: Score $4.0 - 6.9$
   - **Low**: Score $< 4.0$

This approach correctly implements the **principles** of DREAD validation while optimizing for LLM reliability and schema simplicity.

### 3.3 Framework Cross-Walk Mapping

The system maintains **static O(1) mapping tables** (`core/mcp_threat_classifier.py`) between the MCP taxonomy and compliance frameworks. These cross-walks enable automatic annotation resembling schema alignment strategies:

- **MCP to OWASP LLM Top 10**: e.g., `MCP-19` (Direct Injection) $\rightarrow$ `LLM01`.
- **MCP to OWASP Agentic Top 10**: e.g., `MCP-19` $\rightarrow$ `ASI01`.

This mirrors ontology linking strategies used in hybrid taxonomy systems.

---

## 4. Appendix: Key Technical Concepts

| Concept                       | Technical Justification                                                                                                    |
| :---------------------------- | :------------------------------------------------------------------------------------------------------------------------- |
| **Schema-aware Prompting**    | Reduces hallucination by enforcing output structure and semantic constraints via CoT and JSON schema validation.           |
| **Neuro-symbolic Extraction** | Combines probabilistic LLM inference with deterministic regex/symbolic rules to ensure high recall and precision.          |
| **Ontology Constraints**      | Enforces coherent graph structure by restricting extraction to defined entity types (`Threat`, `Component`) and relations. |
| **Entity Resolution**         | Prevents graph fragmentation using multi-stage canonicalization (O(1) lookup + Jaccard similarity).                        |
| **Context-Aware Batching**    | Optimizes LLM attention windows and throughput by processing intelligence in semantically grouped batches.                 |
| **Dynamic Query Expansion**   | Maximizes intelligence recall by iteratively relaxing search constraints until relevant results are found.                 |
