/**
 * MCP Threat Model Matrix
 * 
 * Comprehensive threat modeling framework integrating:
 * - Workflow phase-based attack classification
 * - Threat vector categories
 * - Attack chain analysis
 * - Preference manipulation attacks
 */

const MCPThreatMatrixState = {
    threats: [],
    intelItems: [],
    workflowPhases: {
        'Tool Definition / Registration': [],
        'Tool Catalog / Discovery / Metadata Exposure': [],
        'Tool Invocation / Call Request': [],
        'Tool Execution / Runtime / External Resource Interaction': [],
        'Tool-Chain Orchestration / Multi-Tool Workflow': [],
        'Response Handling / Output Processing': [],
        'Supply-Chain / Dependency / Update / Deployment': [],
        'Infrastructure / Configuration / Deployment Environment': []
    },
    attackTypes: {},
    threatVectors: {},
    mcpUpdChains: [],
    mpmaAttacks: []
};

// MCP Workflow Phases (Enhanced 8-phase model)
const MCP_WORKFLOW_PHASES = [
    'Tool Definition / Registration',
    'Tool Catalog / Discovery / Metadata Exposure',
    'Tool Invocation / Call Request',
    'Tool Execution / Runtime / External Resource Interaction',
    'Tool-Chain Orchestration / Multi-Tool Workflow',
    'Response Handling / Output Processing',
    'Supply-Chain / Dependency / Update / Deployment',
    'Infrastructure / Configuration / Deployment Environment'
];

// Attack Types by Phase (Comprehensive taxonomy)
const ATTACK_TYPES_BY_PHASE = {
    'Tool Definition / Registration': [
        'Tool Poisoning / Malicious Tool',
        'Name-Collision / Tool Spoofing',
        'Metadata / Description Poisoning',
        'Code Signing Bypass',
        'Schema Inconsistencies'
    ],
    'Tool Catalog / Discovery / Metadata Exposure': [
        'Metadata Poisoning',
        'Catalog Manipulation',
        'Tool Discovery Abuse',
        'Information Disclosure',
        'Catalog Injection'
    ],
    'Tool Invocation / Call Request': [
        'Prompt Injection (in metadata / tool description / user input)',
        'Parameter Abuse / Out-of-Scope Argument',
        'Tool-Call Injection',
        'Schema Constraint Bypass',
        'Type Confusion'
    ],
    'Tool Execution / Runtime / External Resource Interaction': [
        'Command Injection / Code Injection / RCE via Tool',
        'Path Traversal / Filesystem Abuse',
        'Network / External API Abuse / SSRF / Exfiltration',
        'Resource Abuse / Compute Hijack / Denial-of-Service',
        'Privilege Escalation / Authorization Bypass',
        'Sandbox Escape'
    ],
    'Tool-Chain Orchestration / Multi-Tool Workflow': [
        'Tool-to-Tool Parasitic Chaining',
        'Orchestration Abuse',
        'Workflow Manipulation',
        'Chain Injection',
        'Multi-Tool Attack'
    ],
    'Response Handling / Output Processing': [
        'Data Exfiltration / Sensitive Data Leakage',
        'Context / State Poisoning / Persistent Context Abuse',
        'User Impersonation',
        'Fake Error',
        'Retrieval Injection',
        'Output Manipulation'
    ],
    'Supply-Chain / Dependency / Update / Deployment': [
        'Supply-Chain / Dependency Attack / Rogue Update',
        'Dependency Poisoning',
        'Update Mechanism Abuse',
        'Deployment Pipeline Attack',
        'Version Manipulation'
    ],
    'Infrastructure / Configuration / Deployment Environment': [
        'Configuration / Misconfiguration / Exposure',
        'Infrastructure Abuse',
        'Environment Variable Exposure',
        'Deployment Configuration Weakness',
        'Infrastructure Privilege Escalation'
    ]
};

// Threat Vector Categories
const THREAT_VECTORS = [
    'Prompt-based Attacks / Injection',
    'Tool / Plugin Misuse / Abuse',
    'Privacy / Data Leakage',
    'Resource Abuse / DoS / Performance Exhaustion',
    'Privilege Escalation / Unauthorized Access',
    'Supply-chain / Dependency / Library Risks',
    'Configuration / Misconfiguration / Deployment Risks',
    'Logic / Business-Logic Abuse / Misuse',
    'Agent/Memory / State-based Attacks',
    'Audit / Logging / Non-repudiation Failures'
];

// MCP-UPD Phases (5-stage attack chain)
const MCP_UPD_PHASES = [
    'Tool Surface Discovery',
    'Parameter Injection / Constraint Evasion',
    'Tool-to-Tool Parasitic Chaining',
    'UPD Exploitation',
    'Post-Tool Impact'
];

// MCP-UPD Tool Types and Attack Types by Phase
const MCP_UPD_PHASE_INFO = {
    'Tool Surface Discovery': {
        toolTypes: ['UPD Surface Tool', 'Deserialization Tool', 'Insecure Resource Access Tool', 'Over-broad File Access Tool', 'Broken AuthN/AuthZ Tool'],
        attackTypes: ['UPD surface', 'Deserialization', 'Insecure Resource Access', 'Over-broad File Access', 'Broken AuthN/AuthZ'],
        description: 'Scanning MCP tools, collecting input/output schemas, identifying parasitic tools'
    },
    'Parameter Injection / Constraint Evasion': {
        toolTypes: ['Injection Tool', 'Schema Bypass Tool'],
        attackTypes: ['Prompt injection', 'Tool-call injection', 'Schema constraint bypass', 'Type confusion'],
        description: 'Injecting malicious parameters or bypassing validators'
    },
    'Tool-to-Tool Parasitic Chaining': {
        toolTypes: ['Parasitic Chain Tool'],
        attackTypes: ['Indirect execution chain', 'Indirect network call chain', 'Privilege-escalation chain', 'Sensitive data transformation chain'],
        description: 'Chaining tool A output as tool B input to form attack chains'
    },
    'UPD Exploitation': {
        toolTypes: ['External Ingestion Tool (EIT)', 'Privacy Access Tool (PAT)', 'Network Access Tool (NAT)'],
        attackTypes: ['File read/write UPD', 'Network pivoting UPD', 'SSRF via tool', 'Code/command injection via tool', 'Data exfiltration via tool output'],
        description: 'Exploiting untrusted parameters to execute dangerous operations'
    },
    'Post-Tool Impact': {
        toolTypes: ['Impact Tool'],
        attackTypes: ['Data Exfiltration', 'Integrity Compromise', 'Availability Impact', 'Privilege Escalation', 'Privacy Leak', 'Supply Chain Propagation'],
        description: 'Actual security impact after tool execution'
    }
};

// Preference Manipulation Attack Types
const PREFERENCE_MANIPULATION_TYPES = [
    'Direct Preference Manipulation',
    'Genetic Algorithm Preference Manipulation',
    'Authority-based Manipulation',
    'Emotional Manipulation',
    'Exaggerated Claims',
    'Subliminal Influence'
];

// GAPMA Strategies
const GAPMA_STRATEGIES = [
    'Authoritative',
    'Emotional',
    'Exaggerated',
    'Subliminal'
];

/**
 * Get API base URL
 */
function getApiBase() {
    if (typeof API_BASE !== 'undefined') {
        return API_BASE;
    }
    const port = window.location.port || '5000';
    const host = window.location.hostname || 'localhost';
    const protocol = window.location.protocol || 'http:';
    return `${protocol}//${host}:${port}/api`;
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    const globalNotify = window.showNotification;
    if (globalNotify && typeof globalNotify === 'function') {
        try {
            if (globalNotify.length === 3) {
                globalNotify(type, 'MCP Threat Matrix', message);
            } else {
                globalNotify(message, type);
            }
        } catch (e) {
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    } else {
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
}

/**
 * Load threat model matrix data
 */
async function loadMCPThreatMatrix() {
    const apiBase = getApiBase();
    console.log('[MCPThreatMatrix] Loading threat model matrix...');

    try {
        // Load threats, intel, and OWASP mappings in parallel
        const [threatsResponse, intelResponse, owaspResponse] = await Promise.all([
            fetch(`${apiBase}/threats?limit=10000`),
            fetch(`${apiBase}/intel/items?limit=10000`),
            fetch(`${apiBase}/owasp/mappings`)
        ]);

        if (!threatsResponse.ok) {
            throw new Error(`Failed to load threats: ${threatsResponse.statusText}`);
        }
        const threatsData = await threatsResponse.json();
        MCPThreatMatrixState.threats = threatsData.threats || threatsData || [];

        if (intelResponse.ok) {
            const intelData = await intelResponse.json();
            MCPThreatMatrixState.intelItems = intelData.items || intelData || [];
        }

        // Load OWASP mappings
        if (owaspResponse.ok) {
            const owaspData = await owaspResponse.json();
            MCPThreatMatrixState.owaspMappings = owaspData.mappings || {};
            MCPThreatMatrixState.owaspLlmTop10 = owaspData.owasp_llm_top10 || {};
            MCPThreatMatrixState.owaspAgenticTop10 = owaspData.owasp_agentic_top10 || {};
        }

        // Auto-classify intel items to MCP Threat IDs
        await autoClassifyIntelItems();

        // Organize threats by workflow phase
        organizeThreatsByPhase();

        // Calculate and update statistics
        calculateStatistics();

        // Render all views
        renderMCPThreatIDMatrix();
        renderThreatVectorMatrix();
        renderMCPUPDChains();
        
        // Auto-load OWASP Mapping View
        await loadOWASPMappingView();

        console.log('[MCPThreatMatrix] Matrix loaded successfully');
        showNotification('Threat matrix loaded', 'success');

        // Set up auto-refresh for real-time updates
        setupAutoRefresh();

    } catch (error) {
        console.error('[MCPThreatMatrix] Error loading matrix:', error);
        showNotification(`Failed to load threat matrix: ${error.message}`, 'error');
    }
}

/**
 * Auto-classify intel items to MCP Threat IDs, OWASP LLM, and OWASP Agentic
 */
async function autoClassifyIntelItems() {
    const apiBase = getApiBase();
    const intelItems = MCPThreatMatrixState.intelItems || [];

    if (intelItems.length === 0) {
        console.log('[MCPThreatMatrix] No intel items to classify');
        return;
    }

    console.log(`[MCPThreatMatrix] Auto-classifying ${intelItems.length} intel items...`);

    try {
        // Batch classify intel items
        const response = await fetch(`${apiBase}/intel/classify-batch`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                limit: intelItems.length
            })
        });

        if (response.ok) {
            const data = await response.json();
            const results = data.results || [];

            // Update intel items with classifications
            results.forEach(result => {
                const intel = intelItems.find(i => i.id === result.intel_id);
                if (intel && result.classification) {
                    intel.mcp_threat_ids = result.classification.mcp_threat_ids || [];
                    intel.owasp_llm_ids = result.classification.owasp_llm_ids || [];
                    intel.owasp_agentic_ids = result.classification.owasp_agentic_ids || [];
                }
            });

            console.log(`[MCPThreatMatrix] Classified ${results.length} intel items`);
        }
    } catch (error) {
        console.warn('[MCPThreatMatrix] Auto-classification failed:', error.message);
    }
}

/**
 * Calculate and update statistics
 */
function calculateStatistics() {
    // Total threats
    const totalThreats = MCPThreatMatrixState.threats.length;
    const totalThreatsEl = document.getElementById('tm-total-threats');
    if (totalThreatsEl) {
        totalThreatsEl.textContent = totalThreats;
    }

    // Intel items mapped - count items that are actually mapped to threats
    const mappedIntelIds = new Set();

    // First, collect all source_intel_ids from threats
    MCPThreatMatrixState.threats.forEach(threat => {
        // Check multiple possible locations for source_intel_ids
        const sourceIntelIds = threat.metadata?.source_intel_ids ||
            threat.schema_data?.source_intel_ids ||
            threat.source_intel_ids || [];

        // Handle both array and string formats
        const ids = Array.isArray(sourceIntelIds) ? sourceIntelIds :
            (sourceIntelIds ? [sourceIntelIds] : []);

        ids.forEach(id => {
            if (id) {
                mappedIntelIds.add(String(id));
            }
        });
    });

    // Also check for fuzzy matches by title/content
    MCPThreatMatrixState.intelItems.forEach(intel => {
        if (!intel || !intel.id) return;
        const intelIdStr = String(intel.id);

        // Skip if already mapped
        if (mappedIntelIds.has(intelIdStr)) return;

        // Check if any threat references this intel item
        const isMapped = MCPThreatMatrixState.threats.some(threat => {
            const sourceIntelIds = threat.metadata?.source_intel_ids ||
                threat.schema_data?.source_intel_ids ||
                threat.source_intel_ids || [];
            const ids = Array.isArray(sourceIntelIds) ? sourceIntelIds :
                (sourceIntelIds ? [sourceIntelIds] : []);

            // Check direct ID match
            if (ids.some(id => String(id) === intelIdStr)) {
                return true;
            }

            // Check title similarity
            const intelTitle = (intel.title || '').toLowerCase();
            if (intelTitle && intelTitle.length > 5) {
                const threatName = (threat.name || threat.title || '').toLowerCase();
                const threatDesc = (threat.description || '').toLowerCase();
                if (threatName.includes(intelTitle) || threatDesc.includes(intelTitle)) {
                    return true;
                }
            }

            // Check content similarity
            const intelContent = (intel.content || intel.ai_summary || '').toLowerCase();
            if (intelContent && intelContent.length > 20) {
                const threatDesc = (threat.description || '').toLowerCase();
                const intelWords = intelContent.split(/\s+/).filter(w => w.length > 4).slice(0, 5);
                const matchingWords = intelWords.filter(word => threatDesc.includes(word));
                if (matchingWords.length >= 2) {
                    return true;
                }
            }

            return false;
        });

        if (isMapped) {
            mappedIntelIds.add(intelIdStr);
        }
    });

    const intelMappedEl = document.getElementById('tm-intel-mapped');
    if (intelMappedEl) {
        intelMappedEl.textContent = mappedIntelIds.size;
    }

    // STRIDE distribution - check multiple possible field locations
    const strideCategories = new Set();
    MCPThreatMatrixState.threats.forEach(threat => {
        const category = threat.category ||
            threat.stride_category ||
            threat.metadata?.stride_category ||
            threat.schema_data?.stride_category;
        if (category) {
            // Check if it's a valid STRIDE category
            const validStrideCategories = [
                'Spoofing', 'Tampering', 'Repudiation',
                'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'
            ];
            if (validStrideCategories.some(c => category.includes(c) || c.includes(category))) {
                strideCategories.add(category);
            }
        }
    });

    const strideEl = document.getElementById('tm-stride-distribution');
    if (strideEl) {
        strideEl.textContent = strideCategories.size;
    }

    // Attack Surfaces - count unique MSB attack types or workflow phases
    const attackSurfacesSet = new Set();
    MCPThreatMatrixState.threats.forEach(threat => {
        // Check for MSB attack type
        const attackType = threat.msb_attack_type ||
            threat.schema_data?.msb_attack_type;
        if (attackType && attackType !== 'Unknown') {
            attackSurfacesSet.add(attackType);
        }

        // Also check workflow phase as attack surface
        const phase = threat.mcp_workflow_phase ||
            threat.schema_data?.mcp_workflow_phase;
        if (phase && phase !== 'Cross-Phase') {
            attackSurfacesSet.add(phase);
        }
    });

    const attackSurfacesEl = document.getElementById('tm-attack-surfaces');
    if (attackSurfacesEl) {
        attackSurfacesEl.textContent = attackSurfacesSet.size;
    }

    console.log(`[MCPThreatMatrix] Statistics: ${totalThreats} threats, ${mappedIntelIds.size} intel mapped, ${strideCategories.size} STRIDE categories, ${attackSurfacesSet.size} attack surfaces`);
}

/**
 * Helper function to extract workflow phase from threat (with inference)
 */
function extractWorkflowPhase(threat) {
    // Check multiple possible locations with extensive fallback
    let workflowPhase = threat.mcp_workflow_phase ||
        threat.workflow_phase ||
        threat.metadata?.mcp_workflow_phase ||
        threat.metadata?.workflow_phase;

    // Check schema_data (can be object or string)
    if (!workflowPhase && threat.schema_data) {
        if (typeof threat.schema_data === 'string') {
            try {
                const parsed = JSON.parse(threat.schema_data);
                workflowPhase = parsed.mcp_workflow_phase ||
                    parsed.workflow_phase ||
                    parsed.workflowPhase;
            } catch (e) {
                // Not JSON, ignore
            }
        } else if (typeof threat.schema_data === 'object') {
            workflowPhase = threat.schema_data.mcp_workflow_phase ||
                threat.schema_data.workflow_phase ||
                threat.schema_data.workflowPhase;
        }
    }

    // If still not found, try to infer from description or name
    if (!workflowPhase || workflowPhase === 'N/A') {
        const desc = (threat.description || '').toLowerCase();
        const name = (threat.name || '').toLowerCase();

        // Map old phase names to new ones for backward compatibility
        if (desc.includes('response') || desc.includes('output') || desc.includes('exfiltration') ||
            desc.includes('data leak') || desc.includes('user impersonation') || desc.includes('fake error')) {
            workflowPhase = 'Response Handling / Output Processing';
        } else if (desc.includes('execution') || desc.includes('runtime') || desc.includes('command injection') ||
            desc.includes('code injection') || desc.includes('rce') || desc.includes('path traversal') ||
            desc.includes('filesystem') || desc.includes('ssrf') || desc.includes('network') ||
            desc.includes('external api') || desc.includes('privilege') || desc.includes('authorization') ||
            desc.includes('sandbox escape')) {
            workflowPhase = 'Tool Execution / Runtime / External Resource Interaction';
        } else if (desc.includes('invocation') || desc.includes('parameter') || desc.includes('tool call') ||
            desc.includes('prompt injection') || desc.includes('tool-call injection') ||
            desc.includes('schema bypass') || desc.includes('constraint evasion')) {
            workflowPhase = 'Tool Invocation / Call Request';
        } else if (desc.includes('tool chain') || desc.includes('orchestration') || desc.includes('multi-tool') ||
            desc.includes('parasitic chain') || desc.includes('tool-to-tool')) {
            workflowPhase = 'Tool-Chain Orchestration / Multi-Tool Workflow';
        } else if (desc.includes('definition') || desc.includes('registration') || desc.includes('tool creation') ||
            desc.includes('tool poisoning') || desc.includes('malicious tool') ||
            desc.includes('name collision') || desc.includes('tool spoofing')) {
            workflowPhase = 'Tool Definition / Registration';
        } else if (desc.includes('catalog') || desc.includes('discovery') || desc.includes('metadata') ||
            desc.includes('tool scanning') || desc.includes('tool surface')) {
            workflowPhase = 'Tool Catalog / Discovery / Metadata Exposure';
        } else if (desc.includes('supply chain') || desc.includes('dependency') || desc.includes('update') ||
            desc.includes('deployment pipeline') || desc.includes('version manipulation')) {
            workflowPhase = 'Supply-Chain / Dependency / Update / Deployment';
        } else if (desc.includes('infrastructure') || desc.includes('configuration') || desc.includes('deployment') ||
            desc.includes('environment variable') || desc.includes('misconfiguration')) {
            workflowPhase = 'Infrastructure / Configuration / Deployment Environment';
        } else {
            // Default to a common phase if we can't determine
            workflowPhase = 'Tool Execution / Runtime / External Resource Interaction';
        }
    }

    // Ensure the phase is one of the valid 8 phases
    if (!MCP_WORKFLOW_PHASES.includes(workflowPhase)) {
        // Try to find a close match
        const phaseLower = workflowPhase.toLowerCase();
        for (const validPhase of MCP_WORKFLOW_PHASES) {
            if (phaseLower.includes(validPhase.toLowerCase()) || validPhase.toLowerCase().includes(phaseLower)) {
                workflowPhase = validPhase;
                break;
            }
        }
        // If still no match, use default
        if (!MCP_WORKFLOW_PHASES.includes(workflowPhase)) {
            workflowPhase = 'Tool Execution / Runtime / External Resource Interaction';
        }
    }

    return workflowPhase;
}

/**
 * Helper function to extract attack type from threat (with inference)
 */
function extractAttackType(threat, workflowPhase) {
    // Check multiple possible locations with extensive fallback
    let attackType = threat.msb_attack_type ||
        threat.attack_type ||
        threat.metadata?.msb_attack_type ||
        threat.metadata?.attack_type;

    // Check schema_data (can be object or string)
    if (!attackType && threat.schema_data) {
        if (typeof threat.schema_data === 'string') {
            try {
                const parsed = JSON.parse(threat.schema_data);
                attackType = parsed.msb_attack_type ||
                    parsed.attack_type ||
                    parsed.attackType;
            } catch (e) {
                // Not JSON, ignore
            }
        } else if (typeof threat.schema_data === 'object') {
            attackType = threat.schema_data.msb_attack_type ||
                threat.schema_data.attack_type ||
                threat.schema_data.attackType;
        }
    }

    // If still not found, try to infer from description or name
    if (!attackType || attackType === 'N/A' || attackType === 'Unknown') {
        const desc = (threat.description || '').toLowerCase();
        const name = (threat.name || '').toLowerCase();
        const phaseLower = (workflowPhase || '').toLowerCase();

        // Get attack types for this phase
        const phaseAttackTypes = ATTACK_TYPES_BY_PHASE[workflowPhase] || [];

        // Infer based on workflow phase and keywords
        for (const candidateType of phaseAttackTypes) {
            const candidateLower = candidateType.toLowerCase();
            if (desc.includes(candidateLower) || name.includes(candidateLower)) {
                attackType = candidateType;
                break;
            }
        }

        // If still not found, use general inference
        if (!attackType || attackType === 'N/A' || attackType === 'Unknown') {
            if (phaseLower.includes('response handling') || phaseLower.includes('output processing')) {
                if (desc.includes('exfiltration') || desc.includes('data leak')) {
                    attackType = 'Data Exfiltration / Sensitive Data Leakage';
                } else if (desc.includes('impersonation')) {
                    attackType = 'User Impersonation';
                } else if (desc.includes('fake error')) {
                    attackType = 'Fake Error';
                } else if (desc.includes('retrieval')) {
                    attackType = 'Retrieval Injection';
                } else {
                    attackType = 'Output Manipulation';
                }
            } else if (phaseLower.includes('tool execution') || phaseLower.includes('runtime')) {
                if (desc.includes('command injection') || desc.includes('code injection') || desc.includes('rce')) {
                    attackType = 'Command Injection / Code Injection / RCE via Tool';
                } else if (desc.includes('path traversal') || desc.includes('filesystem')) {
                    attackType = 'Path Traversal / Filesystem Abuse';
                } else if (desc.includes('ssrf') || desc.includes('network') || desc.includes('external api')) {
                    attackType = 'Network / External API Abuse / SSRF / Exfiltration';
                } else if (desc.includes('privilege') || desc.includes('authorization')) {
                    attackType = 'Privilege Escalation / Authorization Bypass';
                } else {
                    attackType = 'Command Injection / Code Injection / RCE via Tool';
                }
            } else if (phaseLower.includes('tool invocation') || phaseLower.includes('call request')) {
                if (desc.includes('parameter abuse') || desc.includes('out-of-scope')) {
                    attackType = 'Parameter Abuse / Out-of-Scope Argument';
                } else if (desc.includes('prompt injection')) {
                    attackType = 'Prompt Injection (in metadata / tool description / user input)';
                } else if (desc.includes('tool-call injection')) {
                    attackType = 'Tool-Call Injection';
                } else {
                    attackType = 'Parameter Abuse / Out-of-Scope Argument';
                }
            } else if (phaseLower.includes('tool definition') || phaseLower.includes('registration')) {
                if (desc.includes('tool poisoning') || desc.includes('malicious tool')) {
                    attackType = 'Tool Poisoning / Malicious Tool';
                } else if (desc.includes('name collision') || desc.includes('tool spoofing')) {
                    attackType = 'Name-Collision / Tool Spoofing';
                } else if (desc.includes('metadata poisoning') || desc.includes('description poisoning')) {
                    attackType = 'Metadata / Description Poisoning';
                } else {
                    attackType = 'Schema Inconsistencies';
                }
            } else {
                // Default attack type based on phase
                attackType = phaseAttackTypes[0] || 'Unknown';
            }
        }
    }

    return attackType;
}

/**
 * Organize threats by MCP workflow phase
 */
function organizeThreatsByPhase() {
    // Reset state - initialize with all 8 phases
    MCPThreatMatrixState.workflowPhases = {};
    MCP_WORKFLOW_PHASES.forEach(phase => {
        MCPThreatMatrixState.workflowPhases[phase] = [];
    });

    MCPThreatMatrixState.attackTypes = {};
    MCPThreatMatrixState.threatVectors = {};

    MCPThreatMatrixState.threats.forEach(threat => {
        // Extract workflow phase with inference
        const phase = extractWorkflowPhase(threat);

        // Extract attack type with inference
        const attackType = extractAttackType(threat, phase);

        // Add to phase
        if (!MCPThreatMatrixState.workflowPhases[phase]) {
            MCPThreatMatrixState.workflowPhases[phase] = [];
        }
        MCPThreatMatrixState.workflowPhases[phase].push(threat);

        // Track by attack type
        if (!MCPThreatMatrixState.attackTypes[attackType]) {
            MCPThreatMatrixState.attackTypes[attackType] = [];
        }
        MCPThreatMatrixState.attackTypes[attackType].push(threat);

        // Track by threat vector
        const threatVector = threat.threat_vector ||
            threat.schema_data?.threat_vector ||
            threat.category ||
            'Unknown';
        if (!MCPThreatMatrixState.threatVectors[threatVector]) {
            MCPThreatMatrixState.threatVectors[threatVector] = [];
        }
        MCPThreatMatrixState.threatVectors[threatVector].push(threat);
    });

    console.log('[MCPThreatMatrix] Organized threats:', {
        total: MCPThreatMatrixState.threats.length,
        phases: Object.keys(MCPThreatMatrixState.workflowPhases).map(p => ({
            phase: p,
            count: MCPThreatMatrixState.workflowPhases[p].length
        })),
        attackTypes: Object.keys(MCPThreatMatrixState.attackTypes).length,
        threatVectors: Object.keys(MCPThreatMatrixState.threatVectors).length
    });
}

/**
 * Render MCP Threat ID Matrix (MCP-01 to MCP-38) - Primary view
 */
async function renderMCPThreatIDMatrix() {
    // Try primary container first
    let container = document.getElementById('mcp-threat-id-matrix');
    if (!container) {
        // Fallback to workflow phase view container
        container = document.getElementById('mcp-workflow-phase-view');
    }
    if (!container) {
        // Try alternative container
        const altContainer = document.querySelector('.mcp-matrix-section');
        if (!altContainer) {
            console.warn('[MCPThreatMatrix] No container found for MCP Threat ID Matrix');
            return;
        }
        container = altContainer;
    }

    try {
        const apiBase = getApiBase();
        const projectId = new URLSearchParams(window.location.search).get('project_id') || 'default-project';
        const response = await fetch(`${apiBase}/mcp-threat-matrix?project_id=${projectId}`);
        if (!response.ok) {
            throw new Error(`Failed to load MCP Threat Matrix: ${response.statusText}`);
        }
        const matrixData = await response.json();

        // Create MCP Threat ID Matrix view
        container.innerHTML = '<h3>MCP Threat Matrix (MCP-01 to MCP-38)</h3>';

        const description = document.createElement('p');
        description.className = 'matrix-description';
        description.textContent = 'Threat matrix organized by MCP Threat IDs. All threats and intelligence are mapped to these 38 standard threat categories.';
        container.appendChild(description);

        // Render by Domain
        const domainSection = document.createElement('div');
        domainSection.className = 'mcp-threat-domain-section';
        domainSection.innerHTML = '<h4>By Security Domain</h4>';

        const domainGrid = document.createElement('div');
        domainGrid.className = 'mcp-threat-domain-grid';

        const domains = matrixData.matrix.domains;
        const threats = matrixData.threats_by_mcp_id || {};
        const intel = matrixData.intel_by_mcp_id || {};

        for (let domainNum = 1; domainNum <= 7; domainNum++) {
            const domain = domains[domainNum];
            if (!domain) continue;

            const domainCard = document.createElement('div');
            domainCard.className = 'mcp-threat-domain-card';

            const domainName = getDomainName(domainNum);

            // Count threats and intel for this domain
            let domainThreatCount = 0;
            let domainIntelCount = 0;
            domain.threat_ids.forEach(mcpId => {
                if (threats[mcpId]) domainThreatCount += threats[mcpId].length;
                if (intel[mcpId]) domainIntelCount += intel[mcpId].length;
            });

            domainCard.innerHTML = `
                <div class="domain-header">
                    <h5>Domain ${domainNum}: ${domainName}</h5>
                    <span class="domain-count">${domain.count} threats</span>
                </div>
                <div class="domain-stats">
                    <span class="stat-item">Threats: ${domainThreatCount}</span>
                    <span class="stat-item">Intel: ${domainIntelCount}</span>
                </div>
                <div class="domain-threats">
                    ${domain.threat_ids.map(mcpId => {
                const threatIndex = domain.threat_ids.indexOf(mcpId);
                const threatName = domain.threat_names[threatIndex] || mcpId;
                const threatCount = (threats[mcpId] || []).length;
                const intelCount = (intel[mcpId] || []).length;

                // Get OWASP mappings
                const owaspMapping = (MCPThreatMatrixState.owaspMappings?.mappings || {})[mcpId] || {};
                const owaspLlm = owaspMapping.owasp_llm || [];
                const owaspAgentic = owaspMapping.owasp_agentic || [];

                return `
                            <div class="mcp-threat-item" data-mcp-id="${mcpId}" onclick="showMCPThreatDetails('${mcpId}')">
                                <div class="threat-id">${mcpId}</div>
                                <div class="threat-name">${escapeHtml(threatName)}</div>
                                <div class="owasp-tags" style="display: flex; flex-wrap: wrap; gap: 3px; margin: 4px 0;">
                                    ${owaspLlm.slice(0, 2).map(o => `<span class="owasp-tag-mini" style="background: rgba(66,153,225,0.2); color: #4299e1; padding: 1px 4px; border-radius: 3px; font-size: 0.65rem;" title="${escapeHtml(o.name || '')}">${o.id}</span>`).join('')}
                                    ${owaspAgentic.slice(0, 2).map(o => `<span class="owasp-tag-mini" style="background: rgba(237,137,54,0.2); color: #ed8936; padding: 1px 4px; border-radius: 3px; font-size: 0.65rem;" title="${escapeHtml(o.name || '')}">${o.id}</span>`).join('')}
                                </div>
                                <div class="threat-stats">
                                    <span class="threat-count">${threatCount} threats</span>
                                    <span class="intel-count">${intelCount} intel</span>
                                </div>
                            </div>
                        `;
            }).join('')}
                </div>
            `;

            domainGrid.appendChild(domainCard);
        }

        domainSection.appendChild(domainGrid);
        container.appendChild(domainSection);

        // Render by STRIDE
        const strideSection = document.createElement('div');
        strideSection.className = 'mcp-threat-stride-section';
        strideSection.innerHTML = '<h4>By STRIDE Category</h4>';

        const strideGrid = document.createElement('div');
        strideGrid.className = 'mcp-threat-stride-grid';

        const strideData = matrixData.matrix.stride;
        Object.keys(strideData).forEach(strideCategory => {
            const stride = strideData[strideCategory];
            const strideCard = document.createElement('div');
            strideCard.className = 'mcp-threat-stride-card';

            let strideThreatCount = 0;
            let strideIntelCount = 0;
            stride.threat_ids.forEach(mcpId => {
                if (threats[mcpId]) strideThreatCount += threats[mcpId].length;
                if (intel[mcpId]) strideIntelCount += intel[mcpId].length;
            });

            strideCard.innerHTML = `
                <div class="stride-header">
                    <h5>${strideCategory}</h5>
                    <span class="stride-count">${stride.count} threats</span>
                </div>
                <div class="stride-stats">
                    <span class="stat-item">Threats: ${strideThreatCount}</span>
                    <span class="stat-item">Intel: ${strideIntelCount}</span>
                </div>
                <div class="stride-threats">
                    ${stride.threat_ids.map(mcpId => {
                const threatIndex = stride.threat_ids.indexOf(mcpId);
                const threatName = stride.threat_names[threatIndex] || mcpId;
                return `<div class="mcp-threat-mini" data-mcp-id="${mcpId}" onclick="showMCPThreatDetails('${mcpId}')">${mcpId}: ${escapeHtml(threatName)}</div>`;
            }).join('')}
                </div>
            `;

            strideGrid.appendChild(strideCard);
        });

        strideSection.appendChild(strideGrid);
        container.appendChild(strideSection);

        // Store matrix data globally for detail view
        window.MCPThreatMatrixData = matrixData;

    } catch (error) {
        console.error('[MCPThreatMatrix] Error rendering MCP Threat ID Matrix:', error);
        container.innerHTML = `<div class="error-message">Failed to load MCP Threat Matrix: ${error.message}</div>`;
    }
}

/**
 * Get domain name by number
 */
function getDomainName(domainNum) {
    const domainNames = {
        1: 'Identity, Session & Transport Security',
        2: 'Access Control & Privilege Management',
        3: 'Input Validation & Sandbox Integrity',
        4: 'Data & Control Boundary Integrity',
        5: 'Supply Chain & Lifecycle Security',
        6: 'Data Exfiltration & Privacy Leakage',
        7: 'Resource Abuse & Observability Gaps'
    };
    return domainNames[domainNum] || `Domain ${domainNum}`;
}

/**
 * Show details for a specific MCP Threat ID
 */
async function showMCPThreatDetails(mcpThreatId) {
    try {
        console.log(`[MCPThreatMatrix] Loading details for ${mcpThreatId}`);
        const apiBase = getApiBase();
        const projectId = new URLSearchParams(window.location.search).get('project_id') || 'default-project';

        // Fetch both MCP threat details and OWASP mappings
        const [threatResponse, owaspResponse] = await Promise.all([
            fetch(`${apiBase}/mcp-threat-matrix/${mcpThreatId}?project_id=${projectId}`),
            fetch(`${apiBase}/owasp/mappings`)
        ]);

        if (!threatResponse.ok) {
            const errorData = await threatResponse.json().catch(() => ({}));
            throw new Error(errorData.error || `Failed to load threat details: ${threatResponse.statusText}`);
        }
        const data = await threatResponse.json();

        // Get OWASP mappings
        let owaspLlm = [];
        let owaspAgentic = [];
        if (owaspResponse.ok) {
            const owaspData = await owaspResponse.json();
            const mcpMapping = owaspData.mappings?.mappings?.[mcpThreatId] || {};
            owaspLlm = mcpMapping.owasp_llm || [];
            owaspAgentic = mcpMapping.owasp_agentic || [];
        }

        console.log(`[MCPThreatMatrix] Loaded details for ${mcpThreatId}:`, {
            threats_count: data.statistics?.threats_count || 0,
            intel_count: data.statistics?.intel_items_count || 0,
            threats: data.threats?.length || 0,
            intel_items: data.intel_items?.length || 0,
            owasp_llm: owaspLlm.length,
            owasp_agentic: owaspAgentic.length
        });

        // Create modal or detail view
        const modal = document.createElement('div');
        modal.className = 'mcp-threat-detail-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>${mcpThreatId}: ${escapeHtml(data.threat_name)}</h3>
                    <button class="modal-close" onclick="this.closest('.mcp-threat-detail-modal').remove()">×</button>
                </div>
                <div class="modal-body">
                    <div class="threat-info">
                        <div class="info-item">
                            <strong>Domain:</strong> ${data.domain ? `Domain ${data.domain}: ${getDomainName(data.domain)}` : 'N/A'}
                        </div>
                        <div class="info-item">
                            <strong>STRIDE:</strong> ${(data.stride_categories || []).join(', ') || 'N/A'}
                        </div>
                        <div class="info-item">
                            <strong>Risk Level:</strong> ${data.risk_level || 'N/A'}
                        </div>
                    </div>
                    
                    <!-- OWASP Mapping Section -->
                    <div class="owasp-mapping-section" style="margin-top: 16px; padding: 12px; background: var(--bg-tertiary); border-radius: 8px; border-left: 3px solid var(--accent-primary);">
                        <h4 style="margin: 0 0 12px 0; color: var(--text-primary); font-size: 1rem;">
                            🔗 OWASP Framework Mapping
                        </h4>
                        <div class="owasp-grids" style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                            <div class="owasp-llm-mapping">
                                <h5 style="margin: 0 0 8px 0; color: var(--accent-secondary); font-size: 0.9rem;">
                                    📘 OWASP LLM Top 10
                                </h5>
                                <div class="owasp-tags" style="display: flex; flex-wrap: wrap; gap: 6px;">
                                    ${owaspLlm.length > 0 ? owaspLlm.map(o => `
                                        <span class="owasp-tag owasp-llm-tag" style="background: rgba(66, 153, 225, 0.2); color: #4299e1; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; cursor: pointer;" 
                                              onclick="showOWASPDetails('llm', '${o.id}')" title="${escapeHtml(o.name)}">
                                            ${o.id}: ${escapeHtml(o.name)}
                                        </span>
                                    `).join('') : '<span style="color: var(--text-secondary); font-size: 0.85rem;">No mapping</span>'}
                                </div>
                            </div>
                            <div class="owasp-agentic-mapping">
                                <h5 style="margin: 0 0 8px 0; color: var(--accent-warning); font-size: 0.9rem;">
                                    🤖 OWASP Agentic Top 10
                                </h5>
                                <div class="owasp-tags" style="display: flex; flex-wrap: wrap; gap: 6px;">
                                    ${owaspAgentic.length > 0 ? owaspAgentic.map(o => `
                                        <span class="owasp-tag owasp-agentic-tag" style="background: rgba(237, 137, 54, 0.2); color: #ed8936; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; cursor: pointer;" 
                                              onclick="showOWASPDetails('agentic', '${o.id}')" title="${escapeHtml(o.name)}">
                                            ${o.id}: ${escapeHtml(o.name)}
                                        </span>
                                    `).join('') : '<span style="color: var(--text-secondary); font-size: 0.85rem;">No mapping</span>'}
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="threats-section">
                        <h4>Threats (${data.statistics.threats_count})</h4>
                        <div class="section-description" style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 12px; padding: 8px; background: var(--bg-secondary); border-radius: 4px;">
                            Structured threat objects with risk assessment, detection methods, and mitigation strategies. These can be generated from Intelligence Items or created manually.
                        </div>
                        <div class="threats-list">
                            ${(data.threats || []).length > 0 ? (data.threats || []).map(t => {
            const convertedFromIntel = t.schema_data?.source_intel_ids || t.converted_from_intel_id;
            return `
                                <div class="threat-item" onclick="showThreatDetails('${t.id}'); return false;" style="cursor: pointer;">
                                    <div class="threat-name">${escapeHtml(t.name || t.title || 'Unknown')}</div>
                                    <div class="threat-desc">${escapeHtml((t.description || '').substring(0, 200))}${(t.description || '').length > 200 ? '...' : ''}</div>
                                    <div class="threat-meta" style="margin-top: 8px; font-size: 0.85rem; color: var(--text-secondary);">
                                        ${t.risk_level ? `<span class="risk-badge risk-${(t.risk_level || 'medium').toLowerCase()}" style="margin-right: 8px;">${t.risk_level}</span>` : ''}
                                        ${t.stride_category ? `<span>STRIDE: ${t.stride_category}</span>` : ''}
                                        ${convertedFromIntel ? `<span style="margin-left: 8px; color: var(--accent-primary);">📥 From Intel</span>` : ''}
                                    </div>
                                </div>
                            `;
        }).join('') : '<div class="no-threats-message" style="padding: 20px; text-align: center; color: var(--text-secondary);">No threats mapped to this MCP Threat ID yet. Threats will appear here once they are classified or generated.</div>'}
                        </div>
                    </div>
                    <div class="intel-section">
                        <h4>Intelligence Items (${data.statistics.intel_items_count})</h4>
                        <div class="section-description" style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 12px; padding: 8px; background: var(--bg-secondary); border-radius: 4px;">
                            Raw intelligence data (GitHub, CVE, research papers, etc.) that can be mapped directly to this MCP Threat ID. These can be converted to structured Threats using "Generate Threats from Intel" in the Threat Intel page.
                        </div>
                        <div class="intel-list">
                            ${(data.intel_items || []).length > 0 ? (data.intel_items || []).map(i => {
            const sourceUrl = i.source_url || i.url || '#';
            const isValidUrl = sourceUrl &&
                sourceUrl !== '#' &&
                !sourceUrl.includes('localhost') &&
                !sourceUrl.includes('127.0.0.1') &&
                (sourceUrl.startsWith('http://') || sourceUrl.startsWith('https://'));
            const sourceType = i.source_type || i.source || 'Unknown';

            return `
                                <div class="intel-item">
                                    <div class="intel-header">
                                        <div class="intel-title">
                                            ${isValidUrl ?
                    `<a href="${sourceUrl}" target="_blank" rel="noopener noreferrer" class="intel-link">${escapeHtml(i.title || 'Untitled')}</a>` :
                    escapeHtml(i.title || 'Untitled')
                }
                                        </div>
                                        <div class="intel-source">
                                            <span class="intel-source-type">${escapeHtml(sourceType)}</span>
                                            ${isValidUrl ?
                    `<a href="${sourceUrl}" target="_blank" rel="noopener noreferrer" class="intel-source-link" title="${escapeHtml(sourceUrl)}">🔗 View Source</a>` :
                    ''
                }
                                        </div>
                                    </div>
                                    <div class="intel-summary">${escapeHtml((i.ai_summary || i.content || '').substring(0, 150))}${((i.ai_summary || i.content || '').length > 150) ? '...' : ''}</div>
                                </div>
                            `;
        }).join('') : '<div class="no-intel-message" style="padding: 20px; text-align: center; color: var(--text-secondary);">No intelligence items mapped to this MCP Threat ID yet.</div>'}
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });

    } catch (error) {
        console.error('[MCPThreatMatrix] Error showing threat details:', error);
        showNotification(`Failed to load threat details: ${error.message}`, 'error');
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Render workflow phase view
 */
function renderWorkflowPhaseView() {
    const container = document.getElementById('mcp-workflow-phase-view');
    if (!container) return;

    container.innerHTML = '<h3>MCP Workflow Phase Distribution</h3>';

    const phaseStats = {};
    MCP_WORKFLOW_PHASES.forEach(phase => {
        const threats = MCPThreatMatrixState.workflowPhases[phase] || [];
        phaseStats[phase] = threats.length;
    });

    const maxCount = Math.max(...Object.values(phaseStats), 1);

    const statsDiv = document.createElement('div');
    statsDiv.className = 'workflow-phase-stats';
    statsDiv.innerHTML = `
        <div class="phase-stats-grid">
            ${MCP_WORKFLOW_PHASES.map(phase => {
        const count = phaseStats[phase] || 0;
        const percentage = maxCount > 0 ? (count / maxCount * 100) : 0;
        return `
                    <div class="phase-stat-item">
                        <div class="phase-name">${phase}</div>
                        <div class="phase-count">${count} threats</div>
                        <div class="phase-bar">
                            <div class="phase-bar-fill" style="width: ${percentage}%"></div>
                        </div>
        </div>
                `;
    }).join('')}
        </div>
    `;
    container.appendChild(statsDiv);
}

/**
 * Render MSB Attack Type Matrix
 */
// MCPSecBench Surfaces & 17 Attack Types (Exact mapping from Paper)
const MCP_SEC_BENCH_SURFACES = {
    'User Interaction': [
        'Prompt Injection',
        'Tool/Service Misuse'
    ],
    'Client Surface': [
        'Schema Inconsistencies',
        'Slash Command Overlap',
        'Vulnerable Client Exploitation'
    ],
    'Protocol Surface': [
        'MCP Rebinding',
        'Man-in-the-Middle (MitM)'
    ],
    'Server Surface': [
        'Tool Shadowing',
        'Data Exfiltration via Metadata',
        'Package Name Squatting (Tool Level)',
        'Indirect Prompt Injection',
        'Package Name Squatting (Server Level)',
        'Configuration Drift',
        'Sandbox Escape',
        'Tool Poisoning',
        'Vulnerable Server Exploitation',
        'Rug Pull Attack'
    ]
};

/**
 * Render MCPSecBench Taxonomy Matrix (4 Surfaces x 17 Types)
 */
function renderMSBAttackTypeMatrix() {
    const container = document.getElementById('msb-attack-type-matrix');
    if (!container) return;

    container.innerHTML = '<h3>MCPSecBench Taxonomy (4 Surfaces × 17 Attack Types)</h3>';

    // Add description
    const description = document.createElement('p');
    description.className = 'matrix-description';
    description.textContent = 'Threat distribution across the 4 MCPSecBench Attack Surfaces. Click directly on cells to filter threats.';
    container.appendChild(description);

    // Create matrix container
    const matrixGrid = document.createElement('div');
    matrixGrid.className = 'msb-taxonomy-grid';
    matrixGrid.style.display = 'grid';
    matrixGrid.style.gridTemplateColumns = 'repeat(2, 1fr)'; // 2 Columns of Surfaces
    matrixGrid.style.gap = '20px';
    matrixGrid.style.marginTop = '20px';

    // Iterate 4 Surfaces
    Object.entries(MCP_SEC_BENCH_SURFACES).forEach(([surfaceName, attackTypes]) => {
        const surfaceCard = document.createElement('div');
        surfaceCard.className = 'surface-card';
        surfaceCard.style.background = 'var(--bg-secondary)';
        surfaceCard.style.padding = '15px';
        surfaceCard.style.borderRadius = '8px';
        surfaceCard.style.border = '1px solid var(--border-color)';

        // Surface Header
        const header = document.createElement('h4');
        header.textContent = surfaceName;
        header.style.color = 'var(--text-primary)';
        header.style.marginBottom = '12px';
        header.style.borderBottom = '2px solid var(--primary)';
        header.style.paddingBottom = '8px';
        surfaceCard.appendChild(header);

        // List of Attacks
        const attackList = document.createElement('div');
        attackList.className = 'attack-list';
        attackList.style.display = 'flex';
        attackList.style.flexDirection = 'column';
        attackList.style.gap = '8px';

        attackTypes.forEach(type => {
            // Count threats for this type
            // Note: We need to filter threats by 'msb_attack_type' which matches the string 'type'
            const count = MCPThreatMatrixState.threats.filter(t => t.msb_attack_type === type).length;

            const item = document.createElement('div');
            item.className = 'attack-item';
            item.style.display = 'flex';
            item.style.justifyContent = 'space-between';
            item.style.padding = '8px';
            item.style.background = count > 0 ? 'rgba(59, 130, 246, 0.1)' : 'rgba(255,255,255,0.02)';
            item.style.borderRadius = '4px';
            item.style.cursor = 'pointer';
            item.onclick = () => filterThreatsByAttackType(type);

            item.innerHTML = `
                <span style="font-size: 0.9em;">${type}</span>
                <span style="font-weight: bold; color: ${count > 0 ? 'var(--primary)' : 'var(--text-muted)'}">${count}</span>
            `;
            attackList.appendChild(item);
        });

        surfaceCard.appendChild(attackList);
        matrixGrid.appendChild(surfaceCard);
    });

    container.appendChild(matrixGrid);
}
// Placeholder for filter function if not exists
if (typeof filterThreatsByAttackType === 'undefined') {
    window.filterThreatsByAttackType = function (type) {
        console.log('Filtering by type:', type);
        // Implement filtering logic if needed or reused
        alert(`Filtering threats by: ${type}`);
    };
}



/**
 * Render Threat Vector Matrix
 */
function renderThreatVectorMatrix() {
    const container = document.getElementById('threat-vector-matrix');
    if (!container) return;

    container.innerHTML = '<h3>Threat Vector Distribution</h3>';

    const vectorStats = {};
    THREAT_VECTORS.forEach(vector => {
        const threats = MCPThreatMatrixState.threatVectors[vector] || [];
        vectorStats[vector] = threats.length;
    });

    const maxCount = Math.max(...Object.values(vectorStats), 1);

    const statsDiv = document.createElement('div');
    statsDiv.className = 'threat-vector-stats';
    statsDiv.innerHTML = `
        <div class="vector-stats-grid">
            ${THREAT_VECTORS.map(vector => {
        const count = vectorStats[vector] || 0;
        const percentage = maxCount > 0 ? (count / maxCount * 100) : 0;
        return `
                    <div class="vector-stat-item">
                        <div class="vector-name">${vector}</div>
                        <div class="vector-count">${count} threats</div>
                        <div class="vector-bar">
                            <div class="vector-bar-fill" style="width: ${percentage}%"></div>
                        </div>
                    </div>
                `;
    }).join('')}
        </div>
    `;
    container.appendChild(statsDiv);
}

/**
 * Render MCP-UPD Attack Chains
 */
function renderMCPUPDChains() {
    const container = document.getElementById('mcp-upd-chains');
    if (!container) return;

    container.innerHTML = '<h3>MCP-UPD Attack Chains (Parasitic Tool Chains)</h3>';

    // Find threats with MCP-UPD classification
    const updThreats = MCPThreatMatrixState.threats.filter(t => {
        return t.mcp_upd_phase || t.schema_data?.mcp_upd_phase;
    });

    if (updThreats.length === 0) {
        container.innerHTML += '<p class="no-data">No MCP-UPD attack chains identified yet.</p>';
        return;
    }

    // Group by phase and deduplicate threats with improved logic
    const phaseGroups = {};

    // Helper function to normalize threat name for comparison
    function normalizeThreatName(name) {
        if (!name) return '';
        return name.trim()
            .toLowerCase()
            .replace(/\s+/g, ' ')  // Normalize whitespace
            .replace(/[^\w\s]/g, '')  // Remove special characters
            .substring(0, 100);  // Limit length for comparison
    }

    // Helper function to check if two threats are duplicates
    function isDuplicateThreat(threat1, threat2) {
        const name1 = normalizeThreatName(threat1.name);
        const name2 = normalizeThreatName(threat2.name);

        // Exact normalized name match
        if (name1 === name2 && name1.length > 0) return true;

        // Check if names are very similar (one contains the other with high overlap)
        if (name1.length > 15 && name2.length > 15) {
            // Calculate similarity: check if one name contains most of the other
            const shorter = name1.length < name2.length ? name1 : name2;
            const longer = name1.length >= name2.length ? name1 : name2;

            // If shorter name is 80%+ contained in longer name, consider duplicate
            if (longer.includes(shorter) && shorter.length / longer.length > 0.8) {
                return true;
            }

            // Check word overlap
            const words1 = name1.split(/\s+/).filter(w => w.length > 3);
            const words2 = name2.split(/\s+/).filter(w => w.length > 3);
            if (words1.length > 0 && words2.length > 0) {
                const commonWords = words1.filter(w => words2.includes(w));
                const overlapRatio = commonWords.length / Math.min(words1.length, words2.length);
                // If 70%+ words overlap, consider duplicate
                if (overlapRatio >= 0.7 && commonWords.length >= 3) {
                    return true;
                }
            }
        }

        return false;
    }

    MCP_UPD_PHASES.forEach(phase => {
        phaseGroups[phase] = [];
        const seenInPhase = [];  // Track threats in this phase to avoid duplicates

        updThreats.forEach(t => {
            const tPhase = t.mcp_upd_phase || t.schema_data?.mcp_upd_phase;
            if (tPhase !== phase) return;

            // Check if this threat is a duplicate of any already seen threat in this phase
            const isDuplicate = seenInPhase.some(seenThreat => isDuplicateThreat(t, seenThreat));
            if (isDuplicate) {
                console.log(`[MCP-UPD] Skipping duplicate threat: "${t.name}" (similar to existing threat)`);
                return;  // Skip duplicates
            }

            seenInPhase.push(t);
            phaseGroups[phase].push(t);
        });
    });

    // Render chain visualization
    const chainDiv = document.createElement('div');
    chainDiv.className = 'upd-chain-visualization';

    MCP_UPD_PHASES.forEach((phase, index) => {
        const threats = phaseGroups[phase] || [];
        if (threats.length === 0 && index < MCP_UPD_PHASES.length - 1) return;  // Skip empty phases except last

        const phaseInfo = MCP_UPD_PHASE_INFO[phase] || {};
        const toolTypes = phaseInfo.toolTypes || [];
        const attackTypes = phaseInfo.attackTypes || [];
        const description = phaseInfo.description || '';

        const phaseDiv = document.createElement('div');
        phaseDiv.className = 'upd-phase';

        // Phase header
        const headerDiv = document.createElement('div');
        headerDiv.className = 'upd-phase-header';
        headerDiv.innerHTML = `
            <div class="upd-phase-title">
                <h4>${phase}</h4>
                ${description ? `<div class="phase-description">${description}</div>` : ''}
                ${toolTypes.length > 0 ? `<div class="tool-types">
                    <strong>Tool Types:</strong> ${toolTypes.join(', ')}
                </div>` : ''}
                ${attackTypes.length > 0 ? `<div class="attack-types">
                    <strong>Attack Types:</strong> ${attackTypes.join(', ')}
                </div>` : ''}
                        </div>
            <span class="threat-count-badge">${threats.length} threat${threats.length !== 1 ? 's' : ''}</span>
        `;
        phaseDiv.appendChild(headerDiv);

        // Scrollable threats list with rich content
        const threatsListDiv = document.createElement('div');
        threatsListDiv.className = 'upd-threats-list scrollable-threats';

        if (threats.length > 0) {
            threats.forEach(t => {
                const threatItem = document.createElement('div');
                threatItem.className = 'upd-threat-card';

                const threatName = t.name || 'Unnamed Threat';
                const riskLevel = (t.risk_level || 'medium').toLowerCase();
                const description = t.description || t.schema_data?.description || '';
                const attackType = t.msb_attack_type || t.schema_data?.msb_attack_type || 'N/A';
                const workflowPhase = t.mcp_workflow_phase || t.schema_data?.mcp_workflow_phase || 'N/A';

                // Handle impact - can be array, string, or object
                let impact = t.impact || t.schema_data?.impact || [];
                if (typeof impact === 'string') {
                    impact = [impact];
                } else if (!Array.isArray(impact)) {
                    impact = impact ? [impact] : [];
                }

                // Handle mitigations - can be array, string, or object
                let mitigations = t.mitigations || t.schema_data?.mitigations || [];
                if (typeof mitigations === 'string') {
                    mitigations = [mitigations];
                } else if (!Array.isArray(mitigations)) {
                    mitigations = mitigations ? [mitigations] : [];
                }

                threatItem.innerHTML = `
                    <div class="threat-card-header">
                        <h5 class="threat-card-name" onclick="showThreatDetails('${t.id}'); return false;" style="cursor: pointer;">
                            ${threatName}
                        </h5>
                        <span class="risk-badge risk-${riskLevel}">${t.risk_level || 'Medium'}</span>
                    </div>
                    <div class="threat-card-body">
                        ${description ? `<p class="threat-description">${truncateText(description, 150)}</p>` : ''}
                        <div class="threat-meta">
                            <span class="meta-item">
                                <strong>Attack Type:</strong> ${attackType}
                            </span>
                            <span class="meta-item">
                                <strong>Phase:</strong> ${workflowPhase}
                            </span>
                        </div>
                        ${impact.length > 0 ? `
                            <div class="threat-impact">
                                <strong>Impact:</strong>
                                <ul>
                                    ${impact.slice(0, 3).map(imp => `<li>${typeof imp === 'string' ? imp : imp.description || imp}</li>`).join('')}
                                </ul>
                            </div>
                        ` : ''}
                        ${mitigations.length > 0 ? `
                            <div class="threat-mitigations">
                                <strong>Mitigations:</strong>
                                <ul>
                                    ${mitigations.slice(0, 2).map(mit => `<li>${typeof mit === 'string' ? mit : mit.description || mit}</li>`).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                `;
                threatsListDiv.appendChild(threatItem);
            });
        } else {
            threatsListDiv.innerHTML = '<div class="no-threats-in-phase">No threats identified in this phase</div>';
        }

        phaseDiv.appendChild(threatsListDiv);

        if (index < MCP_UPD_PHASES.length - 1) {
            const arrow = document.createElement('div');
            arrow.className = 'chain-arrow';
            arrow.textContent = '→';
            chainDiv.appendChild(phaseDiv);
            chainDiv.appendChild(arrow);
        } else {
            chainDiv.appendChild(phaseDiv);
        }
    });

    container.appendChild(chainDiv);
}

/**
 * Render Preference Manipulation Attacks
 */
function renderMPMAAttacks() {
    const container = document.getElementById('mpma-attacks');
    if (!container) return;

    container.innerHTML = '<h3>Preference Manipulation Attacks</h3>';

    // Find threats related to preference manipulation - use broader matching
    const mpmaThreats = MCPThreatMatrixState.threats.filter(t => {
        const attackType = t.mpma_attack_type || t.schema_data?.mpma_attack_type || '';
        const threatVector = t.threat_vector || t.schema_data?.threat_vector || t.category || '';
        const msbAttackType = t.msb_attack_type || t.schema_data?.msb_attack_type || '';
        const description = (t.description || '').toLowerCase();
        const name = (t.name || '').toLowerCase();

        // Check explicit MPMA classification
        if (attackType) return true;

        // Check if MSB attack type is Preference Manipulation
        if (msbAttackType && (msbAttackType.includes('Preference Manipulation') || msbAttackType.includes('PM'))) {
            return true;
        }

        // Check threat vector
        if (threatVector.includes('Preference') || threatVector.includes('Manipulation')) {
            return true;
        }

        // Check content for preference manipulation keywords
        const keywords = ['preference manipulation', 'preference attack', 'manipulation attack',
            'preference bias', 'tool preference', 'server preference', 'gapma', 'dpma'];
        return keywords.some(keyword =>
            description.includes(keyword) || name.includes(keyword)
        );
    });

    if (mpmaThreats.length === 0) {
        container.innerHTML += '<p class="no-data">No preference manipulation attacks identified yet.</p>';
        return;
    }

    // Group by manipulation type - use PREFERENCE_MANIPULATION_TYPES
    const typeGroups = {};
    PREFERENCE_MANIPULATION_TYPES.forEach(type => {
        typeGroups[type] = mpmaThreats.filter(t => {
            const tType = t.mpma_attack_type || t.schema_data?.mpma_attack_type || '';
            const description = (t.description || '').toLowerCase();
            const name = (t.name || '').toLowerCase();
            const typeLower = type.toLowerCase();

            return tType.includes(type) ||
                description.includes(typeLower) ||
                name.includes(typeLower) ||
                (type.includes('Direct') && (tType.includes('DPMA') || description.includes('direct preference'))) ||
                (type.includes('Genetic') && (tType.includes('GAPMA') || description.includes('genetic algorithm')));
        });
    });

    // Render breakdown - only show types with threats
    const breakdownDiv = document.createElement('div');
    breakdownDiv.className = 'mpma-breakdown';

    PREFERENCE_MANIPULATION_TYPES.forEach(type => {
        const threats = typeGroups[type] || [];
        if (threats.length === 0) return;  // Skip empty types

        const isGAPMA = type.includes('Genetic Algorithm');

        const typeDiv = document.createElement('div');
        typeDiv.className = 'mpma-type-group';
        typeDiv.innerHTML = `
            <div class="mpma-type-header">
                <h4>${type}</h4>
                <span class="threat-count-badge">${threats.length}</span>
                </div>
            ${isGAPMA ? renderGAPMAStrategies(threats) : ''}
            <div class="mpma-threats-list">
                ${threats.slice(0, 5).map(t => {
            const asrScore = t.asr_score || t.schema_data?.asr_score || 0;
            const riskLevel = t.risk_level || 'medium';
            return `
                    <div class="mpma-threat-item">
                        <span class="threat-name">${t.name || 'Unnamed Threat'}</span>
                        ${asrScore > 0 ? `<span class="asr-score">ASR: ${asrScore.toFixed(2)}</span>` : ''}
                        <span class="risk-badge risk-${riskLevel.toLowerCase()}">${riskLevel}</span>
                </div>
                `;
        }).join('')}
                ${threats.length > 5 ? `<div class="more-threats">+${threats.length - 5} more</div>` : ''}
            </div>
        `;
        breakdownDiv.appendChild(typeDiv);
    });

    container.appendChild(breakdownDiv);
}

/**
 * Render GAPMA strategies breakdown
 */
function renderGAPMAStrategies(gapmaThreats) {
    const strategyGroups = {};
    GAPMA_STRATEGIES.forEach(strategy => {
        strategyGroups[strategy] = gapmaThreats.filter(t => {
            const tStrategy = t.gapma_strategy || t.schema_data?.gapma_strategy || '';
            const strategyLower = strategy.toLowerCase();
            return tStrategy.toLowerCase().includes(strategyLower) ||
                tStrategy === strategy;
        });
    });

    return `
        <div class="gapma-strategies">
            ${GAPMA_STRATEGIES.map(strategy => {
        const count = strategyGroups[strategy]?.length || 0;
        const isAuthoritative = strategy.includes('Authoritative');
        return `
                    <div class="gapma-strategy-item ${isAuthoritative ? 'high-risk' : ''}">
                        <span class="strategy-name">${strategy}</span>
                        <span class="strategy-count">${count}</span>
                        ${isAuthoritative ? '<span class="high-risk-badge">Highest Risk</span>' : ''}
                    </div>
                `;
    }).join('')}
        </div>
    `;
}

/**
 * Render Intelligence to Threat Mapping with search and pagination
 */
let intelMappingState = {
    allMappings: [],
    filteredMappings: [],
    currentPage: 1,
    itemsPerPage: 20,
    searchQuery: ''
};

function renderIntelToThreatMapping() {
    const container = document.getElementById('intel-to-threat-mapping');
    if (!container) return;

    container.innerHTML = '<h3>Intelligence Items to Threat Mapping</h3>';

    // Build mapping - support multiple formats and fuzzy matching
    const mapping = [];
    const seenPairs = new Set();  // Track unique threat-intel pairs to avoid duplicates

    MCPThreatMatrixState.threats.forEach(threat => {
        // Get intel IDs from multiple possible locations
        let intelIds = threat.source_intel_ids ||
            threat.schema_data?.source_intel_ids ||
            threat.metadata?.source_intel_ids ||
            [];

        // Handle both array and string formats
        if (typeof intelIds === 'string') {
            try {
                intelIds = JSON.parse(intelIds);
            } catch {
                intelIds = [intelIds];
            }
        }
        if (!Array.isArray(intelIds)) {
            intelIds = intelIds ? [intelIds] : [];
        }

        // Direct ID matching
        intelIds.forEach(intelId => {
            const intelIdStr = String(intelId);
            const pairKey = `${threat.id}-${intelIdStr}`;

            if (seenPairs.has(pairKey)) return;  // Skip duplicates
            seenPairs.add(pairKey);

            const intelItem = MCPThreatMatrixState.intelItems.find(i =>
                String(i.id) === intelIdStr || String(i.id) === String(intelId)
            );

            if (intelItem) {
                mapping.push({
                    threat: threat,
                    intel: intelItem
                });
            }
        });

        // Fuzzy matching by title/content if no direct mapping found
        if (intelIds.length === 0) {
            const threatName = (threat.name || '').toLowerCase();
            const threatDesc = (threat.description || '').toLowerCase();

            MCPThreatMatrixState.intelItems.forEach(intelItem => {
                const pairKey = `${threat.id}-${intelItem.id}`;
                if (seenPairs.has(pairKey)) return;  // Skip if already mapped

                const intelTitle = (intelItem.title || '').toLowerCase();
                const intelContent = (intelItem.content || intelItem.ai_summary || '').toLowerCase();

                // Check for significant overlap in keywords
                const threatWords = threatName.split(/\s+/).filter(w => w.length > 4);
                const matchingWords = threatWords.filter(word =>
                    intelTitle.includes(word) || intelContent.includes(word)
                );

                if (matchingWords.length >= 2 || threatName.includes(intelTitle.substring(0, 20))) {
                    seenPairs.add(pairKey);
                    mapping.push({
                        threat: threat,
                        intel: intelItem
                    });
                }
            });
        }
    });

    // Store all mappings for search and pagination
    intelMappingState.allMappings = mapping;
    intelMappingState.currentPage = 1;  // Reset to first page

    if (mapping.length === 0) {
        container.innerHTML += '<p class="no-data">No intelligence-to-threat mappings found.</p>';
        return;
    }

    // Add search box
    const searchDiv = document.createElement('div');
    searchDiv.className = 'intel-mapping-search';
    searchDiv.innerHTML = `
        <input type="text" id="intel-mapping-search-input" 
               placeholder="Search by threat name, intel title, or source..." 
               class="intel-search-input"
               onkeyup="filterIntelMapping()">
        <span class="search-results-count" id="intel-mapping-count">${mapping.length} mappings</span>
    `;
    container.appendChild(searchDiv);

    // Apply search filter and render table
    filterIntelMapping();
}

function filterIntelMapping() {
    const searchInput = document.getElementById('intel-mapping-search-input');
    const container = document.getElementById('intel-to-threat-mapping');
    if (!container || !searchInput) return;

    const query = searchInput.value.toLowerCase().trim();
    intelMappingState.searchQuery = query;

    // Filter mappings
    if (query) {
        intelMappingState.filteredMappings = intelMappingState.allMappings.filter(item => {
            const threat = item.threat;
            const intel = item.intel;
            const threatName = (threat.name || '').toLowerCase();
            const intelTitle = (intel.title || '').toLowerCase();
            const intelSource = (intel.source || '').toLowerCase();
            const attackType = (threat.msb_attack_type || threat.schema_data?.msb_attack_type || '').toLowerCase();
            const phase = (threat.mcp_workflow_phase || threat.schema_data?.mcp_workflow_phase || '').toLowerCase();

            return threatName.includes(query) ||
                intelTitle.includes(query) ||
                intelSource.includes(query) ||
                attackType.includes(query) ||
                phase.includes(query);
        });
    } else {
        intelMappingState.filteredMappings = intelMappingState.allMappings;
    }

    // Reset to first page when filtering
    intelMappingState.currentPage = 1;

    // Update count
    const countEl = document.getElementById('intel-mapping-count');
    if (countEl) {
        countEl.textContent = `${intelMappingState.filteredMappings.length} of ${intelMappingState.allMappings.length} mappings`;
    }

    // Render table with pagination
    renderIntelMappingTable();
}

function renderIntelMappingTable() {
    const container = document.getElementById('intel-to-threat-mapping');
    if (!container) return;

    // Remove existing table wrapper if any
    const existingWrapper = container.querySelector('.intel-mapping-table-wrapper');
    if (existingWrapper) {
        existingWrapper.remove();
    }

    const mappings = intelMappingState.filteredMappings;
    const totalPages = Math.ceil(mappings.length / intelMappingState.itemsPerPage);
    const startIdx = (intelMappingState.currentPage - 1) * intelMappingState.itemsPerPage;
    const endIdx = startIdx + intelMappingState.itemsPerPage;
    const pageMappings = mappings.slice(startIdx, endIdx);

    // Create table wrapper
    const wrapper = document.createElement('div');
    wrapper.className = 'intel-mapping-table-wrapper';

    // Create table
    const table = document.createElement('table');
    table.className = 'intel-mapping-table';

    // Header
    const headerRow = document.createElement('tr');
    headerRow.innerHTML = `
        <th>Threat</th>
        <th>Workflow Phase</th>
        <th>Attack Type</th>
        <th>Risk Level</th>
        <th>Intel Title</th>
    `;
    table.appendChild(headerRow);

    // Rows
    pageMappings.forEach(item => {
        const row = document.createElement('tr');
        const threat = item.threat;
        const intel = item.intel;

        // Get source URL - prefer source_url, fallback to url, or use #
        const sourceUrl = intel.source_url || intel.url || '#';
        // Only use URL if it's a valid external URL (not localhost/127.0.0.1)
        const isValidUrl = sourceUrl &&
            sourceUrl !== '#' &&
            !sourceUrl.includes('localhost') &&
            !sourceUrl.includes('127.0.0.1') &&
            (sourceUrl.startsWith('http://') || sourceUrl.startsWith('https://'));

        // Get workflow phase - check multiple possible locations with extensive fallback
        let workflowPhase = threat.mcp_workflow_phase ||
            threat.workflow_phase ||
            threat.metadata?.mcp_workflow_phase ||
            threat.metadata?.workflow_phase;

        // Check schema_data (can be object or string)
        if (!workflowPhase && threat.schema_data) {
            if (typeof threat.schema_data === 'string') {
                try {
                    const parsed = JSON.parse(threat.schema_data);
                    workflowPhase = parsed.mcp_workflow_phase ||
                        parsed.workflow_phase ||
                        parsed.workflowPhase;
                } catch (e) {
                    // Not JSON, ignore
                }
            } else if (typeof threat.schema_data === 'object') {
                workflowPhase = threat.schema_data.mcp_workflow_phase ||
                    threat.schema_data.workflow_phase ||
                    threat.schema_data.workflowPhase;
            }
        }

        // If still not found, try to infer from description or name
        if (!workflowPhase || workflowPhase === 'N/A') {
            const desc = (threat.description || '').toLowerCase();
            const name = (threat.name || '').toLowerCase();

            // Map old phase names to new ones for backward compatibility
            if (desc.includes('response') || desc.includes('output') || desc.includes('exfiltration')) {
                workflowPhase = 'Response Handling / Output Processing';
            } else if (desc.includes('execution') || desc.includes('runtime') || desc.includes('command injection')) {
                workflowPhase = 'Tool Execution / Runtime / External Resource Interaction';
            } else if (desc.includes('invocation') || desc.includes('parameter') || desc.includes('tool call')) {
                workflowPhase = 'Tool Invocation / Call Request';
            } else if (desc.includes('tool chain') || desc.includes('orchestration') || desc.includes('multi-tool')) {
                workflowPhase = 'Tool-Chain Orchestration / Multi-Tool Workflow';
            } else if (desc.includes('definition') || desc.includes('registration') || desc.includes('tool creation')) {
                workflowPhase = 'Tool Definition / Registration';
            } else if (desc.includes('catalog') || desc.includes('discovery') || desc.includes('metadata')) {
                workflowPhase = 'Tool Catalog / Discovery / Metadata Exposure';
            } else if (desc.includes('supply chain') || desc.includes('dependency') || desc.includes('update')) {
                workflowPhase = 'Supply-Chain / Dependency / Update / Deployment';
            } else if (desc.includes('infrastructure') || desc.includes('configuration') || desc.includes('deployment')) {
                workflowPhase = 'Infrastructure / Configuration / Deployment Environment';
            } else {
                workflowPhase = 'N/A';
            }
        }

        // Get attack type - check multiple possible locations with extensive fallback
        let attackType = threat.msb_attack_type ||
            threat.attack_type ||
            threat.metadata?.msb_attack_type ||
            threat.metadata?.attack_type;

        // Check schema_data (can be object or string)
        if (!attackType && threat.schema_data) {
            if (typeof threat.schema_data === 'string') {
                try {
                    const parsed = JSON.parse(threat.schema_data);
                    attackType = parsed.msb_attack_type ||
                        parsed.attack_type ||
                        parsed.attackType;
                } catch (e) {
                    // Not JSON, ignore
                }
            } else if (typeof threat.schema_data === 'object') {
                attackType = threat.schema_data.msb_attack_type ||
                    threat.schema_data.attack_type ||
                    threat.schema_data.attackType;
            }
        }

        // If still not found, try to infer from description or name
        if (!attackType || attackType === 'N/A') {
            const desc = (threat.description || '').toLowerCase();
            const name = (threat.name || '').toLowerCase();
            const phaseLower = (workflowPhase || '').toLowerCase();

            // Infer based on workflow phase and keywords
            if (phaseLower.includes('response handling') || phaseLower.includes('output processing')) {
                if (desc.includes('exfiltration') || desc.includes('data leak')) {
                    attackType = 'Data Exfiltration / Sensitive Data Leakage';
                } else if (desc.includes('impersonation')) {
                    attackType = 'User Impersonation';
                } else if (desc.includes('fake error')) {
                    attackType = 'Fake Error';
                } else if (desc.includes('retrieval')) {
                    attackType = 'Retrieval Injection';
                } else {
                    attackType = 'Output Manipulation';
                }
            } else if (phaseLower.includes('tool execution') || phaseLower.includes('runtime')) {
                if (desc.includes('command injection') || desc.includes('code injection') || desc.includes('rce')) {
                    attackType = 'Command Injection / Code Injection / RCE via Tool';
                } else if (desc.includes('path traversal') || desc.includes('filesystem')) {
                    attackType = 'Path Traversal / Filesystem Abuse';
                } else if (desc.includes('ssrf') || desc.includes('network') || desc.includes('external api')) {
                    attackType = 'Network / External API Abuse / SSRF / Exfiltration';
                } else if (desc.includes('privilege') || desc.includes('authorization')) {
                    attackType = 'Privilege Escalation / Authorization Bypass';
                } else {
                    attackType = 'Command Injection / Code Injection / RCE via Tool';
                }
            } else if (phaseLower.includes('tool invocation') || phaseLower.includes('call request')) {
                if (desc.includes('parameter abuse') || desc.includes('out-of-scope')) {
                    attackType = 'Parameter Abuse / Out-of-Scope Argument';
                } else if (desc.includes('prompt injection')) {
                    attackType = 'Prompt Injection (in metadata / tool description / user input)';
                } else if (desc.includes('tool-call injection')) {
                    attackType = 'Tool-Call Injection';
                } else {
                    attackType = 'Parameter Abuse / Out-of-Scope Argument';
                }
            } else if (phaseLower.includes('tool definition') || phaseLower.includes('registration')) {
                if (desc.includes('tool poisoning') || desc.includes('malicious tool')) {
                    attackType = 'Tool Poisoning / Malicious Tool';
                } else if (desc.includes('name collision') || desc.includes('tool spoofing')) {
                    attackType = 'Name-Collision / Tool Spoofing';
                } else if (desc.includes('metadata poisoning') || desc.includes('description poisoning')) {
                    attackType = 'Metadata / Description Poisoning';
                } else {
                    attackType = 'Schema Inconsistencies';
                }
            } else {
                attackType = 'N/A';
            }
        }

        row.innerHTML = `
            <td class="threat-name-cell">
                <a href="#" onclick="showThreatDetails('${threat.id}'); return false;" title="${threat.name || 'Unnamed Threat'}">
                    ${truncateText(threat.name || 'Unnamed Threat', 40)}
                </a>
            </td>
            <td class="phase-cell">${workflowPhase}</td>
            <td class="attack-type-cell">${attackType}</td>
            <td class="risk-cell">
                <span class="risk-badge risk-${(threat.risk_level || 'medium').toLowerCase()}">
                    ${threat.risk_level || 'Medium'}
                </span>
            </td>
            <td class="intel-title-cell">
                <div class="intel-cell-content">
                    <a href="${isValidUrl ? sourceUrl : '#'}" 
                       ${isValidUrl ? 'target="_blank" rel="noopener noreferrer"' : ''}
                       class="intel-title-link"
                       title="${intel.title || ''}">
                        ${truncateText(intel.title || 'Untitled', 50)}
                    </a>
                    <div class="intel-source-info">
                        <span class="intel-source-badge">${escapeHtml(intel.source_type || intel.source || 'Unknown')}</span>
                        ${isValidUrl ?
                `<a href="${sourceUrl}" target="_blank" rel="noopener noreferrer" class="intel-source-link" title="${escapeHtml(sourceUrl)}">🔗</a>` :
                ''
            }
                    </div>
                </div>
            </td>
        `;
        table.appendChild(row);
    });

    wrapper.appendChild(table);

    // Add pagination
    if (totalPages > 1) {
        const paginationDiv = document.createElement('div');
        paginationDiv.className = 'intel-mapping-pagination';

        const prevBtn = document.createElement('button');
        prevBtn.className = 'pagination-btn';
        prevBtn.textContent = '← Previous';
        prevBtn.disabled = intelMappingState.currentPage === 1;
        prevBtn.onclick = () => {
            if (intelMappingState.currentPage > 1) {
                intelMappingState.currentPage--;
                renderIntelMappingTable();
            }
        };

        const pageInfo = document.createElement('span');
        pageInfo.className = 'pagination-info';
        pageInfo.textContent = `Page ${intelMappingState.currentPage} of ${totalPages} (${mappings.length} total)`;

        const nextBtn = document.createElement('button');
        nextBtn.className = 'pagination-btn';
        nextBtn.textContent = 'Next →';
        nextBtn.disabled = intelMappingState.currentPage === totalPages;
        nextBtn.onclick = () => {
            if (intelMappingState.currentPage < totalPages) {
                intelMappingState.currentPage++;
                renderIntelMappingTable();
            }
        };

        paginationDiv.appendChild(prevBtn);
        paginationDiv.appendChild(pageInfo);
        paginationDiv.appendChild(nextBtn);
        wrapper.appendChild(paginationDiv);
    }

    container.appendChild(wrapper);
}

/**
 * Truncate text helper
 */
function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
}

/**
 * Setup auto-refresh for real-time updates
 */
let autoRefreshInterval = null;

function setupAutoRefresh() {
    // Clear existing interval
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }

    // Refresh every 10 seconds to check for new threats/intel
    autoRefreshInterval = setInterval(async () => {
        try {
            const apiBase = getApiBase();
            const threatsResponse = await fetch(`${apiBase}/threats?limit=1`);
            if (threatsResponse.ok) {
                const threatsData = await threatsResponse.json();
                const currentThreatCount = threatsData.total || 0;

                // Only reload if threat count changed
                if (currentThreatCount !== MCPThreatMatrixState.threats.length) {
                    console.log('[MCPThreatMatrix] Detected new threats, auto-refreshing...');
                    await loadMCPThreatMatrix();
                }
            }
        } catch (e) {
            console.warn('[MCPThreatMatrix] Auto-refresh error:', e);
        }
    }, 10000);  // Check every 10 seconds
}


/**
 * Show threat details
 */
function showThreatDetails(threatId) {
    const threat = MCPThreatMatrixState.threats.find(t => t.id === threatId);
    if (!threat) {
        showNotification('Threat not found', 'error');
        return;
    }

    // Create modal or navigate to threat details
    alert(`Threat: ${threat.name}\n\nDescription: ${threat.description || 'No description'}\n\nWorkflow Phase: ${threat.mcp_workflow_phase || 'N/A'}\nMSB Attack Type: ${threat.msb_attack_type || 'N/A'}`);
}

/**
 * Generate threats from intelligence with real-time progress updates
 */
async function generateMCPThreatsFromIntel(forceReprocess = false) {
    const apiBase = getApiBase();
    console.log('[MCPThreatMatrix] Generating threats from intelligence...');

    // Step 1: Load and display existing threat matrix first (don't leave screen blank)
    if (MCPThreatMatrixState.threats.length === 0) {
        try {
            await loadMCPThreatMatrix();
        } catch (e) {
            console.warn('[MCPThreatMatrix] Could not pre-load matrix:', e);
        }
    }

    // Get initial threat count and intel count
    let initialThreatCount = 0;
    let totalIntelCount = 0;
    try {
        const initialResponse = await fetch(`${apiBase}/threats?limit=1`);
        if (initialResponse.ok) {
            const initialData = await initialResponse.json();
            initialThreatCount = initialData.total || 0;
        }
        const intelResponse = await fetch(`${apiBase}/intel/items?limit=1`);
        if (intelResponse.ok) {
            const intelData = await intelResponse.json();
            totalIntelCount = intelData.total || 0;
        }
    } catch (e) {
        console.warn('[MCPThreatMatrix] Could not get initial counts:', e);
    }

    // Show progress indicator (as overlay on top of existing content)
    const progressContainer = document.getElementById('threat-generation-progress');
    let pollInterval = null;
    let apiRequestCompleted = false;
    let lastUpdateTime = Date.now();
    const MAX_IDLE_TIME = 30000; // 30 seconds of no updates before considering done

    if (progressContainer) {
        progressContainer.style.display = 'block';
        progressContainer.innerHTML = `
            <div class="progress-indicator">
                <div class="progress-spinner"></div>
                <div class="progress-text">
                    <div>Generating threats from intelligence...</div>
                    <div style="margin-top: 8px; font-size: 12px; color: var(--text-secondary);">
                        Processing <span id="progress-intel-count">0</span> / <span id="total-intel-count">${totalIntelCount}</span> intel items
                        | Generated <span id="progress-threat-count">${initialThreatCount}</span> threats
                </div>
                    </div>
                </div>
        `;
    } else {
        showNotification('Generating threats from intelligence... This may take a while.', 'info');
    }

    // Update total intel count display
    const totalIntelCountEl = document.getElementById('total-intel-count');
    if (totalIntelCountEl && totalIntelCount > 0) {
        totalIntelCountEl.textContent = totalIntelCount;
    }

    // Start polling for progress updates via the new progress endpoint
    let lastThreatCount = initialThreatCount;
    let lastIntelProcessed = 0;
    pollInterval = setInterval(async () => {
        try {
            // Poll the dedicated progress endpoint
            const progressResponse = await fetch(`${apiBase}/intel/generate-threats/progress`);
            if (progressResponse.ok) {
                const progress = await progressResponse.json();

                // Update intel items processed count
                const progressIntelEl = document.getElementById('progress-intel-count');
                if (progressIntelEl && progress.processed > 0) {
                    progressIntelEl.textContent = progress.processed;
                }

                // Update total count if available
                const totalIntelCountEl = document.getElementById('total-intel-count');
                if (totalIntelCountEl && progress.total > 0) {
                    totalIntelCountEl.textContent = progress.total;
                }

                // Update threat count
                const progressCountEl = document.getElementById('progress-threat-count');
                if (progressCountEl && progress.threats_generated > 0) {
                    progressCountEl.textContent = progress.threats_generated;
                }

                // Update phase/message text
                const progressTextDiv = document.querySelector('#threat-generation-progress .progress-text > div:first-child');
                if (progressTextDiv && progress.message) {
                    const phase = progress.current_phase || '';
                    const phaseEmoji = phase === 'filtering' ? '🔍' : phase === 'generating' ? '⚡' : phase === 'done' ? '✅' : '⏳';
                    progressTextDiv.textContent = `${phaseEmoji} ${progress.message}`;
                }

                if (progress.processed > lastIntelProcessed) {
                    lastIntelProcessed = progress.processed;
                    lastUpdateTime = Date.now();
                }
            }

            // Also check for new threats in DB (for matrix refresh)
            const pollResponse = await fetch(`${apiBase}/threats?limit=1`);
            if (pollResponse.ok) {
                const pollData = await pollResponse.json();
                const currentThreatCount = pollData.total || 0;

                if (currentThreatCount > lastThreatCount) {
                    const newThreats = currentThreatCount - lastThreatCount;
                    lastThreatCount = currentThreatCount;
                    lastUpdateTime = Date.now();

                    console.log(`[MCPThreatMatrix] Detected ${newThreats} new threat(s), refreshing matrix...`);
                    await loadMCPThreatMatrix();
                }

                // If API request completed and no updates for a while, stop polling
                if (apiRequestCompleted && (Date.now() - lastUpdateTime) > MAX_IDLE_TIME) {
                    console.log('[MCPThreatMatrix] No updates for 30s, stopping polling');
                    clearInterval(pollInterval);
                    if (progressContainer) {
                        progressContainer.style.display = 'none';
                    }
                }
            }
        } catch (e) {
            console.warn('[MCPThreatMatrix] Error polling progress:', e);
        }
    }, 2000); // Poll every 2 seconds

    try {
        const response = await fetch(`${apiBase}/intel/generate-threats`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                limit: 10000,  // Process all available intel items
                project_id: 'default-project',
                force_reprocess: forceReprocess
            })
        });

        if (!response.ok) {
            let errorData = {};
            try {
                errorData = await response.json();
            } catch (e) {
                // If not JSON, try text
                 try {
                    const text = await response.text();
                     errorData = { message: text };
                 } catch(e2) {
                     errorData = { message: 'Unknown error' };
                 }
            }

             // Handle ALL_PROCESSED case
            if (response.status === 409 && errorData.code === 'ALL_PROCESSED') {
                 // Stop polling as this request failed
                if (pollInterval) clearInterval(pollInterval);
                if (progressContainer) progressContainer.style.display = 'none';

                if (confirm(`All ${errorData.total_items || 'intelligence'} items have already been processed. Do you want to force re-process them to update existing threats? This will check for updates to existing threats.`)) {
                    // Recursive call with forceReprocess
                    return generateMCPThreatsFromIntel(true);
                } else {
                    showNotification('Threat generation cancelled.', 'info');
                    return;
                }
            }

            throw new Error(errorData.message || errorData.error || `HTTP ${response.status}`);
        }

        const result = await response.json();
        console.log('[MCPThreatMatrix] API response received:', result);

        const finalThreatCount = result.stats?.threats_count || result.saved?.threats_count || 0;
        const intelProcessed = result.stats?.intel_items_processed || 0;
        const skippedCount = result.skipped_intel_count || 0;

        // Update progress with API response data
        const progressCountEl = document.getElementById('progress-threat-count');
        const progressIntelEl = document.getElementById('progress-intel-count');
        if (progressCountEl) {
            progressCountEl.textContent = finalThreatCount;
        }
        if (progressIntelEl && intelProcessed > 0) {
            progressIntelEl.textContent = intelProcessed;
        }

        // Mark API request as completed, but keep polling for a while to catch any delayed saves
        apiRequestCompleted = true;
        console.log(`[MCPThreatMatrix] API request completed: ${finalThreatCount} threats from ${intelProcessed} intel items. Continuing to poll for updates...`);

        // Continue polling for additional updates (threats may still be saving)
        // Stop polling after MAX_IDLE_TIME of no updates
        let noUpdateCount = 0;
        const maxNoUpdateChecks = 15; // 15 checks * 2 seconds = 30 seconds max

        const finalPollInterval = setInterval(async () => {
            try {
                const pollResponse = await fetch(`${apiBase}/threats?limit=1`);
                if (pollResponse.ok) {
                    const pollData = await pollResponse.json();
                    const currentThreatCount = pollData.total || 0;

                    if (currentThreatCount > lastThreatCount) {
                        // New threats detected, reset counter
                        noUpdateCount = 0;
                        lastThreatCount = currentThreatCount;
                        lastUpdateTime = Date.now();

                        // Update progress
                        if (progressCountEl) {
                            progressCountEl.textContent = currentThreatCount - initialThreatCount;
                        }

                        console.log(`[MCPThreatMatrix] Detected additional threat(s), total now: ${currentThreatCount - initialThreatCount}`);
                        await loadMCPThreatMatrix();
                    } else {
                        noUpdateCount++;
                    }

                    // Stop if no updates for a while
                    if (noUpdateCount >= maxNoUpdateChecks || (Date.now() - lastUpdateTime) > MAX_IDLE_TIME) {
                        console.log('[MCPThreatMatrix] No more updates detected, stopping polling');
                        clearInterval(finalPollInterval);
                        if (pollInterval) {
                            clearInterval(pollInterval);
                        }
                        if (progressContainer) {
                            progressContainer.style.display = 'none';
                        }

                        // Show final notification
                        let message = `Generated ${currentThreatCount - initialThreatCount} threats from ${intelProcessed} intelligence items`;
                        if (skippedCount > 0) {
                            message += ` (skipped ${skippedCount} already processed)`;
                        }
                        showNotification(message, 'success');

                        // Final reload
                        await loadMCPThreatMatrix();
                    }
                }
            } catch (e) {
                console.warn('[MCPThreatMatrix] Error in final polling:', e);
                noUpdateCount++;
            }
        }, 2000);

    } catch (error) {
        // Stop polling on error
        if (pollInterval) {
            clearInterval(pollInterval);
        }

        // Hide progress indicator
        if (progressContainer) {
            progressContainer.style.display = 'none';
        }

        console.error('[MCPThreatMatrix] Error generating threats:', error);
        showNotification(`Failed to generate threats: ${error.message}`, 'error');
    }
}

/**
 * Show threats for a specific matrix cell
 */
function showThreatsForCell(phase, attackType, threats) {
    if (threats.length === 0) {
        showNotification(`No threats found for ${attackType} in ${phase}`, 'info');
        return;
    }

    // Create modal to show threats
    const modal = document.createElement('div');
    modal.className = 'threat-detail-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h4>Threats: ${phase} - ${attackType}</h4>
                <button class="modal-close" onclick="this.closest('.threat-detail-modal').remove()">×</button>
            </div>
            <div class="modal-body">
                <div class="threat-list">
                    ${threats.map(t => {
        const threatName = t.name || 'Unnamed Threat';
        const threatDesc = t.description || '';
        const riskLevel = (t.risk_level || 'medium').toLowerCase();
        const severity = t.severity || t.schema_data?.severity || 'N/A';
        const targetAsset = t.target_asset || t.schema_data?.target_asset || t.assets_at_risk || t.schema_data?.assets_at_risk || null;
        const targetAssetStr = targetAsset ? (Array.isArray(targetAsset) ? targetAsset.join(', ') : targetAsset) : '';

        return `
                        <div class="threat-item">
                            <h5>${threatName}</h5>
                            <p>${truncateText(threatDesc, 200)}</p>
                            <div class="threat-meta">
                                <span class="risk-badge risk-${riskLevel}">${t.risk_level || 'Medium'}</span>
                                <span>Severity: ${severity}</span>
                                ${targetAssetStr ? `<span>Target: ${targetAssetStr}</span>` : ''}
                            </div>
                        </div>
                    `;
    }).join('')}
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Close on background click
    modal.onclick = (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    };
}

/**
 * Show OWASP details modal
 * @param {string} type - 'llm' or 'agentic'
 * @param {string} owaspId - OWASP ID (e.g., LLM01, ASI01)
 */
async function showOWASPDetails(type, owaspId) {
    try {
        const apiBase = getApiBase();
        const projectId = new URLSearchParams(window.location.search).get('project_id') || 'default-project';

        const endpoint = type === 'llm' ?
            `${apiBase}/owasp/llm/${owaspId}?project_id=${projectId}` :
            `${apiBase}/owasp/agentic/${owaspId}?project_id=${projectId}`;

        const response = await fetch(endpoint);
        if (!response.ok) {
            throw new Error(`Failed to load OWASP details: ${response.statusText}`);
        }
        const data = await response.json();

        const typeLabel = type === 'llm' ? 'OWASP LLM Top 10' : 'OWASP Agentic Top 10';
        const colorClass = type === 'llm' ? '#4299e1' : '#ed8936';

        const modal = document.createElement('div');
        modal.className = 'owasp-detail-modal';
        modal.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7); display: flex; align-items: center;
            justify-content: center; z-index: 10001;
        `;

        modal.innerHTML = `
            <div class="modal-content" style="background: var(--bg-primary); border-radius: 12px; max-width: 900px; max-height: 85vh; overflow-y: auto; padding: 24px; width: 90%;">
                <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; margin-bottom: 16px;">
                    <div>
                        <span style="color: ${colorClass}; font-size: 0.85rem;">${typeLabel}</span>
                        <h3 style="margin: 4px 0 0 0; color: var(--text-primary);">${owaspId}: ${escapeHtml(data.owasp_name)}</h3>
                    </div>
                    <button class="modal-close" style="background: none; border: none; font-size: 24px; cursor: pointer; color: var(--text-secondary);" onclick="this.closest('.owasp-detail-modal').remove()">×</button>
                </div>
                
                <div class="modal-body">
                    <!-- Statistics -->
                    <div class="owasp-stats" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px;">
                        <div style="background: var(--bg-secondary); padding: 12px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 24px; font-weight: bold; color: ${colorClass};">${data.statistics.mcp_threat_count}</div>
                            <div style="font-size: 0.85rem; color: var(--text-secondary);">MCP Threats Mapped</div>
                        </div>
                        <div style="background: var(--bg-secondary); padding: 12px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 24px; font-weight: bold; color: var(--accent-danger);">${data.statistics.threat_count}</div>
                            <div style="font-size: 0.85rem; color: var(--text-secondary);">Threats in Database</div>
                        </div>
                        <div style="background: var(--bg-secondary); padding: 12px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 24px; font-weight: bold; color: var(--accent-success);">${data.statistics.intel_count}</div>
                            <div style="font-size: 0.85rem; color: var(--text-secondary);">Intelligence Items</div>
                        </div>
                    </div>
                    
                    <!-- Related MCP Threats -->
                    <div class="related-mcp-threats" style="margin-bottom: 20px;">
                        <h4 style="margin: 0 0 12px 0; color: var(--text-primary);">Related MCP Threat Categories</h4>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                            ${data.mcp_threats.map(t => `
                                <span class="mcp-threat-tag" style="background: var(--bg-secondary); color: var(--text-primary); padding: 6px 12px; border-radius: 6px; font-size: 0.85rem; cursor: pointer; border: 1px solid var(--border-color);" 
                                      onclick="this.closest('.owasp-detail-modal').remove(); showMCPThreatDetails('${t.id}');">
                                    <strong>${t.id}</strong>: ${escapeHtml(t.name)}
                                </span>
                            `).join('')}
                        </div>
                    </div>
                    
                    <!-- Threats List -->
                    <div class="threats-section" style="margin-bottom: 20px;">
                        <h4 style="margin: 0 0 12px 0; color: var(--text-primary);">Threats (${data.threats.length})</h4>
                        <div class="threats-list" style="max-height: 200px; overflow-y: auto;">
                            ${data.threats.length > 0 ? data.threats.map(t => `
                                <div class="threat-item" style="background: var(--bg-secondary); padding: 12px; border-radius: 8px; margin-bottom: 8px; cursor: pointer;" onclick="showThreatDetails('${t.id}');">
                                    <div style="font-weight: 500; color: var(--text-primary);">${escapeHtml(t.name || 'Unknown')}</div>
                                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">${escapeHtml((t.description || '').substring(0, 150))}...</div>
                                    <div style="margin-top: 8px;">
                                        ${t.risk_level ? `<span class="risk-badge risk-${(t.risk_level || 'medium').toLowerCase()}" style="font-size: 0.75rem;">${t.risk_level}</span>` : ''}
                                        ${(t.mcp_threat_ids || []).map(id => `<span style="background: rgba(99, 102, 241, 0.2); color: #6366f1; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem; margin-left: 4px;">${id}</span>`).join('')}
                                    </div>
                                </div>
                            `).join('') : '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">No threats found for this OWASP category.</div>'}
                        </div>
                    </div>
                    
                    <!-- Intelligence Items -->
                    <div class="intel-section">
                        <h4 style="margin: 0 0 12px 0; color: var(--text-primary);">Intelligence Items (${data.intel_items.length})</h4>
                        <div class="intel-list" style="max-height: 200px; overflow-y: auto;">
                            ${data.intel_items.length > 0 ? data.intel_items.slice(0, 10).map(i => {
            const sourceUrl = i.source_url || i.url || '#';
            const isValidUrl = sourceUrl && sourceUrl !== '#' && (sourceUrl.startsWith('http://') || sourceUrl.startsWith('https://'));
            return `
                                <div class="intel-item" style="background: var(--bg-secondary); padding: 12px; border-radius: 8px; margin-bottom: 8px;">
                                    <div style="font-weight: 500; color: var(--text-primary);">
                                        ${isValidUrl ?
                    `<a href="${sourceUrl}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-primary); text-decoration: none;">${escapeHtml(i.title || 'Untitled')}</a>` :
                    escapeHtml(i.title || 'Untitled')
                }
                                    </div>
                                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">${escapeHtml((i.ai_summary || i.content || '').substring(0, 100))}...</div>
                                    <div style="margin-top: 6px;">
                                        <span style="background: var(--bg-tertiary); color: var(--text-secondary); padding: 2px 6px; border-radius: 3px; font-size: 0.75rem;">${escapeHtml(i.source_type || 'Unknown')}</span>
                                    </div>
                                </div>
                            `;
        }).join('') + (data.intel_items.length > 10 ? `<div style="padding: 12px; text-align: center; color: var(--text-secondary);">+${data.intel_items.length - 10} more items</div>` : '') :
                '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">No intelligence items found for this OWASP category.</div>'}
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });

    } catch (error) {
        console.error('[MCPThreatMatrix] Error showing OWASP details:', error);
        showNotification(`Failed to load OWASP details: ${error.message}`, 'error');
    }
}

/**
 * Load OWASP Mapping View
 * Displays MCP threats organized by OWASP LLM Top 10 and OWASP Agentic Top 10
 */
async function loadOWASPMappingView() {
    const container = document.getElementById('owasp-mapping-content');
    if (!container) return;

    container.innerHTML = '<div style="padding: 40px; text-align: center;"><div class="loading-spinner"></div><p>Loading OWASP mappings...</p></div>';

    try {
        const apiBase = getApiBase();
        const response = await fetch(`${apiBase}/owasp/mappings`);

        if (!response.ok) {
            throw new Error(`Failed to load OWASP mappings: ${response.statusText}`);
        }

        const data = await response.json();
        const owaspLlm = data.owasp_llm_top10 || {};
        const owaspAgentic = data.owasp_agentic_top10 || {};
        const mappings = data.mappings || {};

        // Build reverse mappings (OWASP -> MCP)
        const llmToMcp = {};
        const agenticToMcp = {};

        Object.keys(owaspLlm).forEach(id => { llmToMcp[id] = []; });
        Object.keys(owaspAgentic).forEach(id => { agenticToMcp[id] = []; });

        if (mappings.mcp_to_owasp_llm) {
            Object.entries(mappings.mcp_to_owasp_llm).forEach(([mcpId, llmIds]) => {
                llmIds.forEach(llmId => {
                    if (!llmToMcp[llmId]) llmToMcp[llmId] = [];
                    llmToMcp[llmId].push(mcpId);
                });
            });
        }

        if (mappings.mcp_to_owasp_agentic) {
            Object.entries(mappings.mcp_to_owasp_agentic).forEach(([mcpId, agenticIds]) => {
                agenticIds.forEach(agenticId => {
                    if (!agenticToMcp[agenticId]) agenticToMcp[agenticId] = [];
                    agenticToMcp[agenticId].push(mcpId);
                });
            });
        }

        container.innerHTML = `
            <div class="owasp-mapping-grids">
                <!-- OWASP LLM Top 10 -->
                <div class="owasp-section" style="margin-bottom: 32px;">
                    <h4 style="color: #4299e1; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                        📘 OWASP Top 10 for LLM Applications (v1.1)
                        <span style="font-size: 0.8rem; color: var(--text-secondary); font-weight: normal;">Click to view related threats</span>
                    </h4>
                    <div class="owasp-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px;">
                        ${Object.entries(owaspLlm).map(([id, name]) => {
            const mcpCount = (llmToMcp[id] || []).length;
            return `
                                <div class="owasp-card" onclick="showOWASPDetails('llm', '${id}')" style="
                                    background: var(--bg-secondary);
                                    border: 1px solid var(--border-color);
                                    border-left: 4px solid #4299e1;
                                    border-radius: 8px;
                                    padding: 16px;
                                    cursor: pointer;
                                    transition: transform 0.2s, box-shadow 0.2s;
                                " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.15)';" 
                                   onmouseout="this.style.transform='none'; this.style.boxShadow='none';">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                                        <div>
                                            <div style="font-weight: 600; color: #4299e1; font-size: 0.9rem;">${id}</div>
                                            <div style="color: var(--text-primary); margin-top: 4px;">${escapeHtml(name)}</div>
                                        </div>
                                        <div style="background: rgba(66, 153, 225, 0.2); color: #4299e1; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600;">
                                            ${mcpCount} MCP
                                        </div>
                                    </div>
                                    <div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-secondary);">
                                        ${(llmToMcp[id] || []).slice(0, 4).join(', ')}${(llmToMcp[id] || []).length > 4 ? '...' : ''}
                                    </div>
                                </div>
                            `;
        }).join('')}
                    </div>
                </div>
                
                <!-- OWASP Agentic Top 10 -->
                <div class="owasp-section">
                    <h4 style="color: #ed8936; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                        🤖 OWASP Agentic Top 10 (ASI01-ASI10)
                        <span style="font-size: 0.8rem; color: var(--text-secondary); font-weight: normal;">Click to view related threats</span>
                    </h4>
                    <div class="owasp-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px;">
                        ${Object.entries(owaspAgentic).map(([id, name]) => {
            const mcpCount = (agenticToMcp[id] || []).length;
            return `
                                <div class="owasp-card" onclick="showOWASPDetails('agentic', '${id}')" style="
                                    background: var(--bg-secondary);
                                    border: 1px solid var(--border-color);
                                    border-left: 4px solid #ed8936;
                                    border-radius: 8px;
                                    padding: 16px;
                                    cursor: pointer;
                                    transition: transform 0.2s, box-shadow 0.2s;
                                " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.15)';" 
                                   onmouseout="this.style.transform='none'; this.style.boxShadow='none';">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                                        <div>
                                            <div style="font-weight: 600; color: #ed8936; font-size: 0.9rem;">${id}</div>
                                            <div style="color: var(--text-primary); margin-top: 4px;">${escapeHtml(name)}</div>
                                        </div>
                                        <div style="background: rgba(237, 137, 54, 0.2); color: #ed8936; padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600;">
                                            ${mcpCount} MCP
                                        </div>
                                    </div>
                                    <div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-secondary);">
                                        ${(agenticToMcp[id] || []).slice(0, 4).join(', ')}${(agenticToMcp[id] || []).length > 4 ? '...' : ''}
                                    </div>
                                </div>
                            `;
        }).join('')}
                    </div>
                </div>
            </div>
        `;

    } catch (error) {
        console.error('[MCPThreatMatrix] Error loading OWASP mappings:', error);
        container.innerHTML = `<div class="error-message" style="padding: 20px; text-align: center; color: var(--accent-danger);">Failed to load OWASP mappings: ${error.message}</div>`;
    }
}

// Export functions to window
if (typeof window !== 'undefined') {
    window.loadMCPThreatMatrix = loadMCPThreatMatrix;
    window.generateMCPThreatsFromIntel = generateMCPThreatsFromIntel;
    window.showThreatDetails = showThreatDetails;
    window.showThreatsForCell = showThreatsForCell;
    window.filterIntelMapping = filterIntelMapping;
    window.showMCPThreatDetails = showMCPThreatDetails;
    window.showOWASPDetails = showOWASPDetails;
    window.loadOWASPMappingView = loadOWASPMappingView;
    window.getDomainName = getDomainName;
    window.escapeHtml = escapeHtml;
}

