/**
 * Standard 4×17 Threat Matrix Visualization
 * 
 * Interactive visualization of the standard threat matrix with:
 * - 4 Attack Surfaces × 17 Attack Types = 68 cells
 * - Severity heatmap (0-10 scale)
 * - Graph pattern visualization
 * - Test template display
 * - Threat count per cell
 */

const MCPSecBenchState = {
    matrix: null,
    threats: [],
    selectedCell: null
};

// Standard Surfaces
const MCPSECBENCH_SURFACES = [
    'Server APIs & Functionality',
    'Tool Metadata & Toolchain',
    'Runtime / Invocation Flow',
    'Client / Integration Surface'
];

// Standard Attack Types
const MCPSECBENCH_ATTACK_TYPES = [
    'Metadata Poisoning',
    'Tool Poisoning (instruction in metadata)',
    'Preference Manipulation (tool selection bias)',
    'Unauthorized Tool Invocation (privilege escalation)',
    'Unvalidated Input → Shell/FS Exec',
    'Directory Traversal / Path-Manipulation',
    'Sensitive Data Exposure (exfiltration)',
    'Supply-chain / Registry Tampering',
    'Resource Exhaustion / DoS',
    'Race / Time-of-Check-Time-of-Use (TOCTOU)',
    'Misconfigured Permissions / Over-privileged Tools',
    'Unsafe Third-party API Calls (backend leak)',
    'Model-induced Logic Flaws (unexpected LLM reasoning)',
    'Chain-of-Tools Attack (multi-tool gadget chain)',
    'Phishing / Social-Engineering via Tools (out-of-band)',
    'Unsigned / Unverified Tool Execution (missing provenance)',
    'Logging / Audit Evasion'
];

/**
 * Load threat matrix data
 */
async function loadMCPSecBenchMatrix() {
    const apiBase = getApiBase();
    console.log('[ThreatMatrix] Loading threat matrix...');

    try {
        // Load matrix definition
        const matrixResponse = await fetch(`${apiBase}/mcpsecbench/matrix`);
        if (!matrixResponse.ok) {
            throw new Error(`Failed to load matrix: ${matrixResponse.statusText}`);
        }
        const matrixData = await matrixResponse.json();
        MCPSecBenchState.matrix = matrixData;

        // Load threats to count per cell
        const threatsResponse = await fetch(`${apiBase}/threats?limit=10000`);
        if (threatsResponse.ok) {
            const threatsData = await threatsResponse.json();
            MCPSecBenchState.threats = threatsData.threats || threatsData || [];

            // Debug: Count threats with MCPSecBench classification
            const classifiedCount = MCPSecBenchState.threats.filter(t => {
                const schemaData = t.schema_data || {};
                return (schemaData.mcp_surface || t.mcp_surface) &&
                    (schemaData.mcpsecbench_attack_type || t.mcpsecbench_attack_type);
            }).length;
            console.log(`[ThreatMatrix] Loaded ${MCPSecBenchState.threats.length} threats, ${classifiedCount} with standard classification`);

            // Debug: Log sample threat classifications
            if (MCPSecBenchState.threats.length > 0) {
                const sampleThreats = MCPSecBenchState.threats.slice(0, 5).map(t => {
                    const schemaData = t.schema_data || {};
                    return {
                        id: t.id,
                        name: t.name,
                        mcp_surface: schemaData.mcp_surface || t.mcp_surface,
                        mcpsecbench_attack_type: schemaData.mcpsecbench_attack_type || t.mcpsecbench_attack_type
                    };
                });
                console.log('[ThreatMatrix] Sample threat classifications:', sampleThreats);
            }
        }

        // Render matrix
        renderMCPSecBenchMatrix();

        console.log('[MCPSecBench] Matrix loaded successfully');
        showNotification('MCPSecBench matrix loaded', 'success');

    } catch (error) {
        console.error('[ThreatMatrix] Error loading matrix:', error);
        showNotification(`Failed to load matrix: ${error.message}`, 'error');
    }
}

/**
 * Render the 4×17 threat matrix
 */
function renderMCPSecBenchMatrix() {
    const container = document.getElementById('mcpsecbench-matrix-container');
    if (!container) {
        console.error('[MCPSecBench] Container not found');
        return;
    }

    if (!MCPSecBenchState.matrix) {
        container.innerHTML = '<p>Loading matrix data...</p>';
        return;
    }

    const matrix = MCPSecBenchState.matrix.matrix || {};

    // Create matrix table
    let html = `
        <div class="mcpsecbench-matrix-wrapper">
            <div class="mcpsecbench-controls">
                <div class="mcpsecbench-filters">
                    <label>
                        <input type="checkbox" id="filter-high-severity" checked>
                        Show only High Severity (≥7)
                    </label>
                    <label>
                        <input type="checkbox" id="filter-with-threats" checked>
                        Show only cells with threats
                    </label>
                </div>
                <div class="mcpsecbench-stats">
                    <span id="matrix-stats">Total cells: 68</span>
                </div>
            </div>
            <div class="mcpsecbench-matrix-table-wrapper">
                <table class="mcpsecbench-matrix-table">
                    <thead>
                        <tr>
                            <th class="col-surface">Attack Surface</th>
                            ${MCPSECBENCH_ATTACK_TYPES.map((type, idx) =>
        `<th class="col-attack-type" title="${type}">${idx + 1}</th>`
    ).join('')}
                        </tr>
                    </thead>
                    <tbody>
    `;

    // Render each surface row
    MCPSECBENCH_SURFACES.forEach((surface, surfaceIdx) => {
        html += `<tr class="surface-row" data-surface="${surfaceIdx}">`;
        html += `<td class="col-surface surface-label">${surface}</td>`;

        MCPSECBENCH_ATTACK_TYPES.forEach((attackType, attackIdx) => {
            const cell = matrix[surface]?.[attackType];
            const severity = cell?.severity || 5;
            const threatCount = getThreatCountForCell(surface, attackType);

            // Debug: Log first few cells to see matching
            if (surfaceIdx === 0 && attackIdx < 3) {
                console.log(`[MCPSecBench] Cell [${surface}][${attackType}]: threatCount=${threatCount}, severity=${severity}`);
            }

            // Determine cell class based on severity
            let severityClass = 'severity-low';
            if (severity >= 9) severityClass = 'severity-critical';
            else if (severity >= 7) severityClass = 'severity-high';
            else if (severity >= 5) severityClass = 'severity-medium';

            html += `
                <td class="matrix-cell ${severityClass}" 
                    data-surface="${surfaceIdx}" 
                    data-attack="${attackIdx}"
                    data-severity="${severity}"
                    data-threat-count="${threatCount}"
                    onclick="showMCPSecBenchCellDetails('${surface}', '${attackType}')"
                    title="${attackType} - Severity: ${severity}/10 - Threats: ${threatCount}">
                    <div class="cell-severity">${severity}</div>
                    ${threatCount > 0 ? `<div class="cell-threat-count">${threatCount}</div>` : ''}
                </td>
            `;
        });

        html += `</tr>`;
    });

    html += `
                    </tbody>
                </table>
            </div>
            <div class="mcpsecbench-legend">
                <div class="legend-item">
                    <span class="legend-color severity-critical"></span>
                    <span>Critical (9-10)</span>
                </div>
                <div class="legend-item">
                    <span class="legend-color severity-high"></span>
                    <span>High (7-8)</span>
                </div>
                <div class="legend-item">
                    <span class="legend-color severity-medium"></span>
                    <span>Medium (5-6)</span>
                </div>
                <div class="legend-item">
                    <span class="legend-color severity-low"></span>
                    <span>Low (0-4)</span>
                </div>
            </div>
        </div>
    `;

    container.innerHTML = html;

    // Add event listeners for filters
    setupMCPSecBenchFilters();
}

/**
 * Get threat count for a specific cell
 */
function getThreatCountForCell(surface, attackType) {
    if (!MCPSecBenchState.threats || MCPSecBenchState.threats.length === 0) {
        return 0;
    }

    // Normalize expected values for comparison
    const normalize = (str) => (str || '').toString().trim().toLowerCase();
    const normalizedExpectedSurface = normalize(surface);
    const normalizedExpectedAttackType = normalize(attackType);

    // Create a mapping of possible attack type variations
    // Map enum names to full names (e.g., "METADATA_POISONING" -> "Metadata Poisoning")
    const attackTypeMap = {
        'metadata_poisoning': 'metadata poisoning',
        'tool_poisoning': 'tool poisoning',
        'preference_manipulation': 'preference manipulation',
        'unauthorized_tool_invocation': 'unauthorized tool invocation',
        'unvalidated_input': 'unvalidated input',
        'directory_traversal': 'directory traversal',
        'sensitive_data_exposure': 'sensitive data exposure',
        'supply_chain': 'supply-chain',
        'resource_exhaustion': 'resource exhaustion',
        'race': 'race',
        'misconfigured_permissions': 'misconfigured permissions',
        'unsafe_third_party_api': 'unsafe third-party api',
        'model_induced_logic_flaws': 'model-induced logic flaws',
        'chain_of_tools_attack': 'chain-of-tools attack',
        'phishing': 'phishing',
        'unsigned_tool_execution': 'unsigned / unverified tool execution',
        'logging_audit_evasion': 'logging / audit evasion'
    };

    return MCPSecBenchState.threats.filter(threat => {
        if (!threat) return false;

        const schemaData = threat.schema_data || {};
        // Try multiple sources for surface
        let threatSurface = schemaData.mcp_surface || threat.mcp_surface;
        // Try multiple sources for attack type
        let threatAttackType = schemaData.mcpsecbench_attack_type || threat.mcpsecbench_attack_type;

        // If both are null/undefined, skip this threat
        if (!threatSurface || !threatAttackType) {
            return false;
        }

        // Normalize threat values
        const normalizedThreatSurface = normalize(threatSurface);
        let normalizedThreatAttackType = normalize(threatAttackType);

        // Try to map enum-style names to full names
        for (const [enumKey, fullName] of Object.entries(attackTypeMap)) {
            if (normalizedThreatAttackType.includes(enumKey) || normalizedThreatAttackType === enumKey) {
                normalizedThreatAttackType = normalize(fullName);
                break;
            }
        }

        // Check surface match first
        if (normalizedThreatSurface !== normalizedExpectedSurface) {
            return false;
        }

        // Check attack type match (exact or partial)
        if (normalizedThreatAttackType === normalizedExpectedAttackType) {
            return true;
        }

        // Partial match: check if either contains the other
        if (normalizedThreatAttackType.includes(normalizedExpectedAttackType) ||
            normalizedExpectedAttackType.includes(normalizedThreatAttackType)) {
            return true;
        }

        // Try matching without special characters and parentheses
        const cleanThreatType = normalizedThreatAttackType.replace(/[()]/g, '').replace(/\s+/g, ' ');
        const cleanExpectedType = normalizedExpectedAttackType.replace(/[()]/g, '').replace(/\s+/g, ' ');
        if (cleanThreatType === cleanExpectedType ||
            cleanThreatType.includes(cleanExpectedType) ||
            cleanExpectedType.includes(cleanThreatType)) {
            return true;
        }

        return false;
    }).length;
}

/**
 * Show cell details modal
 */
async function showMCPSecBenchCellDetails(surface, attackType) {
    const apiBase = getApiBase();

    try {
        const response = await fetch(`${apiBase}/mcpsecbench/cell?surface=${encodeURIComponent(surface)}&attack_type=${encodeURIComponent(attackType)}`);
        if (!response.ok) {
            throw new Error('Failed to load cell details');
        }

        const cellData = await response.json();
        const threats = MCPSecBenchState.threats.filter(t => {
            const schemaData = t.schema_data || {};
            return (schemaData.mcp_surface || t.mcp_surface) === surface &&
                (schemaData.mcpsecbench_attack_type || t.mcpsecbench_attack_type) === attackType;
        });

        // Create modal
        const modal = document.createElement('div');
        modal.className = 'mcpsecbench-cell-modal';
        modal.innerHTML = `
            <div class="modal-backdrop" onclick="closeMCPSecBenchModal()"></div>
            <div class="modal-content mcpsecbench-cell-content">
                <div class="modal-header">
                    <h2>${surface} × ${attackType}</h2>
                    <button class="modal-close" onclick="closeMCPSecBenchModal()">×</button>
                </div>
                <div class="modal-body">
                    <div class="cell-detail-section">
                        <h3>Description</h3>
                        <p>${escapeHtml(cellData.short_description || 'N/A')}</p>
                    </div>
                    
                    <div class="cell-detail-section">
                        <h3>Severity</h3>
                        <div class="severity-display">
                            <span class="severity-badge severity-${cellData.severity >= 9 ? 'critical' : cellData.severity >= 7 ? 'high' : cellData.severity >= 5 ? 'medium' : 'low'}">
                                ${cellData.severity}/10
                            </span>
                        </div>
                    </div>
                    
                    <div class="cell-detail-section">
                        <h3>Graph Pattern</h3>
                        <div class="graph-pattern-display">
                            <div class="pattern-description">
                                <strong>Pattern:</strong> ${escapeHtml(cellData.graph_pattern?.pattern_description || 'N/A')}
                            </div>
                            <div class="pattern-example">
                                <strong>Example:</strong> <code>${escapeHtml(cellData.graph_pattern?.example_pattern || 'N/A')}</code>
                            </div>
                            <div class="pattern-nodes">
                                <strong>Node Types:</strong> ${(cellData.graph_pattern?.node_types || []).join(', ') || 'N/A'}
                            </div>
                            <div class="pattern-edges">
                                <strong>Edge Types:</strong> ${(cellData.graph_pattern?.edge_types || []).join(', ') || 'N/A'}
                            </div>
                        </div>
                    </div>
                    
                    <div class="cell-detail-section">
                        <h3>Test Template</h3>
                        <div class="test-template-display">
                            <div class="test-static">
                                <strong>Static Analysis:</strong>
                                <p>${escapeHtml(cellData.test_template?.static_analysis || 'N/A')}</p>
                            </div>
                            <div class="test-blackbox">
                                <strong>Blackbox Test:</strong>
                                <p>${escapeHtml(cellData.test_template?.blackbox_test || 'N/A')}</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="cell-detail-section">
                        <h3>How Used in Product</h3>
                        <p>${escapeHtml(cellData.how_used_in_product || 'N/A')}</p>
                    </div>
                    
                    <div class="cell-detail-section">
                        <h3>Research Relevance</h3>
                        <div class="research-badges">
                            ${cellData.how_used_in_product ? `<span class="product-usage-badge" title="${cellData.how_used_in_product}">Product</span>` : ''}
                        </div>
                    </div>
                    
                    <div class="cell-detail-section">
                        <h3>Threats (${threats.length})</h3>
                        ${threats.length > 0 ? `
                            <ul class="threat-list">
                                ${threats.slice(0, 10).map(t => `
                                    <li>
                                        <a href="#" onclick="showThreatDetails('${t.id}'); return false;">
                                            ${escapeHtml(t.name || 'Unknown')}
                                        </a>
                                        <span class="threat-risk">Risk: ${t.risk_score || 0}/10</span>
                                    </li>
                                `).join('')}
                                ${threats.length > 10 ? `<li class="more-threats">+ ${threats.length - 10} more threats</li>` : ''}
                            </ul>
                        ` : '<p>No threats mapped to this cell yet.</p>'}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="closeMCPSecBenchModal()">Close</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

    } catch (error) {
        console.error('[MCPSecBench] Error loading cell details:', error);
        showNotification(`Failed to load cell details: ${error.message}`, 'error');
    }
}

/**
 * Close MCPSecBench modal
 */
function closeMCPSecBenchModal() {
    const modal = document.querySelector('.mcpsecbench-cell-modal');
    if (modal) {
        modal.remove();
    }
}

/**
 * Setup filter controls
 */
function setupMCPSecBenchFilters() {
    const highSeverityFilter = document.getElementById('filter-high-severity');
    const withThreatsFilter = document.getElementById('filter-with-threats');

    if (highSeverityFilter) {
        highSeverityFilter.addEventListener('change', applyMCPSecBenchFilters);
    }
    if (withThreatsFilter) {
        withThreatsFilter.addEventListener('change', applyMCPSecBenchFilters);
    }
}

/**
 * Apply filters to matrix
 */
function applyMCPSecBenchFilters() {
    const highSeverityOnly = document.getElementById('filter-high-severity')?.checked || false;
    const withThreatsOnly = document.getElementById('filter-with-threats')?.checked || false;

    const cells = document.querySelectorAll('.matrix-cell');
    let visibleCount = 0;

    cells.forEach(cell => {
        const severity = parseInt(cell.dataset.severity) || 0;
        const threatCount = parseInt(cell.dataset.threatCount) || 0;

        let shouldShow = true;

        if (highSeverityOnly && severity < 7) {
            shouldShow = false;
        }

        if (withThreatsOnly && threatCount === 0) {
            shouldShow = false;
        }

        cell.style.display = shouldShow ? '' : 'none';
        if (shouldShow) visibleCount++;
    });

    // Update stats
    const statsEl = document.getElementById('matrix-stats');
    if (statsEl) {
        statsEl.textContent = `Visible cells: ${visibleCount} / 68`;
    }
}

/**
 * Escape HTML
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Get API base URL
 */
function getApiBase() {
    const port = window.location.port || '5000';
    const host = window.location.hostname || 'localhost';
    const protocol = window.location.protocol || 'http:';
    return `${protocol}//${host}:${port}/api`;
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    // Check if there's a global notification function (from app.js)
    const globalNotify = window.showNotification;
    if (globalNotify && typeof globalNotify === 'function' && globalNotify !== showNotification) {
        // Use the global notification function with correct parameter order
        try {
            // app.js showNotification expects (type, title, message)
            if (globalNotify.length === 3) {
                globalNotify(type, 'MCPSecBench Matrix', message);
            } else {
                globalNotify(message, type);
            }
        } catch (e) {
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    } else {
        // Fallback to console
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
}

// Make functions globally available
window.loadMCPSecBenchMatrix = loadMCPSecBenchMatrix;
window.showMCPSecBenchCellDetails = showMCPSecBenchCellDetails;
window.closeMCPSecBenchModal = closeMCPSecBenchModal;

