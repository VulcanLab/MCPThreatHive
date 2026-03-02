/**
 * Canvas Threat Analyzer - Frontend Integration
 * 
 * Integrates with the Canvas Threat Analyzer API to:
 * - Analyze Canvas components and generate threats
 * - Display threats and attack paths
 * - Show risk score and recommendations
 * - Save threats to database
 */

const CanvasThreatAnalysisState = {
    analysisResult: null,
    isAnalyzing: false
};

/**
 * Analyze Canvas threats
 */
async function analyzeCanvasThreats() {
    const apiBase = getApiBase();
    const analyzeBtn = document.getElementById('analyze-threats-btn');

    if (CanvasThreatAnalysisState.isAnalyzing) {
        return;
    }

    // Get Canvas components
    const components = getCanvasComponents();

    if (components.length === 0) {
        showNotification('warning', 'No Components', 'Please add components to Canvas before analyzing');
        return;
    }

    // Show loading state
    CanvasThreatAnalysisState.isAnalyzing = true;
    if (analyzeBtn) {
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = '⏳ Analyzing...';
    }

    try {
        const response = await fetch(`${apiBase}/canvas/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                components: components,
                save_to_db: true,
                project_id: 'default-project',
                scan_mcp_config: true  // Enable MCP environment configuration scanning
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP ${response.status}`);
        }

        const analysisResult = await response.json();
        CanvasThreatAnalysisState.analysisResult = analysisResult;

        // Display results
        displayThreatAnalysisResults(analysisResult);

        // Update threat count badge
        updateThreatCountBadge(analysisResult.threat_count || 0);

        // Switch to threats tab
        switchDetailTab('threats');

        // Show notification with MCP config scan info if available
        let notificationMsg = `Found ${analysisResult.threat_count} threats and ${analysisResult.attack_path_count} attack paths`;
        if (analysisResult.mcp_config_threats_count !== undefined) {
            notificationMsg += ` (${analysisResult.mcp_config_threats_count} from MCP config scan, ${analysisResult.canvas_threats_count} from Canvas analysis)`;
        }
        showNotification('success', 'Analysis Complete', notificationMsg);

        // Highlight threats on Canvas
        highlightThreatsOnCanvas(analysisResult);

    } catch (error) {
        console.error('[CanvasThreatAnalyzer] Error:', error);
        showNotification('error', 'Analysis Failed', error.message);
    } finally {
        CanvasThreatAnalysisState.isAnalyzing = false;
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = '🔍 Analyze Threats';
        }
    }
}

/**
 * Get Canvas components from current state
 */
function getCanvasComponents() {
    // Get components from AppState.canvas.nodes
    const components = [];

    if (typeof AppState !== 'undefined' && AppState.canvas && AppState.canvas.nodes) {
        AppState.canvas.nodes.forEach((nodeData, nodeId) => {
            const data = nodeData.data || {};
            const component = {
                id: nodeId,
                type: data.cardType || data.type || 'Unknown',
                name: data.name || 'Unnamed Component',
                capabilities: extractCapabilities(data),
                metadata: {
                    description: data.description || '',
                    risk_level: data.risk_level || 'medium',
                    risk_score: data.risk_score || 5.0
                },
                connections: nodeData.connections || []
            };
            components.push(component);
        });
    }

    return components;
}

/**
 * Extract capabilities from component data
 */
function extractCapabilities(data) {
    const capabilities = [];

    // Check description and name for capability keywords
    const text = ((data.description || '') + ' ' + (data.name || '')).toLowerCase();

    if (text.includes('file') || text.includes('write') || text.includes('read')) {
        if (text.includes('write')) capabilities.push('write_file');
        if (text.includes('read')) capabilities.push('read_file');
    }

    if (text.includes('network') || text.includes('http') || text.includes('api') || text.includes('request')) {
        capabilities.push('network_access');
    }

    if (text.includes('exec') || text.includes('command') || text.includes('shell') || text.includes('run')) {
        capabilities.push('exec');
    }

    if (text.includes('database') || text.includes('db') || text.includes('sql')) {
        capabilities.push('db_access');
    }

    if (text.includes('browser') || text.includes('web') || text.includes('page')) {
        capabilities.push('browser_access');
    }

    // Check attack_vector for capabilities
    if (data.attack_vector) {
        const attackVector = typeof data.attack_vector === 'string'
            ? JSON.parse(data.attack_vector || '[]')
            : data.attack_vector;

        if (Array.isArray(attackVector)) {
            attackVector.forEach(step => {
                if (step.tools_needed) {
                    capabilities.push(...step.tools_needed);
                }
            });
        }
    }

    return [...new Set(capabilities)]; // Remove duplicates
}

/**
 * Display threat analysis results
 */
function displayThreatAnalysisResults(analysisResult) {
    const container = document.getElementById('canvas-threat-analysis-results');
    if (!container) return;

    const { threats, attack_paths, risk_score, recommendations, component_count } = analysisResult;

    let html = `
        <div class="analysis-summary">
            <div class="summary-stats">
                <div class="stat-item">
                    <div class="stat-value">${component_count || 0}</div>
                    <div class="stat-label">Components</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${threats?.length || 0}</div>
                    <div class="stat-label">Threats</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${attack_paths?.length || 0}</div>
                    <div class="stat-label">Attack Paths</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value risk-score ${getRiskScoreClass(risk_score)}">${risk_score?.toFixed(1) || '0.0'}</div>
                    <div class="stat-label">Risk Score</div>
                </div>
            </div>
        </div>
    `;

    // Display threats
    if (threats && threats.length > 0) {
        html += `
            <div class="threats-section">
                <h4>Generated Threats (${threats.length})</h4>
                <div class="threats-list">
        `;

        threats.forEach((threat, index) => {
            const severity = threat.severity || 5;
            const severityClass = severity >= 9 ? 'critical' : severity >= 7 ? 'high' : severity >= 5 ? 'medium' : 'low';

            html += `
                <div class="threat-item ${severityClass}" data-threat-id="${threat.id}" onclick="showThreatDetails('${threat.id}')">
                    <div class="threat-header">
                        <span class="threat-severity-badge ${severityClass}">${severity}/10</span>
                        <span class="threat-name">${escapeHtml(threat.name || 'Unknown Threat')}</span>
                    </div>
                    <div class="threat-meta">
                        <span class="threat-component">${escapeHtml(threat.component_name || threat.component_type || 'Unknown')}</span>
                        <span class="threat-surface">${escapeHtml(threat.surface || 'N/A')}</span>
                    </div>
                    <div class="threat-description">${escapeHtml((threat.description || '').substring(0, 100))}${threat.description?.length > 100 ? '...' : ''}</div>
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
    }

    // Display attack paths
    if (attack_paths && attack_paths.length > 0) {
        html += `
            <div class="attack-paths-section">
                <h4>Attack Paths (${attack_paths.length})</h4>
                <div class="attack-paths-list">
        `;

        attack_paths.forEach((path, index) => {
            const severity = path.severity || 5;
            const severityClass = severity >= 9 ? 'critical' : severity >= 7 ? 'high' : severity >= 5 ? 'medium' : 'low';

            html += `
                <div class="attack-path-item ${severityClass}">
                    <div class="path-header">
                        <span class="path-severity-badge ${severityClass}">${severity}/10</span>
                        <span class="path-name">${escapeHtml(path.name || 'Unknown Path')}</span>
                    </div>
                    <div class="path-steps">
                        ${(path.steps || []).map((step, stepIdx) => `
                            <div class="path-step">
                                <span class="step-number">${stepIdx + 1}</span>
                                <span class="step-component">${escapeHtml(step.component_name || step.component_type || 'Unknown')}</span>
                                ${step.attack ? `<span class="step-attack">→ ${escapeHtml(step.attack)}</span>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
    }

    // Display recommendations
    if (recommendations && recommendations.length > 0) {
        html += `
            <div class="recommendations-section">
                <h4>Security Recommendations</h4>
                <div class="recommendations-list">
        `;

        recommendations.forEach((rec, index) => {
            const typeClass = rec.type || 'info';
            html += `
                <div class="recommendation-item ${typeClass}">
                    <div class="recommendation-header">
                        <span class="recommendation-type">${typeClass.toUpperCase()}</span>
                        <span class="recommendation-title">${escapeHtml(rec.title || 'Recommendation')}</span>
                    </div>
                    <div class="recommendation-description">${escapeHtml(rec.description || '')}</div>
                    <div class="recommendation-actions">
                        <ul>
                            ${(rec.actions || []).map(action => `<li>${escapeHtml(action)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

/**
 * Get risk score CSS class
 */
function getRiskScoreClass(score) {
    if (score >= 9) return 'risk-critical';
    if (score >= 7) return 'risk-high';
    if (score >= 5) return 'risk-medium';
    return 'risk-low';
}

/**
 * Update threat count badge
 */
function updateThreatCountBadge(count) {
    const badge = document.getElementById('canvas-threat-count');
    if (badge) {
        badge.textContent = count;
        badge.style.display = count > 0 ? 'inline-block' : 'none';
    }
}

/**
 * Switch detail tab
 */
function switchDetailTab(tab) {
    const detailTab = document.getElementById('detail-tab-content');
    const threatTab = document.getElementById('threat-tab-content');
    const detailTabBtn = document.querySelector('[data-panel-tab="details"]');
    const threatTabBtn = document.querySelector('[data-panel-tab="threats"]');

    if (tab === 'details') {
        if (detailTab) detailTab.classList.add('active');
        if (threatTab) threatTab.classList.remove('active');
        if (detailTabBtn) detailTabBtn.classList.add('active');
        if (threatTabBtn) threatTabBtn.classList.remove('active');
    } else if (tab === 'threats') {
        if (detailTab) detailTab.classList.remove('active');
        if (threatTab) threatTab.classList.add('active');
        if (detailTabBtn) detailTabBtn.classList.remove('active');
        if (threatTabBtn) threatTabBtn.classList.add('active');
    }
}

/**
 * Highlight threats on Canvas
 */
function highlightThreatsOnCanvas(analysisResult) {
    if (!analysisResult.threats || analysisResult.threats.length === 0) {
        return;
    }

    // Group threats by component
    const threatsByComponent = {};
    analysisResult.threats.forEach(threat => {
        const compId = threat.component_id;
        if (compId) {
            if (!threatsByComponent[compId]) {
                threatsByComponent[compId] = [];
            }
            threatsByComponent[compId].push(threat);
        }
    });

    // Add threat badges to components
    Object.keys(threatsByComponent).forEach(compId => {
        const node = document.getElementById(compId);
        if (node) {
            const threats = threatsByComponent[compId];
            const maxSeverity = Math.max(...threats.map(t => t.severity || 5));
            const severityClass = maxSeverity >= 9 ? 'critical' : maxSeverity >= 7 ? 'high' : maxSeverity >= 5 ? 'medium' : 'low';

            // Remove existing badge
            const existingBadge = node.querySelector('.canvas-threat-badge');
            if (existingBadge) {
                existingBadge.remove();
            }

            // Add new badge
            const badge = document.createElement('div');
            badge.className = `canvas-threat-badge ${severityClass}`;
            badge.textContent = `${threats.length}`;
            badge.title = `${threats.length} threat(s) detected`;
            node.appendChild(badge);
        }
    });

    // Highlight attack paths
    if (analysisResult.attack_paths && analysisResult.attack_paths.length > 0) {
        analysisResult.attack_paths.forEach(path => {
            if (path.steps && path.steps.length >= 2) {
                // Highlight connections between components in the path
                for (let i = 0; i < path.steps.length - 1; i++) {
                    const fromId = path.steps[i].component_id;
                    const toId = path.steps[i + 1].component_id;

                    // Find and highlight connection
                    highlightConnection(fromId, toId, path.severity || 5);
                }
            }
        });
    }
}

/**
 * Highlight connection between two components
 */
function highlightConnection(fromId, toId, severity) {
    // This would need to be implemented based on how connections are rendered
    // For now, we'll just log it
    console.log(`[CanvasThreatAnalyzer] Highlighting connection: ${fromId} → ${toId} (severity: ${severity})`);
}

/**
 * Show threat details
 */
function showThreatDetails(threatId) {
    if (!CanvasThreatAnalysisState.analysisResult || !CanvasThreatAnalysisState.analysisResult.threats) {
        return;
    }

    const threat = CanvasThreatAnalysisState.analysisResult.threats.find(t => t.id === threatId);
    if (!threat) {
        return;
    }

    // Create modal
    const modal = document.createElement('div');
    modal.className = 'threat-details-modal';
    modal.innerHTML = `
        <div class="modal-backdrop" onclick="closeThreatDetailsModal()"></div>
        <div class="modal-content threat-details-content">
            <div class="modal-header">
                <h2>${escapeHtml(threat.name || 'Unknown Threat')}</h2>
                <button class="modal-close" onclick="closeThreatDetailsModal()">×</button>
            </div>
            <div class="modal-body">
                <div class="threat-detail-section">
                    <h3>Description</h3>
                    <p>${escapeHtml(threat.description || 'N/A')}</p>
                </div>
                <div class="threat-detail-section">
                    <h3>Component</h3>
                    <p>${escapeHtml(threat.component_name || threat.component_type || 'Unknown')}</p>
                </div>
                <div class="threat-detail-section">
                    <h3>MCPSecBench Classification</h3>
                    <div class="classification-info">
                        <div><strong>Surface:</strong> ${escapeHtml(threat.surface || 'N/A')}</div>
                        <div><strong>Attack Type:</strong> ${escapeHtml(threat.attack_type || 'N/A')}</div>
                        <div><strong>Severity:</strong> <span class="severity-badge severity-${threat.severity >= 9 ? 'critical' : threat.severity >= 7 ? 'high' : threat.severity >= 5 ? 'medium' : 'low'}">${threat.severity || 5}/10</span></div>
                    </div>
                </div>
                ${threat.graph_pattern ? `
                <div class="threat-detail-section">
                    <h3>Graph Pattern</h3>
                    <div class="graph-pattern-display">
                        <div><strong>Pattern:</strong> ${escapeHtml(threat.graph_pattern.pattern_description || 'N/A')}</div>
                        <div><strong>Example:</strong> <code>${escapeHtml(threat.graph_pattern.example_pattern || 'N/A')}</code></div>
                    </div>
                </div>
                ` : ''}
                ${threat.test_template ? `
                <div class="threat-detail-section">
                    <h3>Test Template</h3>
                    <div class="test-template-display">
                        <div><strong>Static Analysis:</strong> ${escapeHtml(threat.test_template.static_analysis || 'N/A')}</div>
                        <div><strong>Blackbox Test:</strong> ${escapeHtml(threat.test_template.blackbox_test || 'N/A')}</div>
                    </div>
                </div>
                ` : ''}
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeThreatDetailsModal()">Close</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
}

/**
 * Close threat details modal
 */
function closeThreatDetailsModal() {
    const modal = document.querySelector('.threat-details-modal');
    if (modal) {
        modal.remove();
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
function showNotification(type, title, message) {
    // Get the global notification function (from app.js)
    const globalNotify = window.showNotification;

    // Check if global function exists and is not this function itself (prevent infinite recursion)
    if (typeof globalNotify === 'function' && globalNotify !== showNotification) {
        // Use the global notification function with correct parameter order
        try {
            // Try different parameter orders based on function signature
            if (globalNotify.length === 3) {
                globalNotify(type, title, message);
            } else if (globalNotify.length === 2) {
                globalNotify(title, message);
            } else {
                globalNotify(message);
            }
        } catch (e) {
            console.error('[CanvasThreatAnalyzer] Error calling global showNotification:', e);
            console.log(`[${type.toUpperCase()}] ${title}: ${message}`);
        }
    } else {
        // Fallback to console log
        console.log(`[${type.toUpperCase()}] ${title}: ${message}`);
    }
}

// Make functions globally available
window.analyzeCanvasThreats = analyzeCanvasThreats;
window.switchDetailTab = switchDetailTab;
window.showThreatDetails = showThreatDetails;
window.closeThreatDetailsModal = closeThreatDetailsModal;


