/**
 * MCP Risk Planning & Detection Methods
 * Plan all risks in MCP and detection methods based on collected intelligence
 */

let riskPlanningData = null;
let riskPlanningAutoRefreshInterval = null;
let lastThreatCount = 0;
let lastIntelCount = 0;
let isAutoRefreshing = false;

/**
 * Auto-load latest risk planning on page load
 */
async function loadLatestRiskPlanning() {
    const loadingEl = document.getElementById('risk-planning-loading');
    const contentEl = document.getElementById('risk-planning-content');
    const summaryEl = document.getElementById('risk-planning-summary');

    try {
        const apiBase = window.API_BASE || (() => {
            const port = window.location.port || '5000';
            const host = window.location.hostname || 'localhost';
            const protocol = window.location.protocol || 'http:';
            return `${protocol}//${host}:${port}/api`;
        })();

        // Get latest risk planning for the project
        const response = await fetch(`${apiBase}/mcp/risk-planning?project_id=default-project`);

        if (response.ok) {
            const data = await response.json();

            // If we have a list, get the latest one
            if (data.plannings && data.plannings.length > 0) {
                const latest = data.plannings[0]; // Already sorted by created_at desc
                riskPlanningData = {
                    risk_planning: latest.planning_data || [],
                    summary: latest.summary || {},
                    planning_id: latest.id
                };

                // Render the loaded planning
                renderSummary(riskPlanningData.summary);
                renderRiskPlanningTable(riskPlanningData.risk_planning);

                // Update counts
                await updateThreatCounts();
                setupAutoRefresh();

                console.log('[RiskPlanning] Auto-loaded latest risk planning');
            } else if (data.risk_planning) {
                // Single planning object
                riskPlanningData = data;
                renderSummary(data.summary || {});
                renderRiskPlanningTable(data.risk_planning || []);
                await updateThreatCounts();
                setupAutoRefresh();
            }
        } else if (response.status !== 404) {
            // 404 is fine (no planning exists yet), but other errors should be logged
            console.warn('[RiskPlanning] Error loading latest planning:', response.status);
        }
    } catch (error) {
        console.warn('[RiskPlanning] Error auto-loading latest planning:', error);
        // Silently fail - user can generate new planning
    }
}

/**
 * Generate risk planning
 */
async function generateRiskPlanning() {
    const loadingEl = document.getElementById('risk-planning-loading');
    const contentEl = document.getElementById('risk-planning-content');
    const summaryEl = document.getElementById('risk-planning-summary');

    // Step 1: Load and display existing data first (don't clear the screen)
    if (!riskPlanningData) {
        await loadLatestRiskPlanning();
    }

    // Step 2: Show loading banner AT TOP without clearing existing content
    loadingEl.style.display = 'flex';
    // Don't clear contentEl — keep existing data visible

    try {
        const response = await fetch('/api/mcp/risk-planning', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                project_id: 'default-project',
                name: `Risk Planning - ${new Date().toLocaleString()}`,
                description: 'AI-generated risk planning based on collected intelligence',
                update_existing: true
            })
        });

        if (!response.ok) {
            let errorData;
            try {
                errorData = await response.json();
            } catch (e) {
                const errorText = await response.text();
                throw new Error(`Server error (${response.status}): ${errorText.substring(0, 200)}`);
            }
            const errorMsg = errorData.message || errorData.error || 'Generation failed';
            const errorDetails = errorData.details || errorData.hint || '';
            throw new Error(errorDetails ? `${errorMsg}. ${errorDetails}` : errorMsg);
        }

        let data;
        try {
            data = await response.json();
        } catch (jsonError) {
            console.error('[RiskPlanning] JSON parse error:', jsonError);
            throw new Error(`JSON parsing failed: ${jsonError.message}. The server response may not be valid JSON.`);
        }
        riskPlanningData = data;

        // Hide loading
        loadingEl.style.display = 'none';

        // Update the display with new data (in-place update, no screen clearing)
        renderSummary(data.summary || {});
        renderRiskPlanningTable(data.risk_planning || []);

        // Notify success
        const count = data.risk_planning?.length || 0;
        if (typeof showNotification === 'function') {
            showNotification('success', 'Risk Planning Updated', `Risk planning updated: ${count} threats analyzed`);
        }

        // Update last counts for auto-refresh
        await updateThreatCounts();
        setupAutoRefresh();

    } catch (error) {
        console.error('[RiskPlanning] Error:', error);
        loadingEl.style.display = 'none';

        // Show error banner WITHOUT clearing existing data
        const errorBanner = document.createElement('div');
        errorBanner.className = 'risk-planning-error';
        errorBanner.innerHTML = `
            <p class="error-title">❌ Generation Failed</p>
            <p class="error-message">${error.message}</p>
            <button class="btn btn-primary" onclick="this.parentElement.remove(); generateRiskPlanning()">Retry</button>
        `;
        // Insert error at top, keep existing data below
        contentEl.insertBefore(errorBanner, contentEl.firstChild);
    }
}

/**
 * Render summary statistics
 */
function renderSummary(summary) {
    const summaryEl = document.getElementById('risk-planning-summary');

    if (!summary || Object.keys(summary).length === 0) {
        summaryEl.style.display = 'none';
        return;
    }

    summaryEl.innerHTML = `
        <div class="summary-grid">
            <div class="summary-item">
                <div class="summary-label">Total Threats</div>
                <div class="summary-value">${summary.total_threats || 0}</div>
            </div>
            <div class="summary-item critical">
                <div class="summary-label">Critical</div>
                <div class="summary-value">${summary.critical_count || 0}</div>
            </div>
            <div class="summary-item high">
                <div class="summary-label">High</div>
                <div class="summary-value">${summary.high_count || 0}</div>
            </div>
            <div class="summary-item medium">
                <div class="summary-label">Medium</div>
                <div class="summary-value">${summary.medium_count || 0}</div>
            </div>
            <div class="summary-item low">
                <div class="summary-label">Low</div>
                <div class="summary-value">${summary.low_count || 0}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Intel Items Analyzed</div>
                <div class="summary-value">${summary.intel_items_analyzed || 0}</div>
            </div>
        </div>
    `;

    summaryEl.style.display = 'block';
}

/**
 * Render risk planning table
 */
function renderRiskPlanningTable(riskPlanning) {
    const contentEl = document.getElementById('risk-planning-content');

    if (!riskPlanning || riskPlanning.length === 0) {
        contentEl.innerHTML = `
            <div class="risk-planning-empty">
                <p>No risk planning data found</p>
            </div>
        `;
        return;
    }

    // Create table
    let tableHTML = `
        <div class="risk-planning-table-wrapper">
            <table class="risk-planning-table">
                <thead>
                    <tr>
                        <th class="col-priority">Priority</th>
                        <th class="col-threat">Threat Name</th>
                        <th class="col-risk">Risk Level</th>
                        <th class="col-phase">Workflow Phase</th>
                        <th class="col-attack">Attack Type</th>
                        <th class="col-detection">Detection Methods</th>
                        <th class="col-tools">Detection Tools</th>
                        <th class="col-test">Test Cases</th>
                        <th class="col-actions">Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;

    // Sort by priority and risk score
    const sortedPlanning = [...riskPlanning].sort((a, b) => {
        const priorityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
        const priorityDiff = (priorityOrder[b.priority] || 0) - (priorityOrder[a.priority] || 0);
        if (priorityDiff !== 0) return priorityDiff;
        return (b.risk_score || 0) - (a.risk_score || 0);
    });

    sortedPlanning.forEach((item, index) => {
        const riskLevel = item.risk_level || 'Unknown';
        const priority = item.priority || 'Medium';
        const riskScore = item.risk_score || 0;

        // Get detection methods summary
        const detectionMethods = item.detection_methods || {};
        const detectionSummary = Object.entries(detectionMethods)
            .map(([key, value]) => `<strong>${key}:</strong> ${value}`)
            .join('<br>') || 'Not specified';

        // Get detection tools
        const tools = Array.isArray(item.detection_tools)
            ? item.detection_tools.join(', ')
            : 'Not specified';

        // Get test cases summary
        const testCases = Array.isArray(item.test_cases) && item.test_cases.length > 0
            ? item.test_cases.map(tc => `<strong>${tc.test_name || 'Test'}:</strong> ${tc.test_description || ''}`).join('<br>')
            : 'Not specified';

        tableHTML += `
            <tr class="risk-row" data-index="${index}">
                <td class="col-priority">
                    <span class="priority-badge priority-${priority.toLowerCase()}">${priority}</span>
                </td>
                <td class="col-threat">
                    <div class="threat-name">${escapeHtml(item.threat_name || item.name || 'Unknown')}</div>
                    <div class="threat-summary">${escapeHtml(item.risk_summary || item.description || '')}</div>
                </td>
                <td class="col-risk">
                    <span class="risk-badge risk-${riskLevel.toLowerCase()}">${riskLevel}</span>
                    <div class="risk-score">Score: ${riskScore.toFixed(1)}</div>
                </td>
                <td class="col-phase">${escapeHtml(item.workflow_phase || 'N/A')}</td>
                <td class="col-attack">${escapeHtml(item.attack_type || 'N/A')}</td>
                <td class="col-detection">
                    <div class="detection-methods">${detectionSummary}</div>
                </td>
                <td class="col-tools">${escapeHtml(tools)}</td>
                <td class="col-test">
                    <div class="test-cases">${testCases}</div>
                </td>
                <td class="col-actions">
                    <button class="btn-icon" onclick="showRiskDetails(${index})" title="View Details">
                        👁️
                    </button>
                </td>
            </tr>
        `;
    });

    tableHTML += `
                </tbody>
            </table>
        </div>
    `;

    contentEl.innerHTML = tableHTML;
}

/**
 * Show risk details
 */
function showRiskDetails(index) {
    if (!riskPlanningData || !riskPlanningData.risk_planning) return;

    const item = riskPlanningData.risk_planning[index];
    if (!item) return;

    const detectionMethods = item.detection_methods || {};
    const testCases = item.test_cases || [];
    const indicators = item.detection_indicators || [];

    let detailsHTML = `
        <div class="risk-details-modal">
            <div class="modal-backdrop" onclick="closeRiskDetails()"></div>
            <div class="modal-content risk-details-content">
                <div class="modal-header">
                    <h2 class="risk-details-title">${escapeHtml(item.threat_name || item.name || 'Unknown')}</h2>
                    <button class="modal-close" onclick="closeRiskDetails()">×</button>
                </div>
                <div class="modal-body">
                    <div class="detail-section">
                        <h3 class="detail-section-title">Risk Summary</h3>
                        <p class="detail-text">${escapeHtml(item.risk_summary || item.description || 'N/A')}</p>
                    </div>
                    
                    <div class="detail-section">
                        <h3 class="detail-section-title">Threat Information</h3>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Threat Vector:</span>
                                <span class="detail-value">${escapeHtml(item.threat_vector || 'N/A')}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Workflow Phase:</span>
                                <span class="detail-value">${escapeHtml(item.workflow_phase || 'N/A')}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Attack Type:</span>
                                <span class="detail-value">${escapeHtml(item.attack_type || 'N/A')}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Risk Level:</span>
                                <span class="detail-value risk-badge risk-${(item.risk_level || 'medium').toLowerCase()}">${item.risk_level || 'Medium'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Risk Score:</span>
                                <span class="detail-value">${(item.risk_score || 0).toFixed(1)}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Priority:</span>
                                <span class="detail-value priority-badge priority-${(item.priority || 'medium').toLowerCase()}">${item.priority || 'Medium'}</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h3 class="detail-section-title">Detection Methods</h3>
                        <div class="detection-methods-detail">
    `;

    Object.entries(detectionMethods).forEach(([method, description]) => {
        detailsHTML += `
            <div class="detection-method-item">
                <strong class="method-name">${escapeHtml(method)}:</strong>
                <p class="method-description">${escapeHtml(description)}</p>
            </div>
        `;
    });

    detailsHTML += `
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h3 class="detail-section-title">Detection Tools</h3>
                        <div class="tools-list">
    `;

    if (Array.isArray(item.detection_tools) && item.detection_tools.length > 0) {
        item.detection_tools.forEach(tool => {
            detailsHTML += `<span class="tool-badge">${escapeHtml(tool)}</span>`;
        });
    } else {
        detailsHTML += `<p class="detail-text">Not specified</p>`;
    }

    detailsHTML += `
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h3 class="detail-section-title">Detection Indicators</h3>
                        <ul class="indicators-list">
    `;

    if (indicators.length > 0) {
        indicators.forEach(indicator => {
            detailsHTML += `<li>${escapeHtml(indicator)}</li>`;
        });
    } else {
        detailsHTML += `<li>Not specified</li>`;
    }

    detailsHTML += `
                        </ul>
                    </div>
                    
                    <div class="detail-section">
                        <h3 class="detail-section-title">Test Cases</h3>
                        <div class="test-cases-detail">
    `;

    if (testCases.length > 0) {
        testCases.forEach((testCase, idx) => {
            detailsHTML += `
                <div class="test-case-item">
                    <h4 class="test-case-name">${escapeHtml(testCase.test_name || `Test Case ${idx + 1}`)}</h4>
                    <p class="test-case-description"><strong>Description:</strong> ${escapeHtml(testCase.test_description || 'N/A')}</p>
                    ${testCase.expected_result ? `<p class="test-case-result"><strong>Expected Result:</strong> ${escapeHtml(testCase.expected_result)}</p>` : ''}
                </div>
            `;
        });
    } else {
        detailsHTML += `<p class="detail-text">Not specified</p>`;
    }

    detailsHTML += `
                        </div>
                    </div>
                    
                    ${item.recommendations ? `
                    <div class="detail-section">
                        <h3 class="detail-section-title">Recommendations</h3>
                        <p class="detail-text">${escapeHtml(item.recommendations)}</p>
                    </div>
                    ` : ''}
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="closeRiskDetails()">Close</button>
                </div>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', detailsHTML);
}

/**
 * Close risk details modal
 */
function closeRiskDetails() {
    const modal = document.querySelector('.risk-details-modal');
    if (modal) {
        modal.remove();
    }
}

/**
 * Export risk planning as JSON
 */
function exportRiskPlanningJSON() {
    if (!riskPlanningData || !riskPlanningData.risk_planning) {
        alert('Please generate risk planning first');
        return;
    }

    const exportData = {
        summary: riskPlanningData.summary || {},
        risk_planning: riskPlanningData.risk_planning || [],
        exported_at: new Date().toISOString(),
        version: '1.0'
    };

    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `mcp-risk-planning-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

/**
 * Export risk planning as CSV
 */
function exportRiskPlanningCSV() {
    if (!riskPlanningData || !riskPlanningData.risk_planning) {
        alert('Please generate risk planning first');
        return;
    }

    const planning = riskPlanningData.risk_planning || [];

    // CSV headers
    const headers = [
        'Priority',
        'Threat Name',
        'Risk Level',
        'Risk Score',
        'Workflow Phase',
        'Attack Type',
        'Threat Vector',
        'Detection Methods (Static)',
        'Detection Methods (Dynamic)',
        'Detection Methods (Behavioral)',
        'Detection Methods (Signature)',
        'Detection Tools',
        'Detection Indicators',
        'Test Cases',
        'Recommendations'
    ];

    // Build CSV rows
    const rows = [headers.join(',')];

    planning.forEach(item => {
        const detectionMethods = item.detection_methods || {};
        const tools = Array.isArray(item.detection_tools) ? item.detection_tools.join('; ') : (item.detection_tools || '');
        const indicators = Array.isArray(item.detection_indicators) ? item.detection_indicators.join('; ') : '';
        const testCases = Array.isArray(item.test_cases)
            ? item.test_cases.map(tc => `${tc.test_name || 'Test'}: ${tc.test_description || ''}`).join('; ')
            : '';

        const row = [
            escapeCsvField(item.priority || 'Medium'),
            escapeCsvField(item.threat_name || item.name || 'Unknown'),
            escapeCsvField(item.risk_level || 'Medium'),
            (item.risk_score || 0).toFixed(1),
            escapeCsvField(item.workflow_phase || 'N/A'),
            escapeCsvField(item.attack_type || 'N/A'),
            escapeCsvField(item.threat_vector || 'N/A'),
            escapeCsvField(detectionMethods.static_analysis || ''),
            escapeCsvField(detectionMethods.dynamic_monitoring || ''),
            escapeCsvField(detectionMethods.behavioral_analysis || ''),
            escapeCsvField(detectionMethods.signature_based || ''),
            escapeCsvField(tools),
            escapeCsvField(indicators),
            escapeCsvField(testCases),
            escapeCsvField(item.recommendations || '')
        ];

        rows.push(row.join(','));
    });

    const csvContent = rows.join('\n');
    const dataBlob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' }); // BOM for Excel
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `mcp-risk-planning-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
}

/**
 * Escape CSV field (handle commas, quotes, newlines)
 */
function escapeCsvField(field) {
    if (field === null || field === undefined) return '';
    const str = String(field);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

/**
 * Export risk planning (shows menu for JSON/CSV)
 */
function exportRiskPlanning() {
    if (!riskPlanningData || !riskPlanningData.risk_planning) {
        alert('Please generate risk planning first');
        return;
    }

    // Show export menu
    const menu = document.createElement('div');
    menu.className = 'export-menu';
    menu.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: var(--bg-primary, #fff);
        border: 1px solid var(--border-color, #ddd);
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
    `;

    menu.innerHTML = `
        <h3 style="margin: 0 0 16px 0; font-size: 1.1rem;">Export Risk Planning</h3>
        <div style="display: flex; gap: 12px;">
            <button class="btn btn-primary" onclick="exportRiskPlanningJSON(); this.closest('.export-menu').remove();" style="flex: 1;">
                Export as JSON
            </button>
            <button class="btn btn-primary" onclick="exportRiskPlanningCSV(); this.closest('.export-menu').remove();" style="flex: 1;">
                Export as CSV
            </button>
            <button class="btn btn-secondary" onclick="this.closest('.export-menu').remove();">
                Cancel
            </button>
        </div>
    `;

    const backdrop = document.createElement('div');
    backdrop.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.3);
        z-index: 9999;
    `;
    backdrop.onclick = () => {
        menu.remove();
        backdrop.remove();
    };

    document.body.appendChild(backdrop);
    document.body.appendChild(menu);
}

// Make export functions globally available
window.exportRiskPlanning = exportRiskPlanning;
window.exportRiskPlanningJSON = exportRiskPlanningJSON;
window.exportRiskPlanningCSV = exportRiskPlanningCSV;

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
 * Update threat and intel counts for auto-refresh
 */
async function updateThreatCounts() {
    try {
        const apiBase = window.API_BASE || (() => {
            const port = window.location.port || '5000';
            const host = window.location.hostname || 'localhost';
            const protocol = window.location.protocol || 'http:';
            return `${protocol}//${host}:${port}/api`;
        })();

        const threatsResponse = await fetch(`${apiBase}/threats?limit=1`);
        if (threatsResponse.ok) {
            const threatsData = await threatsResponse.json();
            lastThreatCount = threatsData.total || 0;
        }

        const intelResponse = await fetch(`${apiBase}/intel/items?limit=1`);
        if (intelResponse.ok) {
            const intelData = await intelResponse.json();
            lastIntelCount = intelData.total || 0;
        }
    } catch (e) {
        console.warn('[RiskPlanning] Error updating counts:', e);
    }
}

/**
 * Setup auto-refresh to regenerate risk planning when new threats are detected
 */
function setupAutoRefresh() {
    // Clear existing interval
    if (riskPlanningAutoRefreshInterval) {
        clearInterval(riskPlanningAutoRefreshInterval);
    }

    // Check every 15 seconds for new threats
    riskPlanningAutoRefreshInterval = setInterval(async () => {
        if (isAutoRefreshing) return; // Prevent concurrent refreshes

        try {
            const apiBase = window.API_BASE || (() => {
                const port = window.location.port || '5000';
                const host = window.location.hostname || 'localhost';
                const protocol = window.location.protocol || 'http:';
                return `${protocol}//${host}:${port}/api`;
            })();

            const threatsResponse = await fetch(`${apiBase}/threats?limit=1`);
            if (threatsResponse.ok) {
                const threatsData = await threatsResponse.json();
                const currentThreatCount = threatsData.total || 0;

                // If threat count increased, auto-regenerate risk planning
                if (currentThreatCount > lastThreatCount) {
                    console.log(`[RiskPlanning] Detected ${currentThreatCount - lastThreatCount} new threat(s), auto-regenerating risk planning...`);
                    isAutoRefreshing = true;
                    lastThreatCount = currentThreatCount;

                    // Show notification
                    if (typeof showNotification === 'function') {
                        showNotification('New threats detected, regenerating risk planning...', 'info');
                    }

                    // Auto-regenerate
                    await generateRiskPlanning();
                    isAutoRefreshing = false;
                }
            }
        } catch (e) {
            console.warn('[RiskPlanning] Auto-refresh error:', e);
            isAutoRefreshing = false;
        }
    }, 15000); // Check every 15 seconds
}

// Initialize: auto-load latest planning and counts on page load
if (typeof window !== 'undefined') {
    window.addEventListener('load', () => {
        loadLatestRiskPlanning();
        updateThreatCounts();
    });
}
