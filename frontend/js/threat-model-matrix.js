/**
 * Threat Model Matrix
 * 
 * Displays intelligence-driven threat modeling based on STRIDE and Standard Framework
 */

const ThreatModelMatrixState = {
    threats: [],
    intelItems: [],
    strideDistribution: {},
    mcpsecbenchMatrix: {},
    intelToThreatMapping: []
};

// Standard Attack Surfaces
// Licensed under Apache 2.0
const ATTACK_SURFACES = [
    'User Interaction',
    'MCP Client',
    'MCP Transport',
    'MCP Server'
];

// Standard Attack Types (17 types)
const ATTACK_TYPES = [
    'Prompt Injection',
    'Tool Poisoning',
    'Tool Shadowing',
    'Data Exfiltration',
    'Jailbreak',
    'Schema Inconsistencies',
    'Slash Command Overlap',
    'MCP Rebinding',
    'Man-in-the-Middle',
    'Sandbox Escape',
    'Unauthorized Access',
    'Privilege Escalation',
    'Denial of Service',
    'Context Injection',
    'Supply Chain Attack',
    'Configuration Weakness',
    'Vulnerability Exploitation'
];

// STRIDE Categories
const STRIDE_CATEGORIES = [
    'Spoofing',
    'Tampering',
    'Repudiation',
    'Information Disclosure',
    'Denial of Service',
    'Elevation of Privilege'
];

/**
 * Get API base URL
 * Uses the same logic as app.js to auto-detect the current port
 * Returns URL with /api suffix (e.g., http://localhost:5000/api)
 */
function getApiBase() {
    // Try to use API_BASE from app.js if available (it's a const, so check if it exists in scope)
    if (typeof API_BASE !== 'undefined') {
        return API_BASE;
    }

    // Auto-detect from current window location (same logic as app.js)
    const port = window.location.port || '5000';
    const host = window.location.hostname || 'localhost';
    const protocol = window.location.protocol || 'http:';

    // Return with /api suffix to match app.js format
    return `${protocol}//${host}:${port}/api`;
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    // Check if there's a global notification function (from app.js)
    const globalNotify = window.showNotification;
    if (globalNotify && globalNotify !== showNotification) {
        // Use the global notification function with correct parameter order
        if (typeof globalNotify === 'function') {
            try {
                // Try different parameter orders
                if (globalNotify.length === 3) {
                    globalNotify(type, 'Threat Model Matrix', message);
                } else {
                    globalNotify(message, type);
                }
            } catch (e) {
                console.log(`[${type.toUpperCase()}] ${message}`);
            }
        }
    } else {
        // Fallback to console or create simple notification
        console.log(`[${type.toUpperCase()}] ${message}`);
        // Try to use app.js notification if available
        if (typeof window.AppState !== 'undefined' && window.AppState.showNotification) {
            window.AppState.showNotification(message, type);
        }
    }
}

/**
 * Load threat model matrix data
 */
async function loadThreatModelMatrix() {
    console.log('[ThreatModelMatrix] loadThreatModelMatrix called');
    try {
        showNotification('Loading threat model matrix...', 'info');

        const apiBase = getApiBase();
        console.log('[ThreatModelMatrix] API Base:', apiBase);

        // Load threats (apiBase already includes /api, so don't add /api again)
        const threatsResponse = await fetch(`${apiBase}/threats?limit=1000`);
        if (!threatsResponse.ok) {
            throw new Error(`Failed to load threats: ${threatsResponse.status}`);
        }
        const threatsData = await threatsResponse.json();
        ThreatModelMatrixState.threats = threatsData.threats || [];
        console.log('[ThreatModelMatrix] Loaded threats:', ThreatModelMatrixState.threats.length);

        // Load intel items (apiBase already includes /api, so don't add /api again)
        const intelResponse = await fetch(`${apiBase}/intel/items?limit=10000`);
        if (!intelResponse.ok) {
            throw new Error(`Failed to load intel items: ${intelResponse.status}`);
        }
        const intelData = await intelResponse.json();
        ThreatModelMatrixState.intelItems = intelData.items || [];
        console.log('[ThreatModelMatrix] Loaded intel items:', ThreatModelMatrixState.intelItems.length);
        console.log('[ThreatModelMatrix] Total intel items in database:', intelData.total || ThreatModelMatrixState.intelItems.length);

        // Calculate statistics
        calculateStatistics();

        // Render all sections
        renderStrideDistribution();
        // renderMCPSecBenchMatrix(); // MCPSecBench 4×17 Threat Matrix removed
        renderIntelToThreatMapping();

        showNotification('Threat model matrix loaded', 'success');
    } catch (error) {
        console.error('[ThreatModelMatrix] Error loading threat model matrix:', error);
        showNotification(`Failed to load threat model matrix: ${error.message}`, 'error');
    }
}

/**
 * Generate threats from intelligence items
 */
async function generateThreatModelFromIntel(forceReprocess = false) {
    console.log('[ThreatModelMatrix] generateThreatModelFromIntel called');

    // Check if task is already running
    const taskId = 'generate-threats';
    if (typeof AppState !== 'undefined' && AppState.backgroundTasks && AppState.backgroundTasks.has(taskId)) {
        const task = AppState.backgroundTasks.get(taskId);
        showNotification('Threat generation is already running in the background. You can switch pages and it will continue.', 'info');
        return;
    }

    try {
        console.log('[ThreatModelMatrix] Starting threat generation...');
        showNotification('Generating threats from intelligence... This will continue in the background even if you switch pages.', 'info');

        const apiBase = getApiBase();
        console.log('[ThreatModelMatrix] API Base:', apiBase);

        // Create task promise without AbortController - let it run in background
        const taskPromise = (async () => {
            const response = await fetch(`${apiBase}/intel/generate-threats`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    limit: 10000,
                    project_id: 'default-project',
                    force_reprocess: forceReprocess
                })
                // Removed signal: controller.signal to allow background execution
            });

            return response;
        })();

        // Track task in background tasks (if AppState is available)
        if (typeof AppState !== 'undefined' && AppState.backgroundTasks) {
            AppState.backgroundTasks.set(taskId, {
                type: 'threat-generation',
                status: 'running',
                startTime: Date.now(),
                promise: taskPromise
            });
        }

        let response;
        response = await taskPromise;

        console.log('[ThreatModelMatrix] Response status:', response.status);

        if (!response.ok) {
            // Check for specific error codes
            let errorData = {};
            try {
                errorData = await response.json();
            } catch (e) {
                // If not JSON, use text
                const errorText = await response.text().catch(() => 'Unknown error');
                throw new Error(`Server error: ${response.status} - ${errorText}`);
            }

            // Handle ALL_PROCESSED case
            if (response.status === 409 && errorData.code === 'ALL_PROCESSED') {
                if (confirm(`All ${errorData.total_items || 'intelligence'} items have already been processed. Do you want to force re-process them to update existing threats? This will check for updates to existing threats.`)) {
                    // Remove task to allow restart
                    if (typeof AppState !== 'undefined' && AppState.backgroundTasks) {
                        AppState.backgroundTasks.delete(taskId);
                    }
                    // Recursive call with forceReprocess
                    return generateThreatModelFromIntel(true);
                } else {
                    showNotification('Threat generation cancelled.', 'info');
                    // Mark task as failed/cancelled
                     if (typeof AppState !== 'undefined' && AppState.backgroundTasks) {
                        AppState.backgroundTasks.set(taskId, {
                            ...AppState.backgroundTasks.get(taskId),
                            status: 'failed',
                            error: 'Cancelled by user'
                        });
                    }
                    return;
                }
            }

            const errorMsg = errorData.error || errorData.message || `Server error: ${response.status}`;
            throw new Error(errorMsg);
        }

        const data = await response.json();
        console.log('[ThreatModelMatrix] Response data:', data);

        if (response.ok) {
            const threatsCount = data.stats?.threats_count || data.threats_count || data.saved?.threats_count || 0;
            const message = data.message || `Generated ${threatsCount} threats from intelligence`;
            showNotification(message, 'success');

            // Update task status (if AppState is available)
            if (typeof AppState !== 'undefined' && AppState.backgroundTasks) {
                AppState.backgroundTasks.set(taskId, {
                    ...AppState.backgroundTasks.get(taskId),
                    status: 'completed',
                    result: data
                });
            }

            // Reload the matrix if we're on the threat-model-matrix tab
            if (typeof AppState !== 'undefined' && AppState.activeTab === 'threat-model-matrix') {
                await loadThreatModelMatrix();
            }
        } else {
            const errorMsg = data.error || data.message || 'Failed to generate threats';
            console.error('[ThreatModelMatrix] Error:', errorMsg);

            // Update task status (if AppState is available)
            if (typeof AppState !== 'undefined' && AppState.backgroundTasks) {
                AppState.backgroundTasks.set(taskId, {
                    ...AppState.backgroundTasks.get(taskId),
                    status: 'failed',
                    error: errorMsg
                });
            }

            // Provide helpful guidance
            let userMessage = errorMsg;
            if (errorMsg.includes('No intelligence items found') || errorMsg.includes('No relevant intelligence items found')) {
                userMessage = 'No intelligence items found. Please go to the Intelligence tab and collect intelligence first.';
            }

            showNotification(userMessage, 'error');
        }
    } catch (error) {
        console.error('[ThreatModelMatrix] Exception generating threats from intel:', error);

        // Update task status (if AppState is available)
        if (typeof AppState !== 'undefined' && AppState.backgroundTasks) {
            if (AppState.backgroundTasks.has(taskId)) {
                AppState.backgroundTasks.set(taskId, {
                    ...AppState.backgroundTasks.get(taskId),
                    status: 'failed',
                    error: error.message
                });
            }
        }

        // Only show error if we're on the same tab or error is critical
        const isOnMatrixTab = typeof AppState !== 'undefined' && AppState.activeTab === 'threat-model-matrix';
        if (isOnMatrixTab || error.message.includes('Server connection failed')) {
            showNotification(`Failed to generate threats: ${error.message}`, 'error');
        } else {
            // Show notification that task failed in background
            showNotification('Threat generation failed. Check the Threat Model Matrix tab for details.', 'error');
        }
    } finally {
        // Clean up task after a delay (keep for status checking)
        if (typeof AppState !== 'undefined' && AppState.backgroundTasks) {
            setTimeout(() => {
                if (AppState.backgroundTasks.has(taskId)) {
                    const task = AppState.backgroundTasks.get(taskId);
                    if (task.status === 'completed' || task.status === 'failed') {
                        AppState.backgroundTasks.delete(taskId);
                    }
                }
            }, 60000); // Keep for 1 minute for status checking
        }
    }
}

/**
 * Refresh threat model matrix
 */
async function refreshThreatModelMatrix() {
    console.log('[ThreatModelMatrix] refreshThreatModelMatrix called');
    await loadThreatModelMatrix();
}

/**
 * Calculate statistics
 */
function calculateStatistics() {
    // Total threats
    const totalThreats = ThreatModelMatrixState.threats.length;
    document.getElementById('tm-total-threats').textContent = totalThreats;

    // Intel items mapped - count items that are actually mapped to threats
    const mappedIntelIds = new Set();

    // First, collect all source_intel_ids from threats
    ThreatModelMatrixState.threats.forEach(threat => {
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

    // Also check for fuzzy matches by title/content - iterate through all intel items
    ThreatModelMatrixState.intelItems.forEach(intel => {
        if (!intel || !intel.id) return;

        const intelIdStr = String(intel.id);
        const intelIdNum = !isNaN(intel.id) ? parseInt(intel.id, 10) : null;

        // Skip if already counted
        if (mappedIntelIds.has(intelIdStr)) {
            return;
        }

        // Check if any threat references this intel item
        const isMapped = ThreatModelMatrixState.threats.some(threat => {
            const sourceIntelIds = threat.metadata?.source_intel_ids ||
                threat.schema_data?.source_intel_ids ||
                threat.source_intel_ids || [];
            const ids = Array.isArray(sourceIntelIds) ? sourceIntelIds :
                (sourceIntelIds ? [sourceIntelIds] : []);

            // Direct ID match - check multiple formats
            if (ids.includes(intelIdStr) ||
                (intelIdNum !== null && ids.includes(intelIdNum)) ||
                ids.some(id => String(id) === intelIdStr || String(id) === String(intel.id))) {
                return true;
            }

            // Fuzzy match by title/content
            const intelTitle = (intel.title || '').toLowerCase().trim();
            if (intelTitle && intelTitle.length > 5) {
                const threatDesc = (threat.description || '').toLowerCase();
                const threatName = (threat.name || '').toLowerCase();
                if (threatDesc.includes(intelTitle) || threatName.includes(intelTitle)) {
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

    document.getElementById('tm-intel-mapped').textContent = mappedIntelIds.size;

    // STRIDE distribution - check multiple possible field locations
    const strideCategories = new Set();
    ThreatModelMatrixState.threats.forEach(threat => {
        const category = threat.category ||
            threat.stride_category ||
            threat.metadata?.stride_category ||
            threat.schema_data?.stride_category;
        if (category && STRIDE_CATEGORIES.includes(category)) {
            strideCategories.add(category);
        }
    });
    document.getElementById('tm-stride-distribution').textContent = strideCategories.size;

    // Attack surfaces (from standard classification) - check multiple possible field locations
    const attackSurfacesSet = new Set();
    ThreatModelMatrixState.threats.forEach(threat => {
        // Check multiple possible locations for attack_surface
        const surface = threat.metadata?.attack_surface ||
            threat.schema_data?.attack_surface ||
            threat.attack_surface;

        if (surface) {
            // Normalize surface name to match ATTACK_SURFACES
            const normalizedSurface = ATTACK_SURFACES.find(s =>
                s.toLowerCase() === surface.toLowerCase() ||
                surface.toLowerCase().includes(s.toLowerCase())
            );

            if (normalizedSurface) {
                attackSurfacesSet.add(normalizedSurface);
            } else if (ATTACK_SURFACES.includes(surface)) {
                attackSurfacesSet.add(surface);
            }
        }
    });
    document.getElementById('tm-attack-surfaces').textContent = attackSurfacesSet.size;

    // Calculate STRIDE distribution for chart
    ThreatModelMatrixState.strideDistribution = {};
    STRIDE_CATEGORIES.forEach(category => {
        ThreatModelMatrixState.strideDistribution[category] =
            ThreatModelMatrixState.threats.filter(t => {
                const threatCategory = t.category ||
                    t.stride_category ||
                    t.metadata?.stride_category ||
                    t.schema_data?.stride_category;
                return threatCategory === category;
            }).length;
    });
}

/**
 * Render STRIDE distribution chart
 */
function renderStrideDistribution() {
    const container = document.getElementById('stride-distribution-chart');
    if (!container) return;

    if (ThreatModelMatrixState.threats.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No threats found. Generate threats from intelligence first.</p>
            </div>
        `;
        return;
    }

    const maxCount = Math.max(...Object.values(ThreatModelMatrixState.strideDistribution), 1);

    let html = '<div class="stride-chart">';
    STRIDE_CATEGORIES.forEach(category => {
        const count = ThreatModelMatrixState.strideDistribution[category] || 0;
        const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;

        html += `
            <div class="stride-bar-item">
                <div class="stride-bar-label">
                    <span>${category}</span>
                    <span class="stride-bar-count">${count}</span>
                </div>
                <div class="stride-bar">
                    <div class="stride-bar-fill" style="width: ${percentage}%; background: ${getStrideColor(category)};"></div>
                </div>
            </div>
        `;
    });
    html += '</div>';

    container.innerHTML = html;
}

/**
 * Get color for STRIDE category
 */
function getStrideColor(category) {
    const colors = {
        'Spoofing': '#ef4444',
        'Tampering': '#D97706',
        'Repudiation': '#8b5cf6',
        'Information Disclosure': '#3b82f6',
        'Denial of Service': '#10b981',
        'Elevation of Privilege': '#ec4899'
    };
    return colors[category] || '#6b7280';
}

/**
 * Render Threat Matrix
 */
function renderMCPSecBenchMatrix() {
    // MCPSecBench 4×17 Threat Matrix feature removed
    return;
    const container = document.getElementById('mcpsecbench-matrix');
    if (!container) return;

    if (ThreatModelMatrixState.threats.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No threats found. Generate threats from intelligence first.</p>
            </div>
        `;
        return;
    }

    // Build matrix data
    const matrix = {};
    ATTACK_SURFACES.forEach(surface => {
        matrix[surface] = {};
        ATTACK_TYPES.forEach(type => {
            matrix[surface][type] = 0;
        });
    });

    // Count threats by surface and type
    ThreatModelMatrixState.threats.forEach(threat => {
        // Try multiple ways to get attack_surface and attack_type
        const surface = threat.metadata?.attack_surface ||
            threat.schema_data?.attack_surface ||
            threat.attack_surface;
        const type = threat.metadata?.attack_type ||
            threat.schema_data?.attack_type ||
            threat.attack_type;

        // Only process if we have valid surface and type
        if (!surface || !type) {
            return;
        }

        // Normalize surface and type to match ATTACK_SURFACES and ATTACK_TYPES
        const normalizedSurface = ATTACK_SURFACES.find(s =>
            s.toLowerCase() === surface.toLowerCase() ||
            surface.toLowerCase().includes(s.toLowerCase())
        );

        const normalizedType = ATTACK_TYPES.find(t =>
            t.toLowerCase() === type.toLowerCase() ||
            type.toLowerCase().includes(t.toLowerCase())
        );

        // Only increment if we found valid matches
        if (normalizedSurface && normalizedType &&
            matrix[normalizedSurface] &&
            matrix[normalizedSurface][normalizedType] !== undefined) {
            matrix[normalizedSurface][normalizedType]++;
        }
    });

    // Render matrix with improved layout
    let html = '<div class="mcpsecbench-matrix-wrapper">';
    html += '<div class="mcpsecbench-matrix-table">';

    // Header row with better spacing
    html += '<div class="matrix-row matrix-header">';
    html += '<div class="matrix-cell matrix-header-cell matrix-corner-cell">Attack Surface / Type</div>';
    ATTACK_TYPES.forEach(type => {
        // Use shorter labels for display, full text in title
        const shortLabel = type.length > 12 ? type.substring(0, 10) + '..' : type;
        html += `<div class="matrix-cell matrix-header-cell matrix-type-header" title="${type}">
            <span class="type-label">${shortLabel}</span>
        </div>`;
    });
    html += '</div>';

    // Data rows
    ATTACK_SURFACES.forEach(surface => {
        html += '<div class="matrix-row">';
        html += `<div class="matrix-cell matrix-label-cell" title="${surface}">
            <span class="surface-label">${surface}</span>
        </div>`;
        ATTACK_TYPES.forEach(type => {
            const count = matrix[surface][type] || 0;
            const intensity = count > 0 ? Math.min(count / 10, 1) : 0;
            const bgColor = count > 0 ? `rgba(239, 68, 68, ${0.3 + intensity * 0.7})` : 'var(--bg-secondary)';
            html += `
                <div class="matrix-cell matrix-data-cell" 
                     style="background: ${bgColor};"
                     title="${surface} - ${type}: ${count} threat(s)">
                    ${count > 0 ? `<span class="threat-count">${count}</span>` : ''}
                </div>
            `;
        });
        html += '</div>';
    });

    html += '</div></div>';
    container.innerHTML = html;
}

/**
 * Render Intel to Threat mapping
 */
function renderIntelToThreatMapping() {
    const container = document.getElementById('intel-threat-mapping');
    if (!container) return;

    if (ThreatModelMatrixState.intelItems.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No intelligence items found. Gather intelligence first.</p>
            </div>
        `;
        return;
    }

    // Build mapping - include all intel items, not just relevant ones
    const mapping = [];
    ThreatModelMatrixState.intelItems.forEach(intel => {
        // Find threats related to this intel item
        const relatedThreats = ThreatModelMatrixState.threats.filter(threat => {
            // Check multiple possible locations for source_intel_ids
            const sourceIntelIds = threat.metadata?.source_intel_ids ||
                threat.schema_data?.source_intel_ids ||
                threat.source_intel_ids || [];

            // Handle both array and string formats
            const ids = Array.isArray(sourceIntelIds) ? sourceIntelIds :
                (sourceIntelIds ? [sourceIntelIds] : []);

            if (!intel || !intel.id) return false;

            const intelIdStr = String(intel.id);
            const intelIdNum = !isNaN(intel.id) ? parseInt(intel.id, 10) : null;

            // Direct ID match - check multiple formats
            if (ids.includes(intelIdStr) ||
                (intelIdNum !== null && ids.includes(intelIdNum)) ||
                ids.some(id => String(id) === intelIdStr || String(id) === String(intel.id))) {
                return true;
            }

            // Fuzzy match by title/content
            const intelTitle = (intel.title || '').toLowerCase().trim();
            const intelContent = (intel.content || intel.ai_summary || '').toLowerCase();
            const threatDesc = (threat.description || '').toLowerCase();
            const threatName = (threat.name || '').toLowerCase();

            // Check if threat description/name contains intel title (if title is meaningful)
            if (intelTitle && intelTitle.length > 5) {
                if (threatDesc.includes(intelTitle) || threatName.includes(intelTitle)) {
                    return true;
                }
            }

            // Check if threat description contains key terms from intel content
            if (intelContent && intelContent.length > 20) {
                const intelWords = intelContent.split(/\s+/).filter(w => w.length > 4).slice(0, 5);
                const matchingWords = intelWords.filter(word => threatDesc.includes(word) || threatName.includes(word));
                if (matchingWords.length >= 2) {
                    return true;
                }
            }

            return false;
        });

        if (relatedThreats.length > 0) {
            mapping.push({
                intel: intel,
                threats: relatedThreats
            });
        }
    });

    if (mapping.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No mappings found. Generate threats from intelligence to create mappings.</p>
            </div>
        `;
        return;
    }

    // Helper function to escape HTML
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Render table with improved layout
    let html = '<div class="mapping-table-wrapper">';
    html += `<div class="mapping-info">Showing ${mapping.length} mapped intelligence items</div>`;
    html += `
        <div class="mapping-table-container">
            <table class="mapping-table-content">
                <thead>
                    <tr>
                        <th style="min-width: 200px;">Intel Item</th>
                        <th style="min-width: 100px;">Source</th>
                        <th style="min-width: 250px;">Mapped Threats</th>
                        <th style="min-width: 120px;">STRIDE</th>
                        <th style="min-width: 150px;">Attack Surface</th>
                        <th style="min-width: 120px;">Attack Type</th>
                    </tr>
                </thead>
                <tbody>
    `;

    // Show all mappings
    mapping.forEach(item => {
        const intel = item.intel;
        const threats = item.threats;
        const title = (intel.title || 'Untitled').substring(0, 100);
        const snippet = (intel.ai_summary || intel.content || '').substring(0, 150);

        // Get unique categories from all threats
        const strideCategories = [...new Set(threats.map(t =>
            t.category || t.stride_category || 'N/A'
        ).filter(c => c !== 'N/A'))];
        const attackSurfaces = [...new Set(threats.map(t =>
            t.metadata?.attack_surface || t.schema_data?.attack_surface || null
        ).filter(s => s))];
        const attackTypes = [...new Set(threats.map(t =>
            t.metadata?.attack_type || t.schema_data?.attack_type || null
        ).filter(t => t))];

        html += `
            <tr>
                <td>
                    <div class="intel-title" title="${escapeHtml(intel.title || 'Untitled')}">${escapeHtml(title)}${intel.title && intel.title.length > 100 ? '...' : ''}</div>
                    <div class="intel-snippet" title="${escapeHtml(intel.ai_summary || intel.content || '')}">${escapeHtml(snippet)}${snippet.length >= 150 ? '...' : ''}</div>
                </td>
                <td>
                    ${intel.source_url ?
                `<a href="${intel.source_url}" target="_blank" class="source-link" title="${escapeHtml(intel.source_url)}">
                            ${escapeHtml(intel.source || intel.source_type || 'Unknown')}
                        </a>` :
                `<span class="source-text">${escapeHtml(intel.source || intel.source_type || 'Unknown')}</span>`
            }
                </td>
                <td>
                    <div class="threat-tags">
                        ${threats.slice(0, 5).map(t => {
                const threatName = (t.name || 'Unknown Threat').substring(0, 40);
                const riskScore = t.risk_score || 0;
                const riskClass = riskScore >= 8 ? 'high' : riskScore >= 5 ? 'medium' : 'low';
                return `<span class="threat-tag threat-tag-${riskClass}" title="${escapeHtml(t.name || 'Unknown Threat')} (Risk: ${riskScore}/10)">${escapeHtml(threatName)}${(t.name || '').length > 40 ? '...' : ''}</span>`;
            }).join('')}
                        ${threats.length > 5 ? `<span class="threat-tag threat-tag-more" title="${threats.length - 5} more threats">+${threats.length - 5}</span>` : ''}
                    </div>
                </td>
                <td>
                    ${strideCategories.length > 0 ? strideCategories.map(cat =>
                `<span class="stride-badge stride-${cat.toLowerCase().replace(/\s+/g, '-')}" title="${escapeHtml(cat)}">${escapeHtml(cat)}</span>`
            ).join(' ') : '<span class="text-muted">N/A</span>'}
                </td>
                <td>
                    ${attackSurfaces.length > 0 ? attackSurfaces.map(surface =>
                `<span class="attack-surface-label" title="${escapeHtml(surface)}">${escapeHtml(surface)}</span>`
            ).join(', ') : '<span class="text-muted">N/A</span>'}
                </td>
                <td>
                    ${attackTypes.length > 0 ? attackTypes.slice(0, 2).map(type =>
                `<span class="attack-type-label" title="${escapeHtml(type)}">${escapeHtml(type.length > 20 ? type.substring(0, 18) + '...' : type)}</span>`
            ).join(', ') + (attackTypes.length > 2 ? ` <span class="more-indicator">+${attackTypes.length - 2}</span>` : '') : '<span class="text-muted">N/A</span>'}
                </td>
            </tr>
        `;
    });

    html += '</tbody></table></div></div>';
    container.innerHTML = html;
}

/**
 * Initialize Threat Model Matrix tab
 */
function initThreatModelMatrixTab() {
    console.log('[ThreatModelMatrix] initThreatModelMatrixTab called');
    // Load data when tab is opened
    loadThreatModelMatrix();
}

// Export functions to window object immediately (before DOMContentLoaded)
// This ensures functions are available even if called during page load
if (typeof window !== 'undefined') {
    window.loadThreatModelMatrix = loadThreatModelMatrix;
    window.generateThreatModelFromIntel = generateThreatModelFromIntel;
    window.refreshThreatModelMatrix = refreshThreatModelMatrix;
    window.initThreatModelMatrixTab = initThreatModelMatrixTab;

    // Log that functions are exported
    console.log('[ThreatModelMatrix] Functions exported to window:', {
        loadThreatModelMatrix: typeof window.loadThreatModelMatrix,
        generateThreatModelFromIntel: typeof window.generateThreatModelFromIntel,
        refreshThreatModelMatrix: typeof window.refreshThreatModelMatrix,
        initThreatModelMatrixTab: typeof window.initThreatModelMatrixTab
    });
} else {
    console.error('[ThreatModelMatrix] window object not available');
}

