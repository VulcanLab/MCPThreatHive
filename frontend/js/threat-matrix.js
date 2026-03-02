/**
 * Threat Matrix Visualization Component
 * 
 * Interactive threat matrix that shows:
 * - X-axis: STRIDE categories
 * - Y-axis: Assets/Components
 * - Cells: Threat risk levels and details
 * 
 * Features:
 * - Click cells to view threat details
 * - Link to threat cards, assets, and controls
 * - Assess intelligence data
 * - Export to threat model database
 */

// Get API_BASE from app.js or use default
function getApiBase() {
    if (typeof API_BASE !== 'undefined') {
        return API_BASE;
    }
    if (typeof window !== 'undefined' && window.API_BASE) {
        return window.API_BASE;
    }
    const port = window.location.port || '5000';
    const host = window.location.hostname || 'localhost';
    return `http://${host}:${port}/api`;
}

// ============== Threat Matrix State ==============
const ThreatMatrixState = {
    matrix: null,
    assets: [],
    threats: [],
    controls: [],
    selectedCell: null,
    hoveredCell: null
};

// ============== Threat Matrix API ==============

async function generateThreatMatrix(projectId = 'default-project', name = 'Threat Matrix') {
    try {
        const response = await fetch(`${getApiBase()}/threat-matrix/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_id: projectId, name })
        });
        
        if (!response.ok) throw new Error('Failed to generate matrix');
        
        const matrix = await response.json();
        ThreatMatrixState.matrix = matrix;
        return matrix;
    } catch (error) {
        console.error('Error generating threat matrix:', error);
        throw error;
    }
}

async function assessIntelligenceMatrix(intelItems, assets, name = 'Intelligence Assessment Matrix') {
    try {
        const response = await fetch(`${getApiBase()}/threat-matrix/assess-intel`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ intel_items: intelItems, assets, name })
        });
        
        if (!response.ok) throw new Error('Failed to assess intelligence');
        
        const matrix = await response.json();
        ThreatMatrixState.matrix = matrix;
        return matrix;
    } catch (error) {
        console.error('Error assessing intelligence matrix:', error);
        throw error;
    }
}

async function exportThreatMatrix(projectId = 'default-project') {
    try {
        const response = await fetch(`${getApiBase()}/threat-matrix/export`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_id: projectId })
        });
        
        if (!response.ok) throw new Error('Failed to export matrix');
        
        return await response.json();
    } catch (error) {
        console.error('Error exporting threat matrix:', error);
        throw error;
    }
}

// ============== Threat Matrix Rendering ==============

function renderThreatMatrix(containerId = 'threat-matrix-container') {
    const container = document.getElementById(containerId);
    if (!container) {
        console.error('Threat matrix container not found');
        return;
    }
    
    // Check if we have data
    const hasAssets = (AppState.assets && AppState.assets.length > 0) || (ThreatMatrixState.assets && ThreatMatrixState.assets.length > 0);
    const hasThreats = (AppState.threats && AppState.threats.length > 0) || (ThreatMatrixState.threats && ThreatMatrixState.threats.length > 0);
    
    if (!ThreatMatrixState.matrix) {
        if (!hasAssets && !hasThreats) {
            container.innerHTML = `
                <div style="padding: 60px 40px; text-align: center; color: var(--text-muted);">
                    <div style="font-size: 4rem; margin-bottom: 16px;">📊</div>
                    <h3 style="color: var(--text-primary); margin-bottom: 12px;">No Threat Matrix Data</h3>
                    <p style="margin-bottom: 24px; line-height: 1.6;">
                        To generate a threat matrix, you need at least one asset and one threat.<br>
                        Import MCP knowledge base or create threats and assets first.
                    </p>
                    <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
                        <button class="btn btn-primary" onclick="importMCPKnowledgeBase()">📥 Import MCP Knowledge Base</button>
                        <button class="btn btn-secondary" onclick="switchTab('canvas')">➕ Create Threats & Assets</button>
                        <button class="btn btn-secondary" onclick="generateThreatMatrix().then(() => renderThreatMatrix())">🔄 Try Generate</button>
                    </div>
                </div>
            `;
        } else if (!hasAssets) {
            container.innerHTML = `
                <div style="padding: 60px 40px; text-align: center; color: var(--text-muted);">
                    <div style="font-size: 4rem; margin-bottom: 16px;">🖥️</div>
                    <h3 style="color: var(--text-primary); margin-bottom: 12px;">No Assets Found</h3>
                    <p style="margin-bottom: 24px; line-height: 1.6;">
                        Threat matrix requires at least one asset to display.<br>
                        Create assets on the canvas or import MCP knowledge base.
                    </p>
                    <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
                        <button class="btn btn-primary" onclick="switchTab('canvas')">➕ Create Assets</button>
                        <button class="btn btn-secondary" onclick="importMCPKnowledgeBase()">📥 Import MCP Knowledge Base</button>
                    </div>
                </div>
            `;
        } else if (!hasThreats) {
            container.innerHTML = `
                <div style="padding: 60px 40px; text-align: center; color: var(--text-muted);">
                    <div style="font-size: 4rem; margin-bottom: 16px;">⚠️</div>
                    <h3 style="color: var(--text-primary); margin-bottom: 12px;">No Threats Found</h3>
                    <p style="margin-bottom: 24px; line-height: 1.6;">
                        Threat matrix requires at least one threat to display.<br>
                        Create threats on the canvas, gather intelligence, or import MCP knowledge base.
                    </p>
                    <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
                        <button class="btn btn-primary" onclick="importMCPKnowledgeBase()">📥 Import MCP Knowledge Base</button>
                        <button class="btn btn-secondary" onclick="gatherIntel()">📡 Gather Intel</button>
                        <button class="btn btn-secondary" onclick="switchTab('canvas')">➕ Create Threats</button>
                    </div>
                </div>
            `;
        } else {
        container.innerHTML = '<p style="color: var(--text-muted); padding: 40px; text-align: center;">No threat matrix data available. Click "Regenerate" to create a matrix.</p>';
        }
        return;
    }
    
    const matrix = ThreatMatrixState.matrix;
    if (!matrix) {
        container.innerHTML = '<p style="color: var(--text-muted); padding: 40px; text-align: center;">No threat matrix data available. Click "Load Default" to load the default MCP threat matrix.</p>';
        return;
    }
    
    const strideCategories = matrix.stride_categories || [];
    const assets = matrix.assets || [];
    const cells = matrix.cells || {};
    
    // Debug logging
    console.log('Rendering matrix:', {
        assets: assets.length,
        strideCategories: strideCategories.length,
        cells: Object.keys(cells).length,
        matrixName: matrix.name
    });
    
    // Check if matrix is empty
    if (assets.length === 0) {
        container.innerHTML = `
            <div style="padding: 60px 40px; text-align: center; color: var(--text-muted);">
                <div style="font-size: 4rem; margin-bottom: 16px;">🖥️</div>
                <h3 style="color: var(--text-primary); margin-bottom: 12px;">No Assets in Matrix</h3>
                <p style="margin-bottom: 24px;">The threat matrix was generated but contains no assets.</p>
                <button class="btn btn-primary" onclick="loadDefaultThreatMatrix()">📋 Load Default</button>
            </div>
        `;
        return;
    }
    
    // Sync assets from AppState
    ThreatMatrixState.assets = AppState.assets || [];
    ThreatMatrixState.threats = AppState.threats || [];
    ThreatMatrixState.controls = AppState.controls || [];
    
    // Create matrix table
    let html = `
        <div class="threat-matrix-wrapper">
            <div class="threat-matrix-header">
                <h3>${matrix.name || 'Threat Matrix'}</h3>
                <div class="threat-matrix-stats">
                    <span>Threats: ${matrix.stats?.threats_found || 0}</span>
                    <span>Mitigated: ${matrix.stats?.mitigated || 0}</span>
                    <span>Coverage: ${(matrix.stats?.coverage || 0).toFixed(1)}%</span>
                </div>
            </div>
            
            <div class="threat-matrix-table-container">
                <table class="threat-matrix-table">
                    <thead>
                        <tr>
                            <th class="matrix-corner">Asset / STRIDE</th>
                            ${strideCategories.map(cat => `<th class="stride-header">${cat}</th>`).join('')}
                        </tr>
                    </thead>
                    <tbody>
    `;
    
    // Render rows (assets)
    for (const assetId of assets) {
        const asset = ThreatMatrixState.assets.find(a => a && a.id === assetId);
        const assetName = asset && asset.name ? asset.name : assetId;
        const safeAssetId = assetId || 'unknown';
        html += `<tr>`;
        html += `<td class="asset-header" data-asset-id="${safeAssetId}">${assetName}</td>`;
        
        // Render cells for each STRIDE category
        for (const strideCategory of strideCategories) {
            // Get cell data - handle both direct access and nested structure
            let cell = null;
            if (cells[assetId]) {
                cell = cells[assetId][strideCategory] || null;
            }
            
            const cellClass = getCellClass(cell);
            const cellTitle = getCellTitle(cell);
            
            // Escape quotes for onclick
            const safeAssetIdEscaped = String(assetId).replace(/'/g, "\\'");
            const safeStride = String(strideCategory).replace(/'/g, "\\'");
            
            html += `
                <td class="threat-cell ${cellClass}" 
                    data-asset-id="${safeAssetIdEscaped}" 
                    data-stride="${safeStride}"
                    title="${cellTitle.replace(/"/g, '&quot;')}"
                    onclick="selectThreatCell('${safeAssetIdEscaped}', '${safeStride}')"
                    onmouseenter="hoverThreatCell('${safeAssetIdEscaped}', '${safeStride}')"
                    onmouseleave="unhoverThreatCell()"
                    oncontextmenu="event.preventDefault(); openAddThreatModal('${safeAssetIdEscaped}', '${safeStride}')">
                    ${renderCellContent(cell)}
                    ${!cell || !cell.threat_id ? '<div class="cell-add-hint" title="Right-click to add threat">+</div>' : ''}
                </td>
            `;
        }
        
        html += `</tr>`;
    }
    
    html += `
                    </tbody>
                </table>
            </div>
            
            <div class="threat-matrix-legend">
                <div class="legend-item"><span class="legend-color critical"></span> Critical (9.0+)</div>
                <div class="legend-item"><span class="legend-color high"></span> High (7.0-8.9)</div>
                <div class="legend-item"><span class="legend-color medium"></span> Medium (5.0-6.9)</div>
                <div class="legend-item"><span class="legend-color low"></span> Low (3.0-4.9)</div>
                <div class="legend-item"><span class="legend-color none"></span> None (<3.0)</div>
                <div class="legend-item"><span class="legend-color mitigated"></span> Mitigated</div>
            </div>
        </div>
    `;
    
    container.innerHTML = html;
    
    // If matrix is empty (no threats), show helpful message
    const hasThreatsInMatrix = Object.values(cells).some(assetDict => 
        Object.values(assetDict).some(cell => cell && cell.threat_id)
    );
    
    if (!hasThreatsInMatrix && assets.length > 0) {
        const emptyMessage = document.createElement('div');
        emptyMessage.style.cssText = 'padding: 20px; margin-top: 20px; background: var(--bg-tertiary); border-radius: 8px; text-align: center; color: var(--text-secondary);';
        emptyMessage.innerHTML = `
            <p style="margin-bottom: 12px;">⚠️ Matrix generated but no threats mapped to assets yet.</p>
            <div style="display: flex; gap: 8px; justify-content: center; flex-wrap: wrap;">
                <button class="btn btn-sm btn-primary" onclick="importMCPKnowledgeBase()">📥 Import MCP Knowledge Base</button>
                <button class="btn btn-sm btn-secondary" onclick="gatherIntel()">📡 Gather Intel</button>
                <button class="btn btn-sm btn-secondary" onclick="switchTab('canvas')">➕ Create Threats</button>
            </div>
        `;
        container.appendChild(emptyMessage);
    }
}

function getCellClass(cell) {
    if (!cell || !cell.threat_id) return 'no-threat';
    
    // Handle both string and object risk_level
    let riskLevel = 'none';
    if (typeof cell.risk_level === 'string') {
        riskLevel = cell.risk_level;
    } else if (cell.risk_level && typeof cell.risk_level === 'object' && cell.risk_level.value) {
        riskLevel = cell.risk_level.value;
    } else {
        riskLevel = cell.risk_level || 'none';
    }
    
    const mitigated = cell.is_mitigated ? 'mitigated' : '';
    
    return `${riskLevel} ${mitigated}`.trim();
}

function getCellTitle(cell) {
    if (!cell || !cell.threat_id) return 'No threat';
    
    const threatName = cell.threat_name || 'Unknown Threat';
    const riskScore = cell.risk_score || 0;
    const mitigated = cell.is_mitigated ? 'Mitigated' : 'Unmitigated';
    
    return `${threatName}\nRisk: ${riskScore.toFixed(1)}\n${mitigated}`;
}

function renderCellContent(cell) {
    if (!cell || !cell.threat_id) return '';
    
    const riskScore = cell.risk_score || 0;
    const mitigated = cell.is_mitigated ? '✓' : '';
    
    return `
        <div class="cell-content">
            <div class="cell-risk">${riskScore.toFixed(1)}</div>
            ${mitigated ? '<div class="cell-mitigated">✓</div>' : ''}
        </div>
    `;
}

// ============== Cell Interaction ==============

function selectThreatCell(assetId, strideCategory) {
    const matrix = ThreatMatrixState.matrix;
    if (!matrix) return;
    
    const cell = matrix.cells[assetId]?.[strideCategory];
    ThreatMatrixState.selectedCell = { assetId, strideCategory, cell };
    
    // Show threat details in right panel
    if (cell && cell.threat_id) {
        showThreatDetails(cell);
    }
    
    // Highlight cell
    document.querySelectorAll('.threat-cell').forEach(c => c.classList.remove('selected'));
    const cellElement = document.querySelector(
        `.threat-cell[data-asset-id="${assetId}"][data-stride="${strideCategory}"]`
    );
    if (cellElement) {
        cellElement.classList.add('selected');
    }
}

function hoverThreatCell(assetId, strideCategory) {
    ThreatMatrixState.hoveredCell = { assetId, strideCategory };
    
    // Highlight row and column
    document.querySelectorAll('.threat-cell').forEach(c => c.classList.remove('hover'));
    document.querySelectorAll(`.threat-cell[data-asset-id="${assetId}"]`).forEach(c => c.classList.add('hover'));
    document.querySelectorAll(`.threat-cell[data-stride="${strideCategory}"]`).forEach(c => c.classList.add('hover'));
}

function unhoverThreatCell() {
    ThreatMatrixState.hoveredCell = null;
    document.querySelectorAll('.threat-cell').forEach(c => c.classList.remove('hover'));
}

function showThreatDetails(cell) {
    // Find threat in threats list
    const threat = ThreatMatrixState.threats.find(t => t.id === cell.threat_id);
    if (!threat) return;
    
    // Update right panel with threat details
    const rightPanel = document.getElementById('right-panel');
    if (rightPanel) {
        rightPanel.innerHTML = `
            <div class="panel-header">
                <h3>Threat Details</h3>
                <button onclick="closeRightPanel()">×</button>
            </div>
            <div class="panel-content">
                <h4>${threat.name || cell.threat_name}</h4>
                <p><strong>STRIDE:</strong> ${cell.stride_category || threat.category}</p>
                <p><strong>Risk Score:</strong> ${cell.risk_score.toFixed(1)}</p>
                <p><strong>Risk Level:</strong> ${cell.risk_level}</p>
                <p><strong>Status:</strong> ${cell.is_mitigated ? 'Mitigated ✓' : 'Unmitigated ⚠️'}</p>
                ${threat.description ? `<p><strong>Description:</strong> ${threat.description}</p>` : ''}
                ${cell.control_ids.length > 0 ? `
                    <div class="controls-list">
                        <strong>Controls:</strong>
                        <ul>
                            ${cell.control_ids.map(id => {
                                const control = ThreatMatrixState.controls.find(c => c.id === id);
                                return `<li>${control ? control.name : id}</li>`;
                            }).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
        rightPanel.classList.add('open');
    }
}

// ============== Integration with Canvas ==============

function linkMatrixToCanvas() {
    // When a threat is selected in the matrix, highlight it on the canvas
    if (ThreatMatrixState.selectedCell && ThreatMatrixState.selectedCell.cell) {
        const threatId = ThreatMatrixState.selectedCell.cell.threat_id;
        
        // Find threat node on canvas
        const threatNode = AppState.canvas.nodes.get(threatId);
        if (threatNode) {
            // Select node on canvas
            selectNode(threatId);
            
            // Center canvas on node
            centerCanvasOnNode(threatId);
        }
    }
}

function linkCanvasToMatrix() {
    // When a threat is selected on canvas, highlight it in the matrix
    if (AppState.canvas.selectedNode) {
        const node = AppState.canvas.nodes.get(AppState.canvas.selectedNode);
        if (node && node.type === 'threat') {
            // Find threat in matrix
            const matrix = ThreatMatrixState.matrix;
            if (matrix) {
                // Search for threat in matrix cells
                for (const [assetId, strideDict] of Object.entries(matrix.cells)) {
                    for (const [strideCategory, cell] of Object.entries(strideDict)) {
                        if (cell.threat_id === node.id) {
                            selectThreatCell(assetId, strideCategory);
                            return;
                        }
                    }
                }
            }
        }
    }
}

// ============== Export Functions ==============

async function exportMatrixToThreatModel(projectId = 'default-project') {
    try {
        const result = await exportThreatMatrix(projectId);
        
        // Show success message
        alert(`Exported ${result.count} threat models from matrix`);
        
        // Optionally reload threats
        await loadThreats();
        
        return result;
    } catch (error) {
        console.error('Error exporting matrix:', error);
        alert('Failed to export threat matrix');
    }
}

// ============== Initialize Threat Matrix Tab ==============

function initThreatMatrixTab() {
    // Sync with AppState
    ThreatMatrixState.assets = AppState.assets || [];
    ThreatMatrixState.threats = AppState.threats || [];
    ThreatMatrixState.controls = AppState.controls || [];
    
    // Check if we have data before generating
    const hasAssets = (AppState.assets && AppState.assets.length > 0);
    const hasThreats = (AppState.threats && AppState.threats.length > 0);
    
    if (!hasAssets || !hasThreats) {
        // Try to load default matrix automatically
        loadDefaultThreatMatrix().catch(() => {
            // If default load fails, show empty state
            renderThreatMatrix();
        });
        return;
    }
    
    // Generate and render matrix
    generateThreatMatrix().then(() => {
        renderThreatMatrix();
    }).catch(error => {
        console.error('Error initializing threat matrix:', error);
        // Try to load default as fallback
        loadDefaultThreatMatrix().catch(() => {
        const container = document.getElementById('threat-matrix-container');
        if (container) {
                container.innerHTML = `
                    <div style="padding: 40px; text-align: center; color: var(--text-muted);">
                        <div style="font-size: 3rem; margin-bottom: 16px;">⚠️</div>
                        <h3 style="color: var(--text-primary); margin-bottom: 12px;">Error Loading Threat Matrix</h3>
                        <p style="margin-bottom: 16px;">${error.message}</p>
                        <button class="btn btn-primary" onclick="loadDefaultThreatMatrix()">📋 Load Default</button>
                    </div>
                `;
            }
        });
    });
}

// ============== JSON Import/Export ==============

async function exportThreatMatrixJSON() {
    try {
        const response = await fetch(`${getApiBase()}/threat-matrix/export-json`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                project_id: 'default-project',
                name: ThreatMatrixState.matrix?.name || 'Threat Matrix'
            })
        });
        
        if (!response.ok) throw new Error('Failed to export matrix');
        
        const data = await response.json();
        
        // Create download
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat-matrix-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showNotification('success', 'Export Success', 'Threat matrix exported as JSON');
    } catch (error) {
        console.error('Error exporting matrix:', error);
        showNotification('error', 'Export Error', `Failed to export matrix: ${error.message}`);
    }
}

async function importThreatMatrixJSON(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch(`${getApiBase()}/threat-matrix/import-json`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Import failed');
        }
        
        const result = await response.json();
        
        // Reload data and regenerate matrix
        if (typeof loadInitialData === 'function') {
            await loadInitialData();
        } else if (typeof window.loadInitialData === 'function') {
            await window.loadInitialData();
        }
        
        await generateThreatMatrix();
        renderThreatMatrix();
        
        showNotification('success', 'Import Success', 
            `Imported ${result.imported.threats} threats, ${result.imported.assets} assets`);
        
        // Reset file input
        event.target.value = '';
    } catch (error) {
        console.error('Error importing matrix:', error);
        showNotification('error', 'Import Error', `Failed to import matrix: ${error.message}`);
        event.target.value = '';
    }
}

async function loadDefaultThreatMatrix() {
    try {
        showNotification('info', 'Loading', 'Loading default MCP threat matrix...');
        
        const response = await fetch(`${getApiBase()}/threat-matrix/load-default`);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to load default matrix');
        }
        
        const result = await response.json();
        
        // Update matrix state immediately
        ThreatMatrixState.matrix = result.matrix;
        
        // Import the data into database (async, don't wait)
        if (result.matrix && result.matrix.assets && result.matrix.assets.length > 0) {
            importMatrixDataToDatabase(result).catch(err => {
                console.warn('Failed to import to database:', err);
            });
        }
        
        // Render matrix immediately with loaded data
        renderThreatMatrix();
        
        showNotification('success', 'Loaded', 'Default MCP threat matrix loaded successfully');
    } catch (error) {
        console.error('Error loading default matrix:', error);
        showNotification('error', 'Load Error', `Failed to load default matrix: ${error.message}`);
    }
}

async function importMatrixDataToDatabase(data) {
    try {
        // Import via the import-json endpoint logic
        // We'll create a FormData with the JSON content
        const jsonBlob = new Blob([JSON.stringify(data)], { type: 'application/json' });
        const formData = new FormData();
        const file = new File([jsonBlob], 'mcp_threat_matrix.json', { type: 'application/json' });
        formData.append('file', file);
        
        const response = await fetch(`${getApiBase()}/threat-matrix/import-json`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const error = await response.json();
            console.warn('Failed to import matrix data:', error);
        }
    } catch (error) {
        console.warn('Error importing matrix data:', error);
    }
}

async function downloadThreatMatrixTemplate() {
    try {
        const response = await fetch(`${getApiBase()}/threat-matrix/template`);
        
        if (!response.ok) {
            throw new Error('Failed to download template');
        }
        
        const template = await response.json();
        
        // Create download
        const blob = new Blob([JSON.stringify(template, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'threat-matrix-template.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showNotification('success', 'Downloaded', 'Threat matrix template downloaded');
    } catch (error) {
        console.error('Error downloading template:', error);
        showNotification('error', 'Download Error', `Failed to download template: ${error.message}`);
    }
}

async function importMCPThreatsToMatrix() {
    try {
        showNotification('info', 'Importing', 'Importing MCP threats into threat matrix...');
        
        const response = await fetch(`${getApiBase()}/threat-matrix/import-mcp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                project_id: 'default-project',
                name: 'MCP Threat Matrix'
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Import failed');
        }
        
        const result = await response.json();
        
        // Update matrix state
        ThreatMatrixState.matrix = result.matrix;
        
        // Reload data
        if (typeof loadInitialData === 'function') {
            await loadInitialData();
        } else if (typeof window.loadInitialData === 'function') {
            await window.loadInitialData();
        }
        
        // Render matrix
        renderThreatMatrix();
        
        showNotification('success', 'Import Success', result.message);
    } catch (error) {
        console.error('Error importing MCP threats:', error);
        showNotification('error', 'Import Error', `Failed to import MCP threats: ${error.message}`);
    }
}

// ============== Add Threat from Cell ==============

function openAddThreatModal(assetId, strideCategory) {
    // Create modal for adding threat to this cell
    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.id = 'add-threat-modal';
    modal.innerHTML = `
        <div class="modal" style="max-width: 600px;">
            <div class="modal-header">
                <span class="modal-title">➕ Add Threat to Matrix</span>
                <button class="modal-close" onclick="closeModal('add-threat-modal')">×</button>
            </div>
            <div class="modal-body">
                <form id="add-threat-form" onsubmit="addThreatToMatrix(event, '${assetId}', '${strideCategory}')">
                    <div class="form-group">
                        <label>Asset</label>
                        <input type="text" value="${assetId}" disabled class="form-control">
                    </div>
                    <div class="form-group">
                        <label>STRIDE Category</label>
                        <input type="text" value="${strideCategory}" disabled class="form-control">
                    </div>
                    <div class="form-group">
                        <label>Threat Name *</label>
                        <input type="text" name="threat_name" required class="form-control" placeholder="Enter threat name">
                    </div>
                    <div class="form-group">
                        <label>Description</label>
                        <textarea name="description" class="form-control" rows="3" placeholder="Enter threat description"></textarea>
                    </div>
                    <div class="form-group">
                        <label>Risk Score (0-10)</label>
                        <input type="number" name="risk_score" min="0" max="10" step="0.1" value="5.0" class="form-control">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" onclick="closeModal('add-threat-modal')">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Threat</button>
                    </div>
                </form>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function addThreatToMatrix(event, assetId, strideCategory) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    
    const threatData = {
        name: formData.get('threat_name'),
        description: formData.get('description') || '',
        threat_type: 'Security',
        stride_category: strideCategory,
        risk_score: parseFloat(formData.get('risk_score')) || 5.0,
        affected_assets: [assetId]
    };
    
    try {
        // Create threat via API
        const response = await fetch(`${getApiBase()}/threats`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                project_id: 'default-project',
                ...threatData
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create threat');
        }
        
        const result = await response.json();
        
        // Reload data and regenerate matrix
        if (typeof loadInitialData === 'function') {
            await loadInitialData();
        } else if (typeof window.loadInitialData === 'function') {
            await window.loadInitialData();
        }
        
        await generateThreatMatrix();
        renderThreatMatrix();
        
        closeModal('add-threat-modal');
        showNotification('success', 'Threat Added', `Threat "${threatData.name}" added to matrix`);
    } catch (error) {
        console.error('Error adding threat:', error);
        showNotification('error', 'Error', `Failed to add threat: ${error.message}`);
    }
}

// Make functions globally available
// Use IIFE to ensure functions are available immediately
(function() {
    'use strict';
    if (typeof window !== 'undefined') {
window.generateThreatMatrix = generateThreatMatrix;
window.assessIntelligenceMatrix = assessIntelligenceMatrix;
window.exportThreatMatrix = exportThreatMatrix;
        window.exportThreatMatrixJSON = exportThreatMatrixJSON;
        window.importThreatMatrixJSON = importThreatMatrixJSON;
        window.loadDefaultThreatMatrix = loadDefaultThreatMatrix;
window.downloadThreatMatrixTemplate = downloadThreatMatrixTemplate;
window.importMCPThreatsToMatrix = importMCPThreatsToMatrix;
window.exportMatrixToThreatModel = exportMatrixToThreatModel;
window.selectThreatCell = selectThreatCell;
window.hoverThreatCell = hoverThreatCell;
window.unhoverThreatCell = unhoverThreatCell;
window.renderThreatMatrix = renderThreatMatrix;
window.initThreatMatrixTab = initThreatMatrixTab;
        window.openAddThreatModal = openAddThreatModal;
        window.addThreatToMatrix = addThreatToMatrix;
    }
})();

