/**
 * MAESTRO Threat Analysis Frontend
 * 
 * Provides UI for MAESTRO seven-layer threat analysis
 */

(function() {
    'use strict';
    
    const API_BASE = window.API_BASE || 'http://localhost:6888/api';
    
    // State
    const MaestroState = {
        layers: [],
        currentLayer: null,
        layerAnalysis: {},
        crossLayerThreats: [],
        threats: []
    };
    
    /**
     * Initialize MAESTRO tab
     */
    function initMaestroTab() {
        loadMaestroLayers();
        loadThreats();
    }
    
    /**
     * Load all MAESTRO layers
     */
    async function loadMaestroLayers() {
        try {
            const response = await fetch(`${API_BASE}/maestro/layers`);
            if (!response.ok) throw new Error('Failed to load layers');
            
            const data = await response.json();
            MaestroState.layers = data.layers || [];
            
            renderLayersGrid();
        } catch (error) {
            console.error('Error loading MAESTRO layers:', error);
            showNotification('error', 'Error', 'Failed to load MAESTRO layers');
        }
    }
    
    /**
     * Render layers grid
     */
    function renderLayersGrid() {
        const container = document.getElementById('maestro-layers-grid');
        if (!container) return;
        
        if (MaestroState.layers.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No layers available</p></div>';
            return;
        }
        
        const html = MaestroState.layers.map(layer => {
            const threatCount = getLayerThreatCount(layer.number);
            const mitigatedCount = getLayerMitigatedCount(layer.number);
            const coverage = threatCount > 0 ? (mitigatedCount / threatCount * 100).toFixed(1) : 0;
            
            return `
                <div class="layer-card" onclick="selectMaestroLayer(${layer.number})">
                    <div class="layer-card-header">
                        <div class="layer-number">L${layer.number}</div>
                        <div class="layer-name">${layer.name}</div>
                    </div>
                    <div class="layer-card-body">
                        <p class="layer-description">${layer.description}</p>
                        <div class="layer-stats">
                            <div class="stat-item">
                                <span class="stat-label">Threats</span>
                                <span class="stat-value">${threatCount}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Mitigated</span>
                                <span class="stat-value">${mitigatedCount}</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Coverage</span>
                                <span class="stat-value">${coverage}%</span>
                            </div>
                        </div>
                    </div>
                    <div class="layer-card-footer">
                        <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); analyzeMaestroLayer(${layer.number})">
                            Analyze
                        </button>
                    </div>
                </div>
            `;
        }).join('');
        
        container.innerHTML = html;
    }
    
    /**
     * Get threat count for a layer
     */
    function getLayerThreatCount(layerNumber) {
        return MaestroState.threats.filter(t => 
            t.maestro_layer === layerNumber || 
            (t.affected_layers && t.affected_layers.includes(layerNumber))
        ).length;
    }
    
    /**
     * Get mitigated count for a layer
     */
    function getLayerMitigatedCount(layerNumber) {
        return MaestroState.threats.filter(t => 
            (t.maestro_layer === layerNumber || 
             (t.affected_layers && t.affected_layers.includes(layerNumber))) &&
            t.is_mitigated
        ).length;
    }
    
    /**
     * Select a layer
     */
    async function selectMaestroLayer(layerNumber) {
        MaestroState.currentLayer = layerNumber;
        
        // Update UI
        document.querySelectorAll('.layer-card').forEach(card => {
            card.classList.remove('active');
        });
        const card = document.querySelector(`.layer-card[onclick*="${layerNumber}"]`);
        if (card) card.classList.add('active');
        
        // Load layer analysis
        await analyzeMaestroLayer(layerNumber);
    }
    
    /**
     * Analyze a specific layer
     */
    async function analyzeMaestroLayer(layerNumber) {
        try {
            showNotification('info', 'Analyzing', `Analyzing Layer ${layerNumber}...`);
            
            const response = await fetch(`${API_BASE}/maestro/analyze-layer`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    layer_number: layerNumber,
                    project_id: 'default-project'
                })
            });
            
            if (!response.ok) throw new Error('Failed to analyze layer');
            
            const data = await response.json();
            MaestroState.layerAnalysis[layerNumber] = data.analysis;
            
            renderLayerAnalysis(data.analysis);
            showNotification('success', 'Complete', `Layer ${layerNumber} analysis complete`);
        } catch (error) {
            console.error('Error analyzing layer:', error);
            showNotification('error', 'Error', `Failed to analyze layer: ${error.message}`);
        }
    }
    
    /**
     * Render layer analysis
     */
    function renderLayerAnalysis(analysis) {
        const container = document.getElementById('maestro-layer-analysis');
        if (!container || !analysis) return;
        
        const stats = analysis.statistics || {};
        const threats = analysis.threats || [];
        
        const html = `
            <div class="layer-analysis-card">
                <div class="analysis-header">
                    <h4>${analysis.layer.name} (L${analysis.layer.number})</h4>
                    <div class="analysis-stats">
                        <div class="stat-box">
                            <div class="stat-value">${stats.total_threats || 0}</div>
                            <div class="stat-label">Total Threats</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">${stats.mitigated || 0}</div>
                            <div class="stat-label">Mitigated</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value">${(stats.coverage || 0).toFixed(1)}%</div>
                            <div class="stat-label">Coverage</div>
                        </div>
                    </div>
                </div>
                
                <div class="analysis-content">
                    <div class="threats-list">
                        <h5>Threats (${threats.length})</h5>
                        ${threats.length > 0 ? threats.map(threat => `
                            <div class="threat-item">
                                <div class="threat-header">
                                    <span class="threat-name">${threat.name || 'Unknown'}</span>
                                    <span class="threat-badge threat-badge-${(threat.risk_level || 'medium').toLowerCase()}">
                                        ${threat.risk_level || 'Medium'}
                                    </span>
                                </div>
                                <div class="threat-details">
                                    <span class="threat-category">${threat.stride_category || 'Unknown'}</span>
                                    <span class="threat-score">Risk: ${(threat.risk_score || 0).toFixed(1)}</span>
                                    ${threat.is_mitigated ? '<span class="threat-mitigated">✓ Mitigated</span>' : ''}
                                </div>
                            </div>
                        `).join('') : '<p class="empty-message">No threats found for this layer</p>'}
                    </div>
                    
                    <div class="risk-distribution">
                        <h5>Risk Distribution</h5>
                        <div class="risk-bars">
                            ${Object.entries(stats.by_risk_level || {}).map(([level, count]) => `
                                <div class="risk-bar-item">
                                    <span class="risk-label">${level}</span>
                                    <div class="risk-bar">
                                        <div class="risk-bar-fill risk-bar-${level}" 
                                             style="width: ${(count / stats.total_threats * 100) || 0}%"></div>
                                    </div>
                                    <span class="risk-count">${count}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        container.innerHTML = html;
    }
    
    /**
     * Analyze all layers
     */
    async function analyzeAllMaestroLayers() {
        try {
            showNotification('info', 'Analyzing', 'Analyzing all MAESTRO layers...');
            
            const response = await fetch(`${API_BASE}/maestro/analyze-all-layers`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ project_id: 'default-project' })
            });
            
            if (!response.ok) throw new Error('Failed to analyze layers');
            
            const data = await response.json();
            
            // Update layer analysis
            if (data.analysis && data.analysis.layers) {
                Object.entries(data.analysis.layers).forEach(([key, analysis]) => {
                    if (analysis && !analysis.error) {
                        MaestroState.layerAnalysis[analysis.layer.number] = analysis;
                    }
                });
            }
            
            // Re-render layers grid with updated stats
            renderLayersGrid();
            
            // Analyze cross-layer threats
            await analyzeCrossLayerThreats();
            
            showNotification('success', 'Complete', 'All layers analyzed successfully');
        } catch (error) {
            console.error('Error analyzing all layers:', error);
            showNotification('error', 'Error', `Failed to analyze layers: ${error.message}`);
        }
    }
    
    /**
     * Analyze cross-layer threats
     */
    async function analyzeCrossLayerThreats() {
        try {
            const response = await fetch(`${API_BASE}/maestro/analyze-cross-layer`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ project_id: 'default-project' })
            });
            
            if (!response.ok) throw new Error('Failed to analyze cross-layer threats');
            
            const data = await response.json();
            MaestroState.crossLayerThreats = data.analysis.cross_layer_threats || [];
            
            renderCrossLayerThreats(data.analysis);
        } catch (error) {
            console.error('Error analyzing cross-layer threats:', error);
        }
    }
    
    /**
     * Render cross-layer threats
     */
    function renderCrossLayerThreats(analysis) {
        const container = document.getElementById('maestro-cross-layer');
        if (!container) return;
        
        const threats = analysis.cross_layer_threats || [];
        
        if (threats.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No cross-layer threats identified</p></div>';
            return;
        }
        
        const html = `
            <div class="cross-layer-card">
                <div class="cross-layer-header">
                    <h4>Cross-Layer Threats (${threats.length})</h4>
                    <p>Threats that span multiple MAESTRO layers</p>
                </div>
                <div class="cross-layer-threats">
                    ${threats.map(threat => {
                        const threatData = threat.threat || {};
                        const layers = threat.affected_layers || [];
                        return `
                            <div class="cross-threat-item">
                                <div class="cross-threat-header">
                                    <span class="cross-threat-name">${threatData.name || 'Unknown'}</span>
                                    <span class="cross-threat-badge">Cross-Layer</span>
                                </div>
                                <div class="cross-threat-layers">
                                    <span class="layers-label">Affected Layers:</span>
                                    ${layers.map(l => `<span class="layer-badge">L${l}</span>`).join('')}
                                </div>
                                <div class="cross-threat-path">
                                    <span class="path-label">Attack Path:</span>
                                    <span class="path-text">${threat.attack_path || 'Unknown'}</span>
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
        
        container.innerHTML = html;
    }
    
    /**
     * Map existing threats to MAESTRO layers
     */
    async function mapExistingThreatsToMaestro() {
        try {
            showNotification('info', 'Mapping', 'Mapping threats to MAESTRO layers...');
            
            const response = await fetch(`${API_BASE}/maestro/map-existing-threats`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ project_id: 'default-project' })
            });
            
            if (!response.ok) throw new Error('Failed to map threats');
            
            const data = await response.json();
            
            // Reload threats
            await loadThreats();
            
            // Re-render
            renderLayersGrid();
            
            showNotification('success', 'Complete', `Mapped ${data.mapped_count || 0} threats to MAESTRO layers`);
        } catch (error) {
            console.error('Error mapping threats:', error);
            showNotification('error', 'Error', `Failed to map threats: ${error.message}`);
        }
    }
    
    /**
     * Load threats from API
     */
    async function loadThreats() {
        try {
            const response = await fetch(`${API_BASE}/threats?project_id=default-project`);
            if (!response.ok) throw new Error('Failed to load threats');
            
            const data = await response.json();
            MaestroState.threats = data.threats || [];
        } catch (error) {
            console.error('Error loading threats:', error);
            MaestroState.threats = [];
        }
    }
    
    /**
     * Show notification
     */
    function showNotification(type, title, message) {
        if (window.showNotification) {
            window.showNotification(type, title, message);
        } else {
            console.log(`[${type.toUpperCase()}] ${title}: ${message}`);
        }
    }
    
    // Export functions to window
    window.initMaestroTab = initMaestroTab;
    window.selectMaestroLayer = selectMaestroLayer;
    window.analyzeMaestroLayer = analyzeMaestroLayer;
    window.analyzeAllMaestroLayers = analyzeAllMaestroLayers;
    window.mapExistingThreatsToMaestro = mapExistingThreatsToMaestro;
    
})();

