/**
 * MCP Threat Platform - Main Application
 * Drag-and-drop threat modeling canvas
 */

// ============== API Configuration ==============
const API_BASE = (() => {
    const port = window.location.port || '5000';
    const host = window.location.hostname || 'localhost';
    const protocol = window.location.protocol || 'http:';
    return `${protocol}//${host}:${port}/api`;
})();

// ============== State Management ==============
const AppState = {
    // Current tab
    activeTab: 'canvas',

    // Canvas state
    canvas: {
        nodes: new Map(),
        connections: [],
        selectedNode: null,
        zoom: 1,
        pan: { x: 0, y: 0 },
        isDragging: false,
        isConnecting: false,
        connectStart: null
    },

    // Data
    assets: [],
    threats: [],
    controls: [],
    evidence: [],
    dataFlows: [],

    // UI state
    rightPanelOpen: false,  // Default collapsed to give more canvas space
    leftPanelCollapsed: {},

    // Loading states
    loading: {
        intel: false,
        attack: false,
        report: false
    },

    // Background tasks - track running tasks across page switches
    backgroundTasks: new Map()  // taskId -> { type, status, startTime, promise }
};

// ============== Initialization ==============
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

async function initializeApp() {
    console.log('🚀 Initializing MCP Threat Platform...');

    // Setup event listeners
    setupNavigation();
    setupCanvasEvents();
    setupDragAndDrop();
    setupPanelEvents();
    setupKeyboardShortcuts();
    setupRightPanelExpandButton();

    // Load initial data
    await loadInitialData();

    // Initialize canvas
    initializeCanvas();

    // Auto-load last saved canvas state
    await autoLoadLastCanvas();

    // Setup auto-save on changes
    setupCanvasAutoSave();

    console.log('✅ Platform initialized');
    showNotification('success', 'Platform Ready', 'MCP Threat Platform loaded successfully');
}

// Auto-load the most recently updated canvas on startup
async function autoLoadLastCanvas() {
    try {
        const listRes = await fetch(`${API_BASE}/canvas/list?project_id=default-project`);
        if (!listRes.ok) return;

        const listData = await listRes.json();
        const canvases = listData.canvases || [];

        if (canvases.length === 0) {
            console.log('No saved canvases to auto-load');
            return;
        }

        // Sort by updated_at to get the most recent
        canvases.sort((a, b) => {
            const dateA = a.updated_at ? new Date(a.updated_at) : new Date(0);
            const dateB = b.updated_at ? new Date(b.updated_at) : new Date(0);
            return dateB - dateA;
        });

        const latestCanvas = canvases[0];
        console.log(`Auto-loading canvas: ${latestCanvas.name}`);

        const loadRes = await fetch(`${API_BASE}/canvas/load?id=${encodeURIComponent(latestCanvas.name)}&project_id=default-project`);
        if (loadRes.ok) {
            const loadData = await loadRes.json();
            if (loadData.state) {
                restoreCanvasState(loadData.state);
                console.log(`Canvas "${latestCanvas.name}" auto-loaded (${loadData.state.nodes?.length || 0} nodes, ${loadData.state.connections?.length || 0} connections)`);
            }
        }
    } catch (err) {
        console.warn('Failed to auto-load canvas:', err);
    }
}

// Setup auto-save when canvas changes
let autoSaveTimeout = null;
function setupCanvasAutoSave() {
    // Debounced auto-save function
    const triggerAutoSave = () => {
        if (autoSaveTimeout) {
            clearTimeout(autoSaveTimeout);
        }
        autoSaveTimeout = setTimeout(async () => {
            // Only auto-save if there are nodes
            if (AppState.canvas.nodes.size > 0) {
                try {
                    // Get existing canvases
                    const listRes = await fetch(`${API_BASE}/canvas/list?project_id=default-project`);
                    if (listRes.ok) {
                        const listData = await listRes.json();
                        const canvases = listData.canvases || [];

                        // Use existing canvas name or 'auto-save'
                        const canvasName = canvases.length > 0 ? canvases[0].name : 'auto-save';

                        // Prepare save data
                        const nodesArray = Array.from(AppState.canvas.nodes.entries()).map(([id, nodeData]) => [
                            id,
                            {
                                id: id,
                                data: nodeData.data,
                                position: nodeData.position || { x: 0, y: 0 }
                            }
                        ]);

                        const connectionsArray = AppState.canvas.connections.map(conn => ({
                            id: conn.id || `conn-${Date.now()}-${Math.random()}`,
                            source: conn.source,
                            target: conn.target,
                            sourceConnector: conn.sourceConnector || 'right',
                            targetConnector: conn.targetConnector || 'left'
                        }));

                        const canvasState = {
                            nodes: nodesArray,
                            connections: connectionsArray,
                            viewport: {
                                zoom: AppState.canvas.zoom,
                                pan: AppState.canvas.pan
                            }
                        };

                        // Silent auto-save
                        await fetch(`${API_BASE}/canvas/save`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                id: canvasName,
                                state: canvasState,
                                project_id: 'default-project'
                            })
                        });

                        console.log(`[AutoSave] Canvas saved: ${nodesArray.length} nodes, ${connectionsArray.length} connections`);
                    }
                } catch (err) {
                    console.warn('[AutoSave] Failed:', err);
                }
            }
        }, 3000); // 3 second delay for debouncing
    };

    // Hook into canvas modifications
    const originalSetNode = AppState.canvas.nodes.set.bind(AppState.canvas.nodes);
    AppState.canvas.nodes.set = function (key, value) {
        const result = originalSetNode(key, value);
        triggerAutoSave();
        return result;
    };

    const originalDeleteNode = AppState.canvas.nodes.delete.bind(AppState.canvas.nodes);
    AppState.canvas.nodes.delete = function (key) {
        const result = originalDeleteNode(key);
        triggerAutoSave();
        return result;
    };

    // Track connection changes
    const originalPush = Array.prototype.push;
    Object.defineProperty(AppState.canvas, 'connections', {
        set: function (value) {
            this._connections = value;
            triggerAutoSave();
        },
        get: function () {
            return this._connections || [];
        }
    });
    AppState.canvas._connections = AppState.canvas.connections || [];
}

// ============== Navigation ==============
function setupNavigation() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            // Use currentTarget to get the button element, not the clicked child
            const button = e.currentTarget || e.target.closest('.nav-tab');
            const tabId = button?.dataset?.tab || button?.getAttribute('data-tab');
            console.log('Tab clicked:', tabId, button);
            if (tabId) {
                switchTab(tabId);
            } else {
                console.error('No tabId found for button:', button);
            }
        });
    });

    // Also add direct onclick handlers as fallback
    document.querySelectorAll('.nav-tab').forEach(tab => {
        const tabId = tab.dataset.tab || tab.getAttribute('data-tab');
        if (tabId) {
            tab.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                switchTab(tabId);
            };
        }
    });
}

function switchTab(tabId) {
    if (!tabId) {
        console.warn('switchTab called with no tabId');
        return;
    }

    console.log('Switching to tab:', tabId);

    // Update nav tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        const tabDataId = tab.dataset.tab || tab.getAttribute('data-tab');
        const isActive = tabDataId === tabId;
        if (isActive) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });

    // Update content - hide all tabs first, then show the active one
    document.querySelectorAll('.tab-content').forEach(content => {
        const contentId = content.id;
        const expectedId = `${tabId}-tab`;
        const isActive = contentId === expectedId;

        if (isActive) {
            content.classList.add('active');
            content.style.display = 'flex';
        } else {
            content.classList.remove('active');
            content.style.display = 'none';
        }
    });

    AppState.activeTab = tabId;

    // Check for completed background tasks and show notifications
    checkBackgroundTasks();

    // Tab-specific initialization
    if (tabId === 'kg') {
        loadIntelKG();
    } else if (tabId === 'intel') {
        if (typeof loadIntelItems === 'function') {
            loadIntelItems();
        } else if (typeof window.loadIntelItems === 'function') {
            window.loadIntelItems();
        } else {
            console.error('loadIntelItems function not available');
        }
    } else if (tabId === 'threat-model-matrix') {
        // Auto-load Threat Model Matrix
        if (typeof window.loadThreatModelMatrix === 'function') {
            window.loadThreatModelMatrix();
        } else {
            // Try again after a short delay in case script is still loading
            setTimeout(() => {
                if (typeof window.loadThreatModelMatrix === 'function') {
                    window.loadThreatModelMatrix();
                }
            }, 100);
        }
    } else if (tabId === 'threat-landscape') {
        // Auto-initialize 3D Landscape when switching to tab
        if (typeof ThreatLandscape !== 'undefined') {
            if (ThreatLandscape.isInitialized && ThreatLandscape.isInitialized()) {
                // Already initialized, force resize to adapt to current screen size
                console.log('[3D Landscape] Already initialized, forcing resize...');
                ThreatLandscape.forceResize();
            } else {
                // Initialize for first time
                if (typeof initThreatLandscape === 'function') {
                    console.log('[3D Landscape] Auto-initializing...');
                    initThreatLandscape();
                }
            }
        }
    }
}

// Check background tasks and show notifications for completed ones
function checkBackgroundTasks() {
    AppState.backgroundTasks.forEach((task, taskId) => {
        if (task.status === 'completed' && task.result) {
            // Task completed - show notification based on type
            if (task.type === 'threat-generation') {
                const threatsCount = task.result.stats?.threats_count || task.result.threats_count || 0;
                showNotification('success', 'Threat Generation Complete',
                    `Generated ${threatsCount} threats from intelligence. Refresh the Threat Model Matrix to see them.`);
            } else if (task.type === 'intel-gathering') {
                const collected = task.result.items_collected || 0;
                showNotification('success', 'Intel Gathering Complete',
                    `Collected ${collected} intelligence items.`);
            }
        } else if (task.status === 'failed' && task.error) {
            // Task failed - show notification
            showNotification('error', 'Background Task Failed',
                `${task.type} failed: ${task.error}`);
        }
    });
}

// ============== Canvas Events ==============
function setupCanvasEvents() {
    const canvas = document.getElementById('threat-canvas');
    if (!canvas) return;

    // Pan and zoom
    canvas.addEventListener('wheel', handleCanvasZoom);
    canvas.addEventListener('mousedown', handleCanvasMouseDown);

    // Global mousemove for connection line and panning
    document.addEventListener('mousemove', (e) => {
        // Update connection line if connecting
        if (AppState.canvas.isConnecting) {
            updateConnectionLine(e);
        }

        // Handle canvas panning
        if (AppState.canvas.isDragging) {
            const dx = e.clientX - AppState.canvas.dragStart.x;
            const dy = e.clientY - AppState.canvas.dragStart.y;

            AppState.canvas.pan.x += dx / AppState.canvas.zoom;
            AppState.canvas.pan.y += dy / AppState.canvas.zoom;
            AppState.canvas.dragStart = { x: e.clientX, y: e.clientY };

            canvas.style.transform = `scale(${AppState.canvas.zoom}) translate(${AppState.canvas.pan.x}px, ${AppState.canvas.pan.y}px)`;
        }
    });

    // Global mouseup to cancel incomplete connections
    document.addEventListener('mouseup', (e) => {
        // Cancel connection if clicking on empty space
        if (AppState.canvas.isConnecting) {
            // Only cancel if not clicking on a connector
            if (!e.target.classList.contains('node-connector')) {
                cancelConnection();
            }
        }

        AppState.canvas.isDragging = false;
    });

    // Click outside to deselect
    canvas.addEventListener('click', (e) => {
        if (e.target === canvas || e.target.id === 'threat-canvas') {
            deselectAllNodes();
        }
    });
}

function handleCanvasZoom(e) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    const newZoom = Math.max(0.25, Math.min(2, AppState.canvas.zoom + delta));
    AppState.canvas.zoom = newZoom;

    const canvas = document.getElementById('threat-canvas');
    canvas.style.transform = `scale(${newZoom}) translate(${AppState.canvas.pan.x}px, ${AppState.canvas.pan.y}px)`;

    updateZoomDisplay();
}

function handleCanvasMouseDown(e) {
    // Only start panning if clicking directly on the canvas background
    if (e.target.id === 'threat-canvas' || e.target.classList.contains('canvas-wrapper')) {
        AppState.canvas.isDragging = true;
        AppState.canvas.dragStart = { x: e.clientX, y: e.clientY };
    }
}

function updateZoomDisplay() {
    const display = document.querySelector('.zoom-value');
    if (display) {
        display.textContent = `${Math.round(AppState.canvas.zoom * 100)}%`;
    }
}

// ============== Drag and Drop ==============
function setupDragAndDrop() {
    // Make palette items draggable
    document.querySelectorAll('.drag-card').forEach(card => {
        card.setAttribute('draggable', 'true');
        card.addEventListener('dragstart', handleDragStart);
        card.addEventListener('dragend', handleDragEnd);
    });

    // Canvas and canvas-wrapper as drop targets
    const canvas = document.getElementById('threat-canvas');
    const canvasWrapper = document.querySelector('.canvas-wrapper');

    if (canvas) {
        canvas.addEventListener('dragover', handleDragOver);
        canvas.addEventListener('drop', handleDrop);
    }

    if (canvasWrapper) {
        canvasWrapper.addEventListener('dragover', handleDragOver);
        canvasWrapper.addEventListener('drop', handleDrop);
    }

    console.log('Drag and drop initialized');
}

function handleDragStart(e) {
    const card = e.target.closest('.drag-card');
    if (!card) return;

    card.classList.add('dragging');
    e.dataTransfer.setData('application/json', JSON.stringify({
        type: card.dataset.type,
        cardType: card.dataset.cardType,
        id: card.dataset.id,
        name: card.dataset.name
    }));
    e.dataTransfer.effectAllowed = 'copy';
}

function handleDragEnd(e) {
    e.target.classList.remove('dragging');
}

function handleDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();

    try {
        const dataStr = e.dataTransfer.getData('application/json');
        console.log('Drop data:', dataStr);

        if (!dataStr) {
            console.warn('No drop data received');
            return;
        }

        const data = JSON.parse(dataStr);
        const canvasWrapper = document.querySelector('.canvas-wrapper');
        const rect = canvasWrapper.getBoundingClientRect();

        // Calculate position accounting for zoom and pan
        const x = (e.clientX - rect.left) / AppState.canvas.zoom - AppState.canvas.pan.x;
        const y = (e.clientY - rect.top) / AppState.canvas.zoom - AppState.canvas.pan.y;

        console.log('Creating node at:', x, y);
        createCanvasNode(data, Math.max(10, x), Math.max(10, y));
    } catch (err) {
        console.error('Drop error:', err);
    }
}

// ============== Canvas Nodes ==============
function createCanvasNode(data, x, y, existingId = null) {
    // Use existing ID if provided (for restoring saved canvases), otherwise generate new ID
    const nodeId = existingId || `node-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const node = document.createElement('div');
    node.className = `canvas-node ${data.cardType} animate-slideIn`;
    node.id = nodeId;
    node.style.left = `${x}px`;
    node.style.top = `${y}px`;

    // Determine icon and colors based on card type
    const icons = {
        asset: '🖥️',
        threat: '⚠️',
        control: '🛡️',
        evidence: '📋'
    };

    node.innerHTML = `
        <div class="node-header">
            <div class="node-icon card-icon ${data.cardType}">
                ${icons[data.cardType] || '📦'}
            </div>
            <div>
                <div class="node-title">${data.name || 'New Item'}</div>
                <div class="node-subtitle">${data.type || data.cardType}</div>
            </div>
        </div>
        <div class="node-body">
            ${getNodeDescription(data)}
        </div>
        <div class="node-connector top"></div>
        <div class="node-connector bottom"></div>
        <div class="node-connector left"></div>
        <div class="node-connector right"></div>
    `;

    // Add to canvas
    const canvas = document.getElementById('threat-canvas');
    canvas.appendChild(node);

    // Store in state
    AppState.canvas.nodes.set(nodeId, {
        id: nodeId,
        data: data,
        position: { x, y },
        connections: []
    });

    // Setup node events
    setupNodeEvents(node);

    // Select the new node (only if not restoring)
    if (!existingId) {
        selectNode(nodeId);
        showNotification('success', 'Node Added', `${data.name || 'Item'} added to canvas`);
    }

    // Check for warnings (threats without controls)
    checkThreatWarnings();

    // Return nodeId for chaining
    return nodeId;
}

function getNodeDescription(data) {
    if (data.cardType === 'threat') {
        return `<span class="stride-badge ${data.category?.toLowerCase() || 'tampering'}">${data.category || 'STRIDE'}</span>`;
    } else if (data.cardType === 'asset') {
        return `<span class="tag">${data.type || 'MCP Server'}</span>`;
    } else if (data.cardType === 'control') {
        return `<span class="tag">${data.type || 'Security Control'}</span>`;
    }
    return '';
}

function setupNodeEvents(node) {
    // Dragging within canvas
    let isDragging = false;
    let dragOffset = { x: 0, y: 0 };

    // Handle connector clicks for starting connections
    node.querySelectorAll('.node-connector').forEach(connector => {
        connector.addEventListener('mousedown', (e) => {
            e.stopPropagation();
            startConnection(node.id, connector);
        });

        // Handle dropping connection on connector
        connector.addEventListener('mouseup', (e) => {
            e.stopPropagation();
            if (AppState.canvas.isConnecting) {
                const connectorType = connector.className.split(' ').find(c => ['top', 'bottom', 'left', 'right'].includes(c));
                endConnection(node.id, connectorType);
            }
        });

        // Highlight connector when hovering during connection
        connector.addEventListener('mouseenter', () => {
            if (AppState.canvas.isConnecting && AppState.canvas.connectStart?.nodeId !== node.id) {
                connector.style.background = 'var(--accent-primary)';
                connector.style.transform = connector.style.transform.replace('scale(1)', '') + ' scale(1.5)';
            }
        });

        connector.addEventListener('mouseleave', () => {
            connector.style.background = '';
            connector.style.transform = connector.style.transform.replace('scale(1.5)', '');
        });
    });

    node.addEventListener('mousedown', (e) => {
        // Don't start dragging if clicking connector
        if (e.target.classList.contains('node-connector')) {
            return;
        }

        isDragging = true;
        const rect = node.getBoundingClientRect();
        dragOffset = {
            x: e.clientX - rect.left,
            y: e.clientY - rect.top
        };
        node.style.zIndex = '100';
        selectNode(node.id);
        e.preventDefault();
    });

    // Node-specific mousemove for dragging
    const handleMouseMove = (e) => {
        if (!isDragging) return;

        const canvas = document.getElementById('threat-canvas');
        const canvasRect = canvas.getBoundingClientRect();

        const x = (e.clientX - canvasRect.left - dragOffset.x) / AppState.canvas.zoom;
        const y = (e.clientY - canvasRect.top - dragOffset.y) / AppState.canvas.zoom;

        node.style.left = `${Math.max(0, x)}px`;
        node.style.top = `${Math.max(0, y)}px`;

        // Update state
        const nodeData = AppState.canvas.nodes.get(node.id);
        if (nodeData) {
            nodeData.position = { x, y };
        }

        // Update connections
        renderConnections();
    };

    const handleMouseUp = () => {
        if (isDragging) {
            isDragging = false;
            node.style.zIndex = '';
        }
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);

    // Double click to edit
    node.addEventListener('dblclick', () => {
        openNodeEditor(node.id);
    });

    // Context menu
    node.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        showNodeContextMenu(node.id, e.clientX, e.clientY);
    });
}

function selectNode(nodeId) {
    // Deselect all
    document.querySelectorAll('.canvas-node').forEach(n => {
        n.classList.remove('selected');
    });

    // Select this node
    const node = document.getElementById(nodeId);
    if (node) {
        node.classList.add('selected');
        AppState.canvas.selectedNode = nodeId;

        // Auto-expand right panel when node is selected
        const panel = document.querySelector('.right-panel');
        const expandBtn = document.querySelector('.right-panel-expand-btn');
        if (panel && !AppState.rightPanelOpen) {
            panel.classList.remove('collapsed');
            AppState.rightPanelOpen = true;
            if (expandBtn) {
                expandBtn.classList.add('hidden');
            }
        }

        updateRightPanel(nodeId);
    }
}

function deselectAllNodes() {
    document.querySelectorAll('.canvas-node').forEach(n => {
        n.classList.remove('selected');
    });
    AppState.canvas.selectedNode = null;
    clearRightPanel();

    // Optionally collapse panel when deselecting (comment out if you want to keep it open)
    // const panel = document.querySelector('.right-panel');
    // if (panel && AppState.rightPanelOpen) {
    //     toggleRightPanel();
    // }
}

function deleteNode(nodeId) {
    const node = document.getElementById(nodeId);
    if (node) {
        node.remove();
        AppState.canvas.nodes.delete(nodeId);

        // Remove connections
        AppState.canvas.connections = AppState.canvas.connections.filter(
            conn => conn.source !== nodeId && conn.target !== nodeId
        );

        // Update connection SVG
        renderConnections();

        deselectAllNodes();
        showNotification('info', 'Node Deleted', 'Item removed from canvas');
    }
}

// ============== Connections ==============
function startConnection(nodeId, connector) {
    AppState.canvas.isConnecting = true;
    AppState.canvas.connectStart = {
        nodeId: nodeId,
        connector: connector.className.split(' ').find(c => ['top', 'bottom', 'left', 'right'].includes(c))
    };

    // Create temporary line SVG
    const svg = getConnectionSVG();
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.id = 'temp-connection';
    line.setAttribute('stroke', '#6366f1');
    line.setAttribute('stroke-width', '3');
    line.setAttribute('stroke-dasharray', '8,4');
    svg.appendChild(line);

    // Add visual feedback
    document.body.style.cursor = 'crosshair';

    console.log('Connection started from:', nodeId);
}

function updateConnectionLine(e) {
    const line = document.getElementById('temp-connection');
    if (!line || !AppState.canvas.connectStart) return;

    const startNode = document.getElementById(AppState.canvas.connectStart.nodeId);
    if (!startNode) return;

    const startPos = getConnectorPosition(startNode, AppState.canvas.connectStart.connector);

    const canvas = document.getElementById('threat-canvas');
    const canvasWrapper = canvas.parentElement;
    const rect = canvasWrapper.getBoundingClientRect();

    // Calculate mouse position relative to canvas
    const mouseX = (e.clientX - rect.left) / AppState.canvas.zoom - AppState.canvas.pan.x;
    const mouseY = (e.clientY - rect.top) / AppState.canvas.zoom - AppState.canvas.pan.y;

    line.setAttribute('x1', startPos.x);
    line.setAttribute('y1', startPos.y);
    line.setAttribute('x2', mouseX);
    line.setAttribute('y2', mouseY);
}

function endConnection(targetNodeId, connector) {
    if (!AppState.canvas.isConnecting || !AppState.canvas.connectStart) {
        console.log('endConnection: not in connecting mode');
        return;
    }

    const startNodeId = AppState.canvas.connectStart.nodeId;

    console.log('Ending connection:', startNodeId, '->', targetNodeId);

    // Don't connect to self
    if (startNodeId === targetNodeId) {
        console.log('Cannot connect to self');
        cancelConnection();
        return;
    }

    // Check if connection already exists - more strict check
    const exists = AppState.canvas.connections.some(c => {
        if (!c || !c.source || !c.target) return false;
        return (c.source === startNodeId && c.target === targetNodeId) ||
            (c.source === targetNodeId && c.target === startNodeId);
    });

    if (exists) {
        console.log('Connection already exists:', { startNodeId, targetNodeId });
        console.log('Existing connections:', AppState.canvas.connections);
        showNotification('warning', 'Already Connected', 'These nodes are already connected');
        cancelConnection();
        return;
    }

    // Create connection
    const connection = {
        id: `conn-${Date.now()}`,
        source: startNodeId,
        sourceConnector: AppState.canvas.connectStart.connector,
        target: targetNodeId,
        targetConnector: connector
    };

    AppState.canvas.connections.push(connection);
    console.log('Connection created:', connection);

    // Render the connection line
    renderConnections();

    // Create data flow
    createDataFlow(startNodeId, targetNodeId);

    // Clean up
    cancelConnection();

    // Check for threat warnings
    checkThreatWarnings();

    showNotification('success', 'Connected', 'Data flow created between nodes');
}

function cancelConnection() {
    AppState.canvas.isConnecting = false;
    AppState.canvas.connectStart = null;

    const line = document.getElementById('temp-connection');
    if (line) line.remove();

    // Reset cursor
    document.body.style.cursor = '';

    // Reset connector highlights
    document.querySelectorAll('.node-connector').forEach(conn => {
        conn.style.background = '';
        conn.style.transform = '';
    });
}

function getConnectionSVG() {
    let svg = document.getElementById('connections-svg');
    if (!svg) {
        svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.id = 'connections-svg';
        svg.style.cssText = 'position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 1;';
        document.getElementById('threat-canvas').appendChild(svg);
    }
    return svg;
}

function getConnectorPosition(node, connector) {
    if (!node) return { x: 0, y: 0 };

    // Get node's position from its style (more reliable)
    const nodeLeft = parseFloat(node.style.left) || 0;
    const nodeTop = parseFloat(node.style.top) || 0;
    const nodeWidth = node.offsetWidth;
    const nodeHeight = node.offsetHeight;

    switch (connector) {
        case 'top': return { x: nodeLeft + nodeWidth / 2, y: nodeTop };
        case 'bottom': return { x: nodeLeft + nodeWidth / 2, y: nodeTop + nodeHeight };
        case 'left': return { x: nodeLeft, y: nodeTop + nodeHeight / 2 };
        case 'right': return { x: nodeLeft + nodeWidth, y: nodeTop + nodeHeight / 2 };
        default: return { x: nodeLeft + nodeWidth / 2, y: nodeTop + nodeHeight / 2 };
    }
}

function renderConnections() {
    const svg = getConnectionSVG();
    svg.innerHTML = '';

    // Add arrow marker definition with actual color
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `
        <marker id="arrowhead" markerWidth="12" markerHeight="8" refX="10" refY="4" orient="auto">
            <polygon points="0 0, 12 4, 0 8" fill="#6366f1" />
        </marker>
    `;
    svg.appendChild(defs);

    console.log('Rendering connections:', AppState.canvas.connections.length);

    AppState.canvas.connections.forEach(conn => {
        const sourceNode = document.getElementById(conn.source);
        const targetNode = document.getElementById(conn.target);

        if (!sourceNode || !targetNode) {
            console.log('Missing node for connection:', conn);
            return;
        }

        const start = getConnectorPosition(sourceNode, conn.sourceConnector);
        const end = getConnectorPosition(targetNode, conn.targetConnector);

        console.log('Drawing line from', start, 'to', end);

        // Calculate control points for bezier curve
        const dx = end.x - start.x;
        const dy = end.y - start.y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const tension = Math.min(distance / 3, 100);

        // Determine curve direction based on connectors
        let cp1x, cp1y, cp2x, cp2y;

        if (conn.sourceConnector === 'right' || conn.sourceConnector === 'left') {
            cp1x = start.x + (conn.sourceConnector === 'right' ? tension : -tension);
            cp1y = start.y;
        } else {
            cp1x = start.x;
            cp1y = start.y + (conn.sourceConnector === 'bottom' ? tension : -tension);
        }

        if (conn.targetConnector === 'right' || conn.targetConnector === 'left') {
            cp2x = end.x + (conn.targetConnector === 'right' ? tension : -tension);
            cp2y = end.y;
        } else {
            cp2x = end.x;
            cp2y = end.y + (conn.targetConnector === 'bottom' ? tension : -tension);
        }

        // Create bezier path
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        const d = `M ${start.x} ${start.y} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${end.x} ${end.y}`;

        path.setAttribute('d', d);
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke', '#6366f1');
        path.setAttribute('stroke-width', '3');
        path.setAttribute('marker-end', 'url(#arrowhead)');
        path.setAttribute('class', 'connection-line');

        svg.appendChild(path);
    });
}

function updateConnections(nodeId) {
    renderConnections();
}

// ============== Right Panel ==============
function setupPanelEvents() {
    // Toggle right panel
    document.querySelector('.toggle-right-panel')?.addEventListener('click', toggleRightPanel);

    // Section toggles in left panel
    document.querySelectorAll('.section-header').forEach(header => {
        header.addEventListener('click', () => {
            const section = header.closest('.panel-section');
            const items = section.querySelector('.section-items');
            items.style.display = items.style.display === 'none' ? 'flex' : 'none';
        });
    });
}

function toggleRightPanel() {
    const panel = document.querySelector('.right-panel');
    const expandBtn = document.querySelector('.right-panel-expand-btn');

    panel.classList.toggle('collapsed');
    AppState.rightPanelOpen = !AppState.rightPanelOpen;

    // Show/hide expand button
    if (expandBtn) {
        expandBtn.classList.toggle('hidden', AppState.rightPanelOpen);
    }

    // If opening and no node selected, show empty state
    if (AppState.rightPanelOpen && !AppState.canvas.selectedNode) {
        clearRightPanel();
    }
}

// Setup expand button visibility
function setupRightPanelExpandButton() {
    const panel = document.querySelector('.right-panel');
    const expandBtn = document.querySelector('.right-panel-expand-btn');

    if (expandBtn && panel) {
        // Initially hide button if panel is open
        expandBtn.classList.toggle('hidden', AppState.rightPanelOpen);
    }
}

function updateRightPanel(nodeId) {
    const nodeData = AppState.canvas.nodes.get(nodeId);
    if (!nodeData) return;

    const panel = document.querySelector('.detail-content');
    if (!panel) return;

    const data = nodeData.data;

    panel.innerHTML = `
        <div class="detail-section">
            <div class="detail-section-title">Basic Information</div>
            <div class="detail-field">
                <div class="detail-label">Title</div>
                <input type="text" class="detail-input" id="node-title" value="${data.name || ''}" />
            </div>
            <div class="detail-field">
                <div class="detail-label">Type</div>
                <div class="detail-value">
                    <span class="tag">${data.cardType}</span>
                    ${data.type ? `<span class="tag">${data.type}</span>` : ''}
                </div>
            </div>
            ${data.cardType === 'threat' ? `
                <div class="detail-field">
                    <div class="detail-label">STRIDE Category</div>
                    <select class="detail-input detail-select" id="node-stride">
                        <option value="Spoofing" ${data.category === 'Spoofing' ? 'selected' : ''}>Spoofing</option>
                        <option value="Tampering" ${data.category === 'Tampering' ? 'selected' : ''}>Tampering</option>
                        <option value="Repudiation" ${data.category === 'Repudiation' ? 'selected' : ''}>Repudiation</option>
                        <option value="Information Disclosure" ${data.category === 'Information Disclosure' ? 'selected' : ''}>Information Disclosure</option>
                        <option value="Denial of Service" ${data.category === 'Denial of Service' ? 'selected' : ''}>Denial of Service</option>
                        <option value="Elevation of Privilege" ${data.category === 'Elevation of Privilege' ? 'selected' : ''}>Elevation of Privilege</option>
                    </select>
                </div>
                <div class="detail-field">
                    <div class="detail-label">Risk Score</div>
                    <div class="risk-slider-container">
                        <input type="range" class="risk-slider" id="node-risk" min="0" max="10" step="0.1" value="${data.riskScore || 5}" />
                        <span class="risk-value" id="risk-display">${data.riskScore || 5}</span>
                    </div>
                </div>
            ` : ''}
        </div>
        
        <div class="detail-section">
            <div class="detail-section-title">Description</div>
            <textarea class="detail-input detail-textarea" id="node-description">${data.description || ''}</textarea>
        </div>
        
        ${data.cardType === 'threat' ? `
            <div class="detail-section">
                <div class="detail-section-title">Impact</div>
                <div class="tag-container" id="impact-tags">
                    ${(data.impact || []).map(i => `<span class="tag">${i} <span class="tag-remove" onclick="removeTag('impact', '${i}')">×</span></span>`).join('')}
                </div>
                <input type="text" class="detail-input" placeholder="Add impact..." onkeypress="handleAddTag(event, 'impact')" />
            </div>
            
            <div class="detail-section">
                <div class="detail-section-title">Recommended Controls</div>
                <div class="tag-container" id="controls-tags">
                    ${(data.recommendedControls || []).map(c => `<span class="tag">${c}</span>`).join('')}
                </div>
            </div>
        ` : ''}
        
        <div class="detail-section">
            <div class="detail-section-title">JSON Schema</div>
            <div class="json-viewer">
                <pre>${JSON.stringify(data, null, 2)}</pre>
            </div>
        </div>
        
        <div class="detail-section">
            <button class="btn btn-danger btn-sm" onclick="deleteNode('${nodeId}')">
                🗑️ Delete Node
            </button>
        </div>
    `;

    // Setup event listeners for editable fields
    document.getElementById('node-title')?.addEventListener('change', (e) => {
        updateNodeData(nodeId, 'name', e.target.value);
    });

    document.getElementById('node-description')?.addEventListener('change', (e) => {
        updateNodeData(nodeId, 'description', e.target.value);
    });

    document.getElementById('node-stride')?.addEventListener('change', (e) => {
        updateNodeData(nodeId, 'category', e.target.value);
    });

    document.getElementById('node-risk')?.addEventListener('input', (e) => {
        document.getElementById('risk-display').textContent = e.target.value;
        updateNodeData(nodeId, 'riskScore', parseFloat(e.target.value));
    });
}

function updateNodeData(nodeId, field, value) {
    const nodeData = AppState.canvas.nodes.get(nodeId);
    if (nodeData) {
        nodeData.data[field] = value;

        // Update visual
        const node = document.getElementById(nodeId);
        if (field === 'name') {
            node.querySelector('.node-title').textContent = value;
        }
    }
}

function clearRightPanel() {
    const panel = document.querySelector('.detail-content');
    if (panel) {
        const nodeCount = AppState.canvas.nodes.size;
        const connectionCount = AppState.canvas.connections.length;

        panel.innerHTML = `
            <div class="empty-state">
                <div style="text-align: center; padding: 20px; color: var(--text-muted);">
                    <div style="font-size: 3rem; margin-bottom: 16px;">🎯</div>
                    <div style="font-size: 0.875rem; font-weight: 500; color: var(--text-secondary); margin-bottom: 8px;">
                        Select a node to view details
                    </div>
                    <div style="font-size: 0.75rem; margin-bottom: 24px;">
                        Drag components from the left panel to build your threat model
                    </div>
                </div>
                
                <div class="detail-section" style="margin-top: 24px;">
                    <div class="detail-section-title">Canvas Statistics</div>
                    <div style="display: flex; flex-direction: column; gap: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 0.8rem; color: var(--text-secondary);">Nodes</span>
                            <span style="font-size: 0.875rem; font-weight: 600; color: var(--text-primary);">${nodeCount}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 0.8rem; color: var(--text-secondary);">Connections</span>
                            <span style="font-size: 0.875rem; font-weight: 600; color: var(--text-primary);">${connectionCount}</span>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="detail-section-title">Quick Actions</div>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        <button class="btn btn-secondary btn-sm" onclick="openDiscoverModal()" style="width: 100%; justify-content: center;">
                            🔍 Discover MCP Config
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="gatherIntel()" style="width: 100%; justify-content: center;">
                            📡 Gather Intelligence
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="generateReport()" style="width: 100%; justify-content: center;">
                            📊 Generate Report
                        </button>
                    </div>
                </div>
                
                <div class="detail-section">
                    <div class="detail-section-title">Keyboard Shortcuts</div>
                    <div style="display: flex; flex-direction: column; gap: 8px; font-size: 0.75rem;">
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: var(--text-secondary);">Delete Node</span>
                            <span style="color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Delete / Backspace</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: var(--text-secondary);">Deselect</span>
                            <span style="color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Esc</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: var(--text-secondary);">Save Canvas</span>
                            <span style="color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Ctrl + S</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: var(--text-secondary);">Zoom In</span>
                            <span style="color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Ctrl + +</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: var(--text-secondary);">Zoom Out</span>
                            <span style="color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Ctrl + -</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: var(--text-secondary);">Reset Zoom</span>
                            <span style="color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Ctrl + 0</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
}

// ============== Threat Warnings ==============
function checkThreatWarnings() {
    // Find threats without connected controls
    AppState.canvas.nodes.forEach((nodeData, nodeId) => {
        if (nodeData.data.cardType === 'threat') {
            const hasControl = AppState.canvas.connections.some(conn => {
                const otherNodeId = conn.source === nodeId ? conn.target : conn.source;
                const otherNode = AppState.canvas.nodes.get(otherNodeId);
                return otherNode?.data.cardType === 'control';
            });

            const node = document.getElementById(nodeId);
            if (node) {
                node.classList.toggle('warning', !hasControl);
            }
        }
    });
}

// ============== Data Loading ==============
async function loadInitialData() {
    try {
        // Load all data in parallel
        const [assetsRes, threatsRes, controlsRes, evidenceRes] = await Promise.all([
            fetch(`${API_BASE}/assets?project_id=default-project`),
            fetch(`${API_BASE}/threats?project_id=default-project`),
            fetch(`${API_BASE}/controls?project_id=default-project`),
            fetch(`${API_BASE}/evidence?project_id=default-project`)
        ]);

        if (assetsRes.ok) {
            const data = await assetsRes.json();
            AppState.assets = data.assets || [];
            updateAssetPalette();
        }

        if (threatsRes.ok) {
            const data = await threatsRes.json();
            AppState.threats = data.threats || [];
            updateThreatPalette();
            document.getElementById('threat-count').textContent = AppState.threats.length;
        }

        if (controlsRes.ok) {
            const data = await controlsRes.json();
            AppState.controls = data.controls || [];
            updateControlPalette();
        }

        if (evidenceRes.ok) {
            const data = await evidenceRes.json();
            AppState.evidence = data.evidence || [];
            updateEvidencePalette();
            document.getElementById('evidence-count').textContent = AppState.evidence.length;
        }

        // Load threat templates
        await loadThreatTemplates();

        // Load Threat Model Matrix data if available
        if (typeof loadThreatModelMatrix === 'function') {
            loadThreatModelMatrix().catch(err => console.error('Error auto-loading Threat Model Matrix:', err));
        }

        // Load Knowledge Graph data if function exists
        if (typeof loadKnowledgeGraph === 'function') {
            loadKnowledgeGraph().catch(err => console.error('Error auto-loading Knowledge Graph:', err));
        }

        // Load 3D Landscape if function exists
        if (typeof window.threatLandscape3D !== 'undefined' && typeof window.threatLandscape3D.refreshData === 'function') {
            window.threatLandscape3D.refreshData().catch(err => console.error('Error refreshing 3D Landscape:', err));
        }

    } catch (err) {
        console.error('Failed to load initial data:', err);
        showNotification('error', 'Load Error', 'Failed to load platform data');
    }
}

async function loadThreatTemplates() {
    try {
        const res = await fetch(`${API_BASE}/threats/templates`);
        if (res.ok) {
            const data = await res.json();
            updateTemplatePalette(data.templates || []);
        }
    } catch (err) {
        console.error('Failed to load templates:', err);
    }
}

function updateAssetPalette() {
    const container = document.getElementById('asset-items');
    if (!container) return;

    // Add predefined asset types
    const assetTypes = [
        { type: 'mcp_server', name: 'MCP Server', icon: '🖥️' },
        { type: 'mcp_client', name: 'MCP Client', icon: '💻' },
        { type: 'llm_provider', name: 'LLM Provider', icon: '🤖' },
        { type: 'tool', name: 'Tool', icon: '🔧' },
        { type: 'filesystem', name: 'File System', icon: '📁' },
        { type: 'browser', name: 'Browser', icon: '🌐' },
        { type: 'database', name: 'Database', icon: '🗄️' },
        { type: 'api_key_store', name: 'API Key Store', icon: '🔑' }
    ];

    container.innerHTML = assetTypes.map(asset => `
        <div class="drag-card" 
             draggable="true" 
             data-card-type="asset" 
             data-type="${asset.type}"
             data-name="${asset.name}">
            <div class="card-icon asset">${asset.icon}</div>
            <div class="card-info">
                <div class="card-name">${asset.name}</div>
                <div class="card-meta">Asset</div>
            </div>
        </div>
    `).join('');

    // Re-setup drag events
    container.querySelectorAll('.drag-card').forEach(card => {
        card.addEventListener('dragstart', handleDragStart);
        card.addEventListener('dragend', handleDragEnd);
    });
}

function updateThreatPalette() {
    const container = document.getElementById('threat-items');
    if (!container) return;

    // Helper function to escape HTML
    const escapeHtml = (text) => {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    const html = AppState.threats.map(threat => {
        // Use name (not title) and stride_category (not category)
        // Check to_dict() in models.py: it returns both 'name' and 'category'/'stride_category'
        const threatName = threat.name || threat.title || 'Unknown Threat';
        const threatCategory = threat.stride_category || threat.category || 'STRIDE';

        return `
        <div class="drag-card" 
             draggable="true" 
             data-card-type="threat" 
             data-id="${threat.id}"
             data-name="${escapeHtml(threatName)}"
             data-category="${escapeHtml(threatCategory)}">
            <div class="card-icon threat">⚠️</div>
            <div class="card-info">
                <div class="card-name">${escapeHtml(threatName)}</div>
                <div class="card-meta">${escapeHtml(threatCategory)}</div>
            </div>
        </div>
    `;
    }).join('');

    container.innerHTML = html || '<div class="card-meta" style="padding: 10px;">No threats loaded</div>';

    // Re-setup drag events
    container.querySelectorAll('.drag-card').forEach(card => {
        card.addEventListener('dragstart', handleDragStart);
        card.addEventListener('dragend', handleDragEnd);
    });
}

function updateTemplatePalette(templates) {
    const container = document.getElementById('template-items');
    if (!container) return;

    container.innerHTML = templates.map(template => `
        <div class="drag-card" 
             draggable="true" 
             data-card-type="threat" 
             data-name="${template.title}"
             data-category="${template.category}"
             data-type="template">
            <div class="card-icon threat">📋</div>
            <div class="card-info">
                <div class="card-name">${template.title}</div>
                <div class="card-meta">${template.category}</div>
            </div>
        </div>
    `).join('');

    // Re-setup drag events
    container.querySelectorAll('.drag-card').forEach(card => {
        card.addEventListener('dragstart', handleDragStart);
        card.addEventListener('dragend', handleDragEnd);
    });
}

function updateControlPalette() {
    const container = document.getElementById('control-items');
    if (!container) return;

    // Add predefined control types
    const controlTypes = [
        { type: 'tool_sandbox', name: 'Tool Sandbox', icon: '📦' },
        { type: 'tool_permission', name: 'Tool Permission', icon: '🔐' },
        { type: 'rate_limit', name: 'Rate Limit', icon: '⏱️' },
        { type: 'path_whitelist', name: 'Path Whitelist', icon: '📂' },
        { type: 'url_whitelist', name: 'URL Whitelist', icon: '🔗' },
        { type: 'output_validation', name: 'Output Validation', icon: '✅' },
        { type: 'token_redaction', name: 'Token Redaction', icon: '🔒' },
        { type: 'audit_logging', name: 'Audit Logging', icon: '📝' }
    ];

    container.innerHTML = controlTypes.map(control => `
        <div class="drag-card" 
             draggable="true" 
             data-card-type="control" 
             data-type="${control.type}"
             data-name="${control.name}">
            <div class="card-icon control">${control.icon}</div>
            <div class="card-info">
                <div class="card-name">${control.name}</div>
                <div class="card-meta">Security Control</div>
            </div>
        </div>
    `).join('');

    // Re-setup drag events
    container.querySelectorAll('.drag-card').forEach(card => {
        card.addEventListener('dragstart', handleDragStart);
        card.addEventListener('dragend', handleDragEnd);
    });
}

// ============== Canvas Initialization ==============
function initializeCanvas() {
    updateZoomDisplay();
    clearRightPanel();
    // Setup right panel expand button visibility
    setupRightPanelExpandButton();
}

// ============== Keyboard Shortcuts ==============
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Delete selected node
        if (e.key === 'Delete' || e.key === 'Backspace') {
            if (AppState.canvas.selectedNode && !e.target.matches('input, textarea')) {
                deleteNode(AppState.canvas.selectedNode);
            }
        }

        // Escape to deselect or cancel connection
        if (e.key === 'Escape') {
            if (AppState.canvas.isConnecting) {
                cancelConnection();
            } else {
                deselectAllNodes();
            }
        }

        // Ctrl+S to save
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            saveCanvas();
        }

        // Zoom shortcuts
        if (e.ctrlKey && (e.key === '+' || e.key === '=')) {
            e.preventDefault();
            zoomIn();
        }
        if (e.ctrlKey && e.key === '-') {
            e.preventDefault();
            zoomOut();
        }
        if (e.ctrlKey && e.key === '0') {
            e.preventDefault();
            resetZoom();
        }
    });
}

// ============== Zoom Controls ==============
function zoomIn() {
    AppState.canvas.zoom = Math.min(2, AppState.canvas.zoom + 0.1);
    applyZoom();
}

function zoomOut() {
    AppState.canvas.zoom = Math.max(0.25, AppState.canvas.zoom - 0.1);
    applyZoom();
}

function resetZoom() {
    AppState.canvas.zoom = 1;
    AppState.canvas.pan = { x: 0, y: 0 };
    applyZoom();
}

function applyZoom() {
    const canvas = document.getElementById('threat-canvas');
    canvas.style.transform = `scale(${AppState.canvas.zoom}) translate(${AppState.canvas.pan.x}px, ${AppState.canvas.pan.y}px)`;
    updateZoomDisplay();
}

// ============== Canvas Save/Load ==============
async function saveCanvas() {
    // Check if there are existing canvases
    let existingCanvases = [];
    try {
        const listRes = await fetch(`${API_BASE}/canvas/list?project_id=default-project`);
        if (listRes.ok) {
            const listData = await listRes.json();
            existingCanvases = listData.canvases || [];
        }
    } catch (err) {
        console.warn('Failed to fetch canvas list:', err);
    }

    // If there's only one canvas, use it automatically (auto-update)
    // If multiple, show selection modal
    // If none, ask for new name
    let canvasName;
    if (existingCanvases.length === 1) {
        // Auto-update the only existing canvas
        canvasName = existingCanvases[0].name;
        const existing = existingCanvases[0];
        await performCanvasSave(canvasName, existing);
    } else if (existingCanvases.length > 1) {
        // Show selection modal for multiple canvases
        showCanvasSaveModal(existingCanvases);
        return; // Modal will handle the save
    } else {
        // No existing canvases, ask for new name
        canvasName = prompt('Enter canvas name:', 'default');
        if (!canvasName) return;
        await performCanvasSave(canvasName, undefined);
    }
}

async function performCanvasSave(canvasName, existing) {

    // Prepare nodes data
    const nodesArray = Array.from(AppState.canvas.nodes.entries()).map(([id, nodeData]) => [
        id,
        {
            id: id,
            data: nodeData.data,
            position: nodeData.position || { x: 0, y: 0 }
        }
    ]);

    // Prepare connections - ensure all required fields
    const connectionsArray = AppState.canvas.connections.map(conn => ({
        id: conn.id || `conn-${Date.now()}-${Math.random()}`,
        source: conn.source,
        target: conn.target,
        sourceConnector: conn.sourceConnector || 'right',
        targetConnector: conn.targetConnector || 'left'
    }));

    const canvasState = {
        nodes: nodesArray,
        connections: connectionsArray,
        viewport: {
            zoom: AppState.canvas.zoom,
            pan: AppState.canvas.pan
        }
    };

    console.log('Saving canvas:', {
        nodeCount: nodesArray.length,
        connectionCount: connectionsArray.length,
        connections: connectionsArray
    });

    try {
        const res = await fetch(`${API_BASE}/canvas/save`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: canvasName,
                state: canvasState,
                project_id: 'default-project'
            })
        });

        if (res.ok) {
            const data = await res.json();
            const isUpdate = existing !== undefined;
            showNotification('success', isUpdate ? 'Updated' : 'Saved',
                `Canvas "${canvasName}" ${isUpdate ? 'updated' : 'saved'} (v${data.version || 1}, ${nodesArray.length} nodes, ${connectionsArray.length} connections)`);
        } else {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.error || 'Save failed');
        }
    } catch (err) {
        console.error('Save error:', err);
        showNotification('error', 'Save Error', 'Failed to save canvas: ' + err.message);
    }
}

function showCanvasSaveModal(existingCanvases) {
    // Create modal for saving/updating canvas
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay active';
    overlay.id = 'canvas-save-modal';

    overlay.innerHTML = `
        <div class="modal" style="max-width: 600px;">
            <div class="modal-header">
                <span class="modal-title">💾 Save Canvas</span>
                <button class="modal-close" onclick="closeModal('canvas-save-modal')">×</button>
            </div>
            <div class="modal-body">
                <div style="margin-bottom: 16px;">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-secondary); font-size: 0.875rem;">
                        Canvas Name:
                    </label>
                    <input type="text" id="canvas-save-name" class="detail-input" placeholder="Enter canvas name" value="default">
                </div>
                <div style="margin-bottom: 16px; color: var(--text-secondary); font-size: 0.875rem;">
                    Or select existing to update:
                </div>
                <div class="canvas-list">
                    ${existingCanvases.map((canvas, index) => `
                        <div class="canvas-item" onclick="selectCanvasForSave('${canvas.name}')">
                            <div class="canvas-item-header">
                                <div class="canvas-item-name">${canvas.name || 'Untitled'}</div>
                                <div class="canvas-item-badge">v${canvas.version || 1}</div>
                            </div>
                            <div class="canvas-item-meta">
                                <span class="canvas-item-date">📅 ${new Date(canvas.updated_at).toLocaleString()}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('canvas-save-modal')">Cancel</button>
                <button class="btn btn-primary" onclick="saveCanvasFromModal()">Save</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    // Close on overlay click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            closeModal('canvas-save-modal');
        }
    });

    // Close button
    overlay.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-close') || e.target.closest('.modal-close')) {
            e.stopPropagation();
            closeModal('canvas-save-modal');
        }
    });
}

function selectCanvasForSave(canvasName) {
    document.getElementById('canvas-save-name').value = canvasName;
}

async function saveCanvasFromModal() {
    const canvasName = document.getElementById('canvas-save-name').value.trim();
    if (!canvasName) {
        showNotification('error', 'Invalid Name', 'Please enter a canvas name');
        return;
    }

    closeModal('canvas-save-modal');

    // Get existing canvases to check if updating
    let existingCanvases = [];
    try {
        const listRes = await fetch(`${API_BASE}/canvas/list?project_id=default-project`);
        if (listRes.ok) {
            const listData = await listRes.json();
            existingCanvases = listData.canvases || [];
        }
    } catch (err) {
        console.warn('Failed to fetch canvas list:', err);
    }

    const existing = existingCanvases.find(c => c.name === canvasName);
    await performCanvasSave(canvasName, existing);
}

async function performCanvasSave(canvasName, existing) {
    // Prepare nodes data
    const nodesArray = Array.from(AppState.canvas.nodes.entries()).map(([id, nodeData]) => [
        id,
        {
            id: id,
            data: nodeData.data,
            position: nodeData.position || { x: 0, y: 0 }
        }
    ]);

    // Prepare connections - ensure all required fields
    const connectionsArray = AppState.canvas.connections.map(conn => ({
        id: conn.id || `conn-${Date.now()}-${Math.random()}`,
        source: conn.source,
        target: conn.target,
        sourceConnector: conn.sourceConnector || 'right',
        targetConnector: conn.targetConnector || 'left'
    }));

    const canvasState = {
        nodes: nodesArray,
        connections: connectionsArray,
        viewport: {
            zoom: AppState.canvas.zoom,
            pan: AppState.canvas.pan
        }
    };

    console.log('Saving canvas:', {
        nodeCount: nodesArray.length,
        connectionCount: connectionsArray.length,
        connections: connectionsArray
    });

    try {
        const res = await fetch(`${API_BASE}/canvas/save`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: canvasName,
                state: canvasState,
                project_id: 'default-project'
            })
        });

        if (res.ok) {
            const data = await res.json();
            const isUpdate = existing !== undefined;
            showNotification('success', isUpdate ? 'Updated' : 'Saved',
                `Canvas "${canvasName}" ${isUpdate ? 'updated' : 'saved'} (v${data.version || 1}, ${nodesArray.length} nodes, ${connectionsArray.length} connections)`);
        } else {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.error || 'Save failed');
        }
    } catch (err) {
        console.error('Save error:', err);
        showNotification('error', 'Save Error', 'Failed to save canvas: ' + err.message);
    }
}

async function loadCanvas() {
    try {
        // First, get list of saved canvases
        const listRes = await fetch(`${API_BASE}/canvas/list?project_id=default-project`);
        if (!listRes.ok) {
            throw new Error('Failed to fetch canvas list');
        }

        const listData = await listRes.json();
        const canvases = listData.canvases || [];

        if (canvases.length === 0) {
            showNotification('info', 'No Saved Canvases', 'No saved canvases found');
            return;
        }

        // Show canvas selection modal
        showCanvasSelectionModal(canvases);
    } catch (err) {
        console.error('Load error:', err);
        showNotification('error', 'Load Error', 'Failed to load canvas: ' + err.message);
    }
}

function showCanvasSelectionModal(canvases) {
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay active';
    overlay.id = 'canvas-selection-modal';

    // Format date helper
    const formatDate = (dateStr) => {
        if (!dateStr) return 'Unknown';
        const date = new Date(dateStr);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    overlay.innerHTML = `
        <div class="modal" style="max-width: 600px;">
            <div class="modal-header">
                <span class="modal-title">📂 Load Canvas</span>
                <button class="modal-close" id="canvas-modal-close-btn">×</button>
            </div>
            <div class="modal-body" style="max-height: 500px; overflow-y: auto;">
                <div style="margin-bottom: 16px; color: var(--text-secondary); font-size: 0.875rem;">
                    Select a saved canvas to load:
                </div>
                <div class="canvas-list">
                    ${canvases.map((canvas, index) => `
                        <div class="canvas-item" data-index="${index}" data-name="${canvas.name}">
                            <div class="canvas-item-header">
                                <div class="canvas-item-name">${canvas.name || 'Untitled'}</div>
                                <div class="canvas-item-badge">v${canvas.version || 1}</div>
                            </div>
                            <div class="canvas-item-meta">
                                <span class="canvas-item-date">📅 ${formatDate(canvas.updated_at)}</span>
                            </div>
                            <button class="btn btn-primary btn-sm canvas-load-btn" onclick="loadSelectedCanvas('${canvas.name}')">
                                Load
                            </button>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    // Close on overlay click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            closeModal('canvas-selection-modal');
        }
    });

    // Ensure close button works - use event delegation
    overlay.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-close') || e.target.closest('.modal-close')) {
            e.stopPropagation();
            closeModal('canvas-selection-modal');
        }
    });
}

async function loadSelectedCanvas(canvasName) {
    try {
        closeModal('canvas-selection-modal');
        showNotification('info', 'Loading', 'Loading canvas...');

        const res = await fetch(`${API_BASE}/canvas/load?id=${canvasName}&project_id=default-project`);
        if (res.ok) {
            const data = await res.json();
            if (data.state) {
                restoreCanvasState(data.state);
                showNotification('success', 'Loaded', `Canvas "${canvasName}" loaded successfully`);
            } else {
                throw new Error('No canvas state found');
            }
        } else {
            throw new Error('Failed to load canvas');
        }
    } catch (err) {
        console.error('Load error:', err);
        showNotification('error', 'Load Error', 'Failed to load canvas: ' + err.message);
    }
}

function restoreCanvasState(state) {
    // Clear current canvas
    const canvas = document.getElementById('threat-canvas');
    canvas.querySelectorAll('.canvas-node').forEach(n => n.remove());
    AppState.canvas.nodes.clear();
    AppState.canvas.connections = [];

    // Restore nodes - handle both array of arrays and array of objects
    // IMPORTANT: Use original node IDs to preserve connections
    const restoredNodeIds = new Set();
    if (state.nodes) {
        const nodesArray = Array.isArray(state.nodes) ? state.nodes : [];
        nodesArray.forEach((item) => {
            let originalId, nodeData;

            // Handle [id, nodeData] format
            if (Array.isArray(item) && item.length === 2) {
                [originalId, nodeData] = item;
            }
            // Handle {id, data, position} format
            else if (item && typeof item === 'object') {
                originalId = item.id || item[0];
                nodeData = item.data || item[1] || item;
            }
            else {
                return; // Skip invalid entries
            }

            // Ensure nodeData has required structure and use original ID
            if (nodeData && nodeData.data && nodeData.position) {
                createCanvasNode(nodeData.data, nodeData.position.x || 100, nodeData.position.y || 100, originalId);
                restoredNodeIds.add(originalId);
            } else if (nodeData && nodeData.position) {
                createCanvasNode(nodeData, nodeData.position.x || 100, nodeData.position.y || 100, originalId);
                restoredNodeIds.add(originalId);
            } else if (nodeData && typeof nodeData === 'object') {
                // Handle case where nodeData is the data itself
                const position = nodeData.position || { x: 100, y: 100 };
                createCanvasNode(nodeData, position.x, position.y, originalId);
                restoredNodeIds.add(originalId);
            }
        });
        console.log('Restored nodes:', restoredNodeIds.size, 'Node IDs:', Array.from(restoredNodeIds));
    }

    // Restore connections - must be after nodes are restored
    if (state.connections && Array.isArray(state.connections)) {
        // Wait a bit for DOM to be ready
        setTimeout(() => {
            AppState.canvas.connections = state.connections.filter(conn => {
                // Validate connection has required fields
                if (!conn || !conn.source || !conn.target) {
                    console.warn('Invalid connection:', conn);
                    return false;
                }
                // Ensure both source and target nodes exist
                const sourceExists = AppState.canvas.nodes.has(conn.source);
                const targetExists = AppState.canvas.nodes.has(conn.target);
                if (!sourceExists || !targetExists) {
                    console.warn('Connection references missing node:', {
                        source: conn.source,
                        target: conn.target,
                        sourceExists,
                        targetExists,
                        availableNodes: Array.from(AppState.canvas.nodes.keys())
                    });
                    return false;
                }
                return true;
            });
            console.log('Restored connections:', AppState.canvas.connections.length);
            // Render connections after nodes are fully rendered
            renderConnections();
        }, 200);
    } else {
        AppState.canvas.connections = [];
        console.log('No connections to restore');
    }

    // Restore zoom/pan
    if (state.viewport) {
        if (state.viewport.zoom) AppState.canvas.zoom = state.viewport.zoom;
        if (state.viewport.pan) {
            AppState.canvas.pan = state.viewport.pan;
        }
    } else {
        if (state.zoom) AppState.canvas.zoom = state.zoom;
        if (state.pan) AppState.canvas.pan = state.pan;
    }
    applyZoom();
}

// ============== Data Flow ==============
function createDataFlow(sourceId, targetId) {
    const sourceNode = AppState.canvas.nodes.get(sourceId);
    const targetNode = AppState.canvas.nodes.get(targetId);

    if (!sourceNode || !targetNode) return;

    AppState.dataFlows.push({
        id: `flow-${Date.now()}`,
        source: sourceId,
        target: targetId,
        sourceType: sourceNode.data.cardType,
        targetType: targetNode.data.cardType
    });
}

// ============== Notifications ==============
function showNotification(type, title, message) {
    const container = document.querySelector('.notification-container') || createNotificationContainer();

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;

    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    notification.innerHTML = `
        <div class="notification-icon">${icons[type] || 'ℹ'}</div>
        <div class="notification-content">
            <div class="notification-title">${title}</div>
            <div class="notification-message">${message}</div>
        </div>
    `;

    container.appendChild(notification);

    // Animate in
    setTimeout(() => notification.classList.add('show'), 10);

    // Auto remove
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.className = 'notification-container';
    document.body.appendChild(container);
    return container;
}

// ============== Dashboard ==============
// Dashboard functions removed - Dashboard tab has been deleted

// ============== API Functions ==============

async function updateSTRIDEChart() {
    const strideCounts = {
        'Spoofing': 0,
        'Tampering': 0,
        'Repudiation': 0,
        'Information Disclosure': 0,
        'Denial of Service': 0,
        'Elevation of Privilege': 0
    };

    // Fetch threats from API
    try {
        const res = await fetch(`${API_BASE}/threats?project_id=default-project&limit=1000`);
        if (res.ok) {
            const data = await res.json();
            const threats = data.threats || [];

            threats.forEach(threat => {
                if (threat && threat.category) {
                    // Handle both enum and string category
                    let category = threat.category;
                    if (typeof category === 'object' && category.value) {
                        category = category.value;
                    }
                    category = String(category);

                    // Map common variations
                    const categoryMap = {
                        'spoofing': 'Spoofing',
                        'tampering': 'Tampering',
                        'repudiation': 'Repudiation',
                        'information_disclosure': 'Information Disclosure',
                        'information disclosure': 'Information Disclosure',
                        'denial_of_service': 'Denial of Service',
                        'denial of service': 'Denial of Service',
                        'elevation_of_privilege': 'Elevation of Privilege',
                        'elevation of privilege': 'Elevation of Privilege'
                    };

                    category = categoryMap[category.toLowerCase()] || category;

                    if (strideCounts.hasOwnProperty(category)) {
                        strideCounts[category]++;
                    }
                }
            });

            // Update AppState
            AppState.threats = threats;
        }
    } catch (err) {
        console.error('Failed to load threats for STRIDE chart:', err);
        // Fallback to AppState
        if (AppState.threats && Array.isArray(AppState.threats)) {
            AppState.threats.forEach(threat => {
                if (threat && threat.category) {
                    let category = threat.category;
                    if (typeof category === 'object' && category.value) {
                        category = category.value;
                    }
                    category = String(category);
                    if (strideCounts.hasOwnProperty(category)) {
                        strideCounts[category]++;
                    }
                }
            });
        }
    }

    // Render simple bar chart
    const container = document.getElementById('stride-chart');
    if (!container) return;

    const total = Object.values(strideCounts).reduce((a, b) => a + b, 0);

    if (total === 0) {
        container.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-secondary); padding: 2rem;">
                <div style="text-align: center;">
                    <div style="font-size: 2rem; margin-bottom: 0.5rem;">📊</div>
                    <div>No threats available</div>
                    <div style="font-size: 0.875rem; margin-top: 0.5rem; color: var(--text-tertiary);">
                        Add threats to see STRIDE distribution
                    </div>
                </div>
            </div>
        `;
        return;
    }

    container.innerHTML = Object.entries(strideCounts).map(([category, count]) => `
        <div style="display: flex; align-items: center; margin-bottom: 8px;">
            <div style="width: 140px; font-size: 0.75rem; color: var(--text-secondary);">${category}</div>
            <div style="flex: 1; height: 20px; background: var(--bg-tertiary); border-radius: 4px; overflow: hidden;">
                <div style="width: ${(count / total) * 100}%; height: 100%; background: var(--stride-${category.toLowerCase().replace(' ', '-')}); transition: width 0.3s;"></div>
            </div>
            <div style="width: 30px; text-align: right; font-size: 0.75rem; color: var(--text-muted);">${count}</div>
        </div>
    `).join('');
}

async function updateRiskMatrix() {
    // Fetch threats and calculate risk matrix
    try {
        const res = await fetch(`${API_BASE}/threats?project_id=default-project`);
        if (res.ok) {
            const data = await res.json();
            const threats = data.threats || [];

            if (threats.length === 0) {
                // Show empty state
                const matrixContainer = document.getElementById('risk-matrix');
                if (matrixContainer) {
                    matrixContainer.innerHTML = `
                        <div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-secondary); padding: 2rem;">
                            <div style="text-align: center;">
                                <div style="font-size: 2rem; margin-bottom: 0.5rem;">📊</div>
                                <div>No threats available</div>
                                <div style="font-size: 0.875rem; margin-top: 0.5rem; color: var(--text-tertiary);">
                                    Add threats to see risk distribution
                                </div>
                            </div>
                        </div>
                    `;
                }
                return;
            }

            // Calculate risk distribution
            const riskMatrix = {
                'Rare': { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0 },
                'Unlikely': { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0 },
                'Possible': { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0 },
                'Likely': { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0 },
                'Certain': { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0 }
            };

            threats.forEach(threat => {
                const likelihood = threat.likelihood || 'Possible';
                let riskLevel = threat.risk_level || 'Medium';

                // Map risk_score to risk level if needed
                if (threat.risk_score !== undefined && typeof threat.risk_score === 'number') {
                    if (threat.risk_score >= 0.8) riskLevel = 'Critical';
                    else if (threat.risk_score >= 0.6) riskLevel = 'High';
                    else if (threat.risk_score >= 0.4) riskLevel = 'Medium';
                    else if (threat.risk_score >= 0.2) riskLevel = 'Low';
                    else riskLevel = 'Info';
                }

                if (riskMatrix[likelihood] && riskMatrix[likelihood][riskLevel] !== undefined) {
                    riskMatrix[likelihood][riskLevel]++;
                }
            });

            // Update cells with counts
            const matrixContainer = document.getElementById('risk-matrix');
            if (matrixContainer) {
                Object.keys(riskMatrix).forEach(likelihood => {
                    Object.keys(riskMatrix[likelihood]).forEach(riskLevel => {
                        const count = riskMatrix[likelihood][riskLevel];
                        const cell = matrixContainer.querySelector(`[data-likelihood="${likelihood}"][data-risk="${riskLevel}"]`);
                        if (cell) {
                            cell.textContent = count > 0 ? count : '';
                            cell.style.opacity = count > 0 ? '1' : '0.3';
                        }
                    });
                });
            }
        }
    } catch (err) {
        console.error('Failed to update risk matrix:', err);
    }
}

async function updateRecentThreats() {
    try {
        const res = await fetch(`${API_BASE}/threats?project_id=default-project&limit=5&order_by=created_at&order=desc`);
        const container = document.getElementById('recent-threats');
        if (!container) return;

        if (res.ok) {
            const data = await res.json();
            const threats = data.threats || [];

            if (threats.length === 0) {
                container.innerHTML = `
                    <div style="color: var(--text-muted); font-size: 0.875rem; padding: 1rem; text-align: center;">
                        <div style="font-size: 2rem; margin-bottom: 0.5rem;">⚠️</div>
                        <div>No threats detected yet</div>
                        <div style="font-size: 0.75rem; margin-top: 0.5rem; color: var(--text-tertiary);">
                            Add threats to see them here
                        </div>
                    </div>
                `;
                return;
            }

            container.innerHTML = threats.map(threat => `
                <div style="padding: 12px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 12px;">
                    <div style="font-size: 1.5rem;">⚠️</div>
                    <div style="flex: 1;">
                        <div style="font-weight: 600; font-size: 0.875rem; color: var(--text-primary);">${threat.name || threat.title || 'Unknown Threat'}</div>
                        <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 4px;">
                            ${threat.category || 'STRIDE'} • ${threat.risk_level || 'Medium'} Risk
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = `
                <div style="color: var(--text-muted); font-size: 0.875rem;">Failed to load threats</div>
            `;
        }
    } catch (err) {
        console.error('Failed to update recent threats:', err);
        const container = document.getElementById('recent-threats');
        if (container) {
            container.innerHTML = `
                <div style="color: var(--text-muted); font-size: 0.875rem;">Error loading threats</div>
            `;
        }
    }
}

async function updateSecurityPosture() {
    try {
        // Fetch controls and threats to calculate security posture
        const [controlsRes, threatsRes] = await Promise.all([
            fetch(`${API_BASE}/controls?project_id=default-project`),
            fetch(`${API_BASE}/threats?project_id=default-project&limit=1000`)
        ]);

        const container = document.getElementById('security-posture');
        if (!container) return;

        if (controlsRes.ok && threatsRes.ok) {
            const controlsData = await controlsRes.json();
            const threatsData = await threatsRes.json();

            const controls = controlsData.controls || [];
            const threats = threatsData.threats || [];

            // Calculate security grade based on control coverage
            const totalThreats = threats.length;
            const threatsWithControls = threats.filter(t => {
                const threatControls = t.controls || [];
                return threatControls.length > 0;
            }).length;

            const coverage = totalThreats > 0 ? (threatsWithControls / totalThreats) * 100 : 100;

            // Determine grade
            let grade = 'A';
            let gradeColor = '#10b981'; // green
            if (coverage < 50) {
                grade = 'D';
                gradeColor = '#ef4444'; // red
            } else if (coverage < 70) {
                grade = 'C';
                gradeColor = '#D97706'; // orange
            } else if (coverage < 85) {
                grade = 'B';
                gradeColor = '#3b82f6'; // blue
            }

            container.innerHTML = `
                <div style="text-align: center; padding: 1rem;">
                    <div style="font-size: 3rem; font-weight: bold; color: ${gradeColor}; margin-bottom: 0.5rem;">${grade}</div>
                    <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 1rem;">
                        Security Grade
                    </div>
                    <div style="background: var(--bg-secondary); border-radius: 8px; padding: 0.5rem; margin-top: 1rem;">
                        <div style="font-size: 0.75rem; color: var(--text-tertiary); margin-bottom: 0.25rem;">Control Coverage</div>
                        <div style="background: var(--bg-primary); border-radius: 4px; height: 8px; overflow: hidden;">
                            <div style="background: ${gradeColor}; height: 100%; width: ${coverage}%; transition: width 0.3s;"></div>
                        </div>
                        <div style="font-size: 0.875rem; color: var(--text-primary); margin-top: 0.5rem;">
                            ${coverage.toFixed(1)}% (${threatsWithControls}/${totalThreats} threats covered)
                        </div>
                    </div>
                </div>
            `;
        } else {
            container.innerHTML = `
                <div style="color: var(--text-muted); font-size: 0.875rem; padding: 1rem; text-align: center;">
                    Failed to load security posture
                </div>
            `;
        }
    } catch (err) {
        console.error('Failed to update security posture:', err);
        const container = document.getElementById('security-posture');
        if (container) {
            container.innerHTML = `
                <div style="color: var(--text-muted); font-size: 0.875rem; padding: 1rem; text-align: center;">
                    Error loading security posture
                </div>
            `;
        }
    }
}

async function updateEvidenceSection() {
    try {
        const res = await fetch(`${API_BASE}/evidence?project_id=default-project&limit=5&order_by=created_at&order=desc`);
        const container = document.getElementById('evidence-section');
        if (!container) return;

        if (res.ok) {
            const data = await res.json();
            const evidence = data.evidence || [];

            if (evidence.length === 0) {
                container.innerHTML = `
                    <div style="color: var(--text-muted); font-size: 0.875rem; padding: 1rem; text-align: center;">
                        <div style="font-size: 2rem; margin-bottom: 0.5rem;">📋</div>
                        <div>No evidence recorded yet</div>
                    </div>
                `;
                return;
            }

            container.innerHTML = evidence.map(ev => `
                <div style="padding: 12px; border-bottom: 1px solid var(--border-color);">
                    <div style="font-weight: 600; font-size: 0.875rem; color: var(--text-primary); margin-bottom: 4px;">
                        ${ev.title || ev.name || 'Evidence'}
                    </div>
                    <div style="font-size: 0.75rem; color: var(--text-secondary);">
                        ${ev.description ? ev.description.substring(0, 100) + (ev.description.length > 100 ? '...' : '') : 'No description'}
                    </div>
                    ${ev.source_url ? `
                        <a href="${ev.source_url}" target="_blank" style="font-size: 0.75rem; color: var(--primary-color); margin-top: 4px; display: inline-block;">
                            View Source →
                        </a>
                    ` : ''}
                </div>
            `).join('');
        } else {
            container.innerHTML = `
                <div style="color: var(--text-muted); font-size: 0.875rem; padding: 1rem;">
                    Failed to load evidence
                </div>
            `;
        }
    } catch (err) {
        console.error('Failed to update evidence section:', err);
        const container = document.getElementById('evidence-section');
        if (container) {
            container.innerHTML = `
                <div style="color: var(--text-muted); font-size: 0.875rem; padding: 1rem;">
                    Error loading evidence
                </div>
            `;
        }
    }
}

// ============== API Functions ==============
// Open Gather Intel Modal
function gatherIntel() {
    // Check if task is already running
    const taskId = 'gather-intel';
    if (AppState.backgroundTasks.has(taskId)) {
        const task = AppState.backgroundTasks.get(taskId);
        showNotification('info', 'Intel Gathering', 'Intel gathering is already running in the background. You can switch pages and it will continue.');
        return;
    }

    // Open modal
    const modal = document.getElementById('gather-intel-modal');
    if (modal) {
        modal.classList.add('active');
        // Reset input
        const input = document.getElementById('intel-max-items');
        if (input) input.value = '50';
    }
}

// Execute Gather Intel (called from modal)
async function startGatherIntel() {
    const input = document.getElementById('intel-max-items');
    
    // 1. Check if input element exists
    if (!input) {
        showNotification('error', 'System Error', 'Input field not found.');
        return;
    }

    // 2. data access (no default fallback)
    const rawValue = input.value;
    const maxItemsStr = rawValue ? rawValue.trim() : '';
    
    // 3. Strict validation: Must be non-empty and numeric
    if (!maxItemsStr || !/^\d+$/.test(maxItemsStr)) {
        showNotification('warning', 'Invalid Input', 'Please enter a valid number. Operation cancelled.');
        return;
    }

    const itemsCount = parseInt(maxItemsStr, 10);
    
    // 4. Range validation
    if (isNaN(itemsCount) || itemsCount <= 0 || itemsCount > 100) {
        showNotification('warning', 'Invalid Range', 'Please enter a number between 1 and 100.');
        return;
    }

    closeModal('gather-intel-modal');

    AppState.loading.intel = true;
    showNotification('info', 'Gathering Intel',
        `Starting intelligence collection (max ${itemsCount} items per source)... This will continue in the background.`);

    // Generate a unique task ID
    const taskId = 'intel-gather-' + Date.now();

    // Create task promise - no AbortController, let it run in background
    const taskPromise = (async () => {
        const res = await fetch(`${API_BASE}/intel/gather`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                max_items: itemsCount,
                enable_cve: true,
                enable_rss: true,
                enable_web_search: true,
                enable_github: false,  // GitHub requires token
                use_ai: false  // AI processing can be slow
            })
        });
        return res;
    })();

    // Track task in background tasks
    AppState.backgroundTasks.set(taskId, {
        type: 'intel-gathering',
        status: 'running',
        startTime: Date.now(),
        promise: taskPromise
    });

    try {
        const res = await taskPromise;

        if (res.ok) {
            const data = await res.json();
            const collected = data.items_collected || 0;
            const relevant = data.items_relevant || 0;
            const threats = data.threats_generated || 0;

            // Update task status
            AppState.backgroundTasks.set(taskId, {
                ...AppState.backgroundTasks.get(taskId),
                status: 'completed',
                result: data
            });

            showNotification('success', 'Intel Gathered',
                `Collected ${collected} items, ${relevant} relevant, generated ${threats} threats`);

            // Refresh data globally
            await loadInitialData(); // Refresh data unconditionally
        } else {
            const errorData = await res.json().catch(() => ({}));
            const errorMsg = errorData.error || 'Intel gathering failed';
            const errorType = errorData.error_type || '';
            throw new Error(errorType ? `${errorType}: ${errorMsg}` : errorMsg);
        }
    } catch (err) {
        console.error('Intel error:', err);
        const errorMsg = err.message || 'Failed to gather intelligence';

        // Update task status
        AppState.backgroundTasks.set(taskId, {
            ...AppState.backgroundTasks.get(taskId),
            status: 'failed',
            error: errorMsg
        });

        // Show notification
        if (AppState.activeTab === 'intel' || err.message.includes('connection')) {
            showNotification('error', 'Intel Error', errorMsg);
        } else {
            showNotification('error', 'Intel Error', 'Intel gathering failed. Check the Intel tab for details.');
        }
    } finally {
        AppState.loading.intel = false;

        // Clean up task after a delay
        setTimeout(() => {
            if (AppState.backgroundTasks.has(taskId)) {
                const task = AppState.backgroundTasks.get(taskId);
                if (task.status === 'completed' || task.status === 'failed') {
                    AppState.backgroundTasks.delete(taskId);
                }
            }
        }, 60000); // Keep for 1 minute
    }
}

async function runAttackSimulation(targetId, attackType) {
    if (AppState.loading.attack) return;

    AppState.loading.attack = true;
    showNotification('info', 'Running Attack', `Starting ${attackType} simulation...`);

    try {
        const res = await fetch(`${API_BASE}/attack/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_id: targetId, attack_type: attackType })
        });

        if (res.ok) {
            const data = await res.json();
            showNotification(
                data.success ? 'warning' : 'success',
                'Attack Complete',
                data.success ? 'Vulnerability confirmed!' : 'No vulnerability found'
            );

            // Add evidence to canvas
            if (data.evidence) {
                createCanvasNode({
                    cardType: 'evidence',
                    name: `${attackType} Result`,
                    ...data.evidence
                }, 400, 300);
            }
        }
    } catch (err) {
        console.error('Attack error:', err);
        showNotification('error', 'Attack Error', 'Simulation failed');
    } finally {
        AppState.loading.attack = false;
    }
}



function renderMarkdown(content) {
    const viewer = document.getElementById('report-viewer');
    if (!viewer) return;

    // Simple markdown rendering (can be enhanced with a library like marked.js)
    let html = content
        .replace(/^# (.*$)/gim, '<h1>$1</h1>')
        .replace(/^## (.*$)/gim, '<h2>$1</h2>')
        .replace(/^### (.*$)/gim, '<h3>$1</h3>')
        .replace(/^#### (.*$)/gim, '<h4>$1</h4>')
        .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/gim, '<em>$1</em>')
        .replace(/^\- (.*$)/gim, '<li>$1</li>')
        .replace(/^\d+\. (.*$)/gim, '<li>$1</li>')
        .replace(/\n\n/gim, '</p><p>')
        .replace(/^<p>/gim, '<p>')
        .replace(/<\/p>$/gim, '</p>');

    // Wrap lists
    html = html.replace(/(<li>.*<\/li>)/gim, '<ul>$1</ul>');

    // Handle tables (basic)
    html = html.replace(/\|(.*)\|/gim, '<tr><td>' + '$1'.split('|').map(cell => cell.trim()).join('</td><td>') + '</td></tr>');

    viewer.innerHTML = '<p>' + html + '</p>';
}

function toggleReportEdit() {
    const viewer = document.getElementById('report-viewer');
    const editor = document.getElementById('report-editor');
    const editBtn = document.getElementById('edit-report-btn');
    const saveBtn = document.getElementById('save-report-btn');

    if (viewer.style.display !== 'none') {
        // Switch to edit mode
        viewer.style.display = 'none';
        editor.style.display = 'block';
        editor.value = window.currentReportContent;
        editBtn.style.display = 'none';
        saveBtn.style.display = 'inline-block';
        editor.focus();
    } else {
        // Switch to view mode
        viewer.style.display = 'block';
        editor.style.display = 'none';
        window.currentReportContent = editor.value;
        renderMarkdown(window.currentReportContent);
        editBtn.style.display = 'inline-block';
        saveBtn.style.display = 'none';
    }
}

function saveReport() {
    const editor = document.getElementById('report-editor');
    if (editor) {
        window.currentReportContent = editor.value;
        toggleReportEdit();
        showNotification('success', 'Report Saved', 'Changes saved locally');
    }
}

function downloadReport() {
    const content = window.currentReportContent || '';
    const blob = new Blob([content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-threat-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    showNotification('success', 'Report Downloaded', 'Markdown file downloaded');
}

function copyReport() {
    const content = window.currentReportContent || '';
    navigator.clipboard.writeText(content).then(() => {
        showNotification('success', 'Report Copied', 'Report content copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showNotification('error', 'Copy Failed', 'Failed to copy report');
    });
}

function closeReportModal() {
    const modal = document.getElementById('report-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

async function discoverMCPConfig(config) {
    showNotification('info', 'Discovering Assets', 'Analyzing MCP configuration...');

    try {
        const res = await fetch(`${API_BASE}/mcp/discover`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config })
        });

        if (res.ok) {
            const data = await res.json();

            // Add discovered assets to canvas
            let x = 100, y = 100;
            data.assets?.forEach((asset, i) => {
                createCanvasNode({
                    cardType: 'asset',
                    ...asset
                }, x + (i % 3) * 220, y + Math.floor(i / 3) * 150);
            });

            // Add auto-generated threats
            data.threats?.forEach((threat, i) => {
                createCanvasNode({
                    cardType: 'threat',
                    ...threat
                }, 600 + (i % 2) * 220, y + Math.floor(i / 2) * 150);
            });

            showNotification('success', 'Discovery Complete',
                `Found ${data.assets?.length || 0} assets, ${data.threats?.length || 0} threats`);
        }
    } catch (err) {
        console.error('Discovery error:', err);
        showNotification('error', 'Discovery Error', 'Failed to analyze configuration');
    }
}

// ============== Intel Items ==============
let intelCurrentPage = 0;
const intelPageSize = 20;

async function loadIntelItems(page = 0) {
    const sourceFilter = document.getElementById('intel-source-filter')?.value || '';
    const relevanceFilter = document.getElementById('intel-relevance-filter')?.value || '';

    const params = new URLSearchParams({
        limit: intelPageSize,
        offset: page * intelPageSize
    });

    if (sourceFilter) {
        params.append('source_type', sourceFilter);
    }

    if (relevanceFilter) {
        params.append('is_relevant', relevanceFilter);
    }

    try {
        const res = await fetch(`${API_BASE}/intel/items?${params}`);
        if (!res.ok) throw new Error('Failed to load intel items');

        const data = await res.json();
        renderIntelItems(data.items || [], data.total || 0);
        // Update stats with total counts from API
        await updateIntelStats(data.total || 0, data.items || [], {
            total_relevant: data.total_relevant,
            total_processed: data.total_processed,
            total_with_summary: data.total_with_summary
        });
        intelCurrentPage = page;
        renderIntelPagination(data.total || 0);
    } catch (err) {
        console.error('Failed to load intel items:', err);
        document.getElementById('intel-list').innerHTML = `
            <div class="intel-error">
                <div class="intel-error-icon">⚠️</div>
                <div class="intel-error-message">Failed to load intelligence items</div>
                <button class="btn btn-secondary" onclick="loadIntelItems()">Retry</button>
            </div>
        `;
    }
}

function renderIntelItems(items, total) {
    const container = document.getElementById('intel-list');

    if (!items || items.length === 0) {
        container.innerHTML = `
            <div class="intel-empty">
                <div class="intel-empty-icon">📡</div>
                <div class="intel-empty-title">No intelligence items found</div>
                <div class="intel-empty-message">Start gathering intelligence to see items here</div>
                <button class="btn btn-primary" onclick="gatherIntel()">📡 Gather Intel</button>
            </div>
        `;
        return;
    }

    container.innerHTML = items.map(item => {
        const sourceIcon = getSourceIcon(item.source_type);
        const relevanceBadge = item.is_relevant
            ? '<span class="intel-badge intel-badge-relevant">Relevant</span>'
            : '<span class="intel-badge intel-badge-neutral">Neutral</span>';

        const score = item.ai_relevance_score ?
            `<div class="intel-score">Score: ${item.ai_relevance_score.toFixed(1)}</div>` : '';

        const date = item.created_at ? new Date(item.created_at).toLocaleDateString() : '';

        return `
            <div class="intel-card" onclick="openIntelSource('${item.url || ''}')">
                <div class="intel-card-header">
                    <div class="intel-card-source">
                        <span class="intel-source-icon">${sourceIcon}</span>
                        <span class="intel-source-name">${item.source_type || 'Unknown'}</span>
                        ${relevanceBadge}
                    </div>
                    <div class="intel-card-meta">
                        ${score}
                        <span class="intel-date">${date}</span>
                    </div>
                </div>
                <div class="intel-card-title">${item.title || 'Untitled'}</div>
                <div class="intel-card-content">${truncateText(item.content || item.ai_summary || '', 200)}</div>
                <div class="intel-card-footer">
                    ${item.url ? `<a href="${item.url}" target="_blank" class="intel-link" onclick="event.stopPropagation()">🔗 View Source</a>` : ''}
                    ${item.author ? `<span class="intel-author">By ${item.author}</span>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function getSourceIcon(sourceType) {
    const icons = {
        'web_search': '🌐',
        'cve': '🔴',
        'rss': '📰',
        'github': '💻',
        'twitter': '🐦',
        'hacker_news': '📰'
    };
    return icons[sourceType] || '📡';
}

function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

async function updateIntelStats(total, currentPageItems = [], statsData = null) {
    // Update total count
    const totalEl = document.getElementById('intel-total-count');
    const relevantEl = document.getElementById('intel-relevant-count');
    const summaryEl = document.getElementById('intel-with-summary-count');

    if (totalEl) totalEl.textContent = total;

    // Always fetch stats from API endpoint for accurate counts
    try {
        const statsRes = await fetch(`${API_BASE}/intel/stats`);
        if (statsRes.ok) {
            const stats = await statsRes.json();
            if (relevantEl) relevantEl.textContent = stats.total_relevant || 0;
            if (summaryEl) summaryEl.textContent = stats.total_with_summary || 0;
            return;
        }
    } catch (err) {
        console.error('Failed to fetch intel stats:', err);
    }

    // Fallback: use statsData from response if available
    if (statsData) {
        if (relevantEl) relevantEl.textContent = statsData.total_relevant || 0;
        if (summaryEl) summaryEl.textContent = statsData.total_with_summary || 0;
        return;
    }

    // Final fallback: count from current page items
    const relevant = currentPageItems.filter(i => i.is_relevant).length;
    const withSummary = currentPageItems.filter(i => i.ai_summary).length;

    if (relevantEl) relevantEl.textContent = relevant;
    if (summaryEl) summaryEl.textContent = withSummary;
}

function renderIntelPagination(total) {
    const totalPages = Math.ceil(total / intelPageSize);
    const container = document.getElementById('intel-pagination');

    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '<div class="intel-pagination-controls">';

    // Previous button
    html += `<button class="intel-pagination-btn" ${intelCurrentPage === 0 ? 'disabled' : ''} onclick="loadIntelItems(${intelCurrentPage - 1})">← Previous</button>`;

    // Page numbers
    for (let i = 0; i < totalPages; i++) {
        if (i === 0 || i === totalPages - 1 || (i >= intelCurrentPage - 2 && i <= intelCurrentPage + 2)) {
            html += `<button class="intel-pagination-btn ${i === intelCurrentPage ? 'active' : ''}" onclick="loadIntelItems(${i})">${i + 1}</button>`;
        } else if (i === intelCurrentPage - 3 || i === intelCurrentPage + 3) {
            html += `<span class="intel-pagination-ellipsis">...</span>`;
        }
    }

    // Next button
    html += `<button class="intel-pagination-btn" ${intelCurrentPage >= totalPages - 1 ? 'disabled' : ''} onclick="loadIntelItems(${intelCurrentPage + 1})">Next →</button>`;

    html += '</div>';
    container.innerHTML = html;
}

function openIntelSource(url) {
    if (url) {
        window.open(url, '_blank');
    }
}

// Setup filter change handlers
document.addEventListener('DOMContentLoaded', () => {
    const sourceFilter = document.getElementById('intel-source-filter');
    const relevanceFilter = document.getElementById('intel-relevance-filter');

    if (sourceFilter) {
        sourceFilter.addEventListener('change', () => loadIntelItems(0));
    }

    if (relevanceFilter) {
        relevanceFilter.addEventListener('change', () => loadIntelItems(0));
    }
});

// ============== Knowledge Graph ==============
// ============== Knowledge Graph ==============
window.isKGGenerating = false;

async function loadKnowledgeGraph() {
    try {
        // Use the intel KG data endpoint (which has in-memory cache + file persistence)
        const res = await fetch(`${API_BASE}/intel/kg/data?limit=0&use_ai=false&use_litellm=false`);
        if (res.ok) {
            const data = await res.json();
            if (data && data.nodes && data.nodes.length > 0) {
                renderKnowledgeGraph(data);
            } else {
                // No data yet, that's ok — user can generate from KG tab
                console.log('No KG data available yet.');
            }
        }
    } catch (err) {
        // Silently fail on startup — KG tab has its own load/generate buttons
        console.warn('KG auto-load skipped:', err.message);
    }
}

async function generateKG() {
    try {
        showNotification('info', 'Generating KG', 'Creating knowledge graph from threat model...');
        const res = await fetch(`${API_BASE}/kg/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ use_ai: true, use_litellm: true })
        });

        if (res.ok) {
            const data = await res.json();
            showNotification('success', 'KG Generated', `Created graph with ${data.stats?.nodes || 0} nodes`);
            await loadKnowledgeGraph();
        } else {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to generate KG');
        }
    } catch (err) {
        console.error('KG generation error:', err);
        showNotification('error', 'KG Error', err.message || 'Failed to generate knowledge graph');
    }
}

// updateKnowledgeGraph is defined below (single definition near renderKnowledgeGraph)

async function streamGenerateKG(limit = 0, forceAll = false) {
    if (window.isKGGenerating) {
        console.log("KG generation already in progress (stream)...");
        return;
    }
    window.isKGGenerating = true;

    // Limit UI removed, so no need to disable/enable inputs

    const canvas = document.getElementById('kg-canvas');
    if (!canvas) {
        window.isKGGenerating = false;
        return;
    }

    // Show loading overlay if empty
    if (!window.kgNodes || window.kgNodes.length === 0) {
        const modeText = forceAll ? 'Regenerating from ALL intelligence items...' : 'Analyzing intelligence data with AI...';
        canvas.innerHTML = `
            <div class="kg-loading">
                <div class="spinner"></div>
                <div class="loading-text">${modeText}</div>
                <div class="loading-subtext">This may take a moment. Real-time updates will appear below.</div>
            </div>
        `;
    }

    const statsEl = document.getElementById('kg-stats');
    if (statsEl) statsEl.innerText = `Connecting to AI stream...`;

    try {
        const response = await fetch(`${API_BASE}/intel/kg/generate_stream`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ use_ai: true, use_litellm: true, limit: 0, require_summary: false, force_all: forceAll })
        });

        if (!response.ok) {
            const err = await response.json();
            if (response.status === 429) {
                showNotification('warning', 'Busy', err.message);
                return;
            }
            throw new Error(err.message || 'Failed to start generation');
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        // Track the latest graph data from the stream
        let latestGraphData = null;

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n'); // Split by single newline
            buffer = lines.pop(); // Keep incomplete line

            for (const line of lines) {
                if (!line.trim()) continue;

                if (line.startsWith('data: ')) {
                    const jsonStr = line.slice(6);
                    if (!jsonStr) continue;
                    try {
                        const update = JSON.parse(jsonStr);

                        if (update.status === 'error') {
                            throw new Error(update.message);
                        }

                        if (update.status === 'start') {
                            if (statsEl) statsEl.innerText = `Starting analysis of ${update.total} items...`;
                        }

                        // Handle 'complete' with no graph = all items already processed
                        if (update.status === 'complete' && !update.graph) {
                            const msg = update.message || 'All intelligence items have been processed.';
                            showNotification('info', 'KG Up to Date', msg);
                            if (statsEl) statsEl.innerText = msg;
                            // Load existing graph for display
                            try {
                                const existingRes = await fetch(`${API_BASE}/intel/kg/data?limit=0&use_ai=false&use_litellm=false`);
                                if (existingRes.ok) {
                                    const existingData = await existingRes.json();
                                    if (existingData && existingData.nodes && existingData.nodes.length > 0) {
                                        renderKnowledgeGraph(existingData);
                                        if (statsEl) statsEl.innerText = `${msg} (${existingData.nodes.length} nodes, ${existingData.edges?.length || 0} edges)`;
                                    }
                                }
                            } catch (loadErr) {
                                console.warn('Failed to load existing KG after complete:', loadErr);
                            }
                        }

                        if (update.graph) {
                            latestGraphData = update.graph;
                            updateKnowledgeGraph(update.graph);

                            if (update.status === 'progress') {
                                if (statsEl) statsEl.innerText = `Analyzed ${update.current}/${update.total}: ${update.item_title.substring(0, 30)}...`;
                            } else if (update.status === 'complete') {
                                if (statsEl) statsEl.innerText = `Completed analysis of ${update.total} items.`;
                                showNotification('success', 'KG Complete', `Finished processing ${update.total} items.`);
                            }
                        }
                    } catch (e) {
                        console.error('Error parsing stream:', e);
                    }
                }
            }
        }

        // After stream completes, ensure the final graph is rendered
        if (latestGraphData && latestGraphData.nodes && latestGraphData.nodes.length > 0) {
            console.log(`Stream complete. Rendering final graph: ${latestGraphData.nodes.length} nodes, ${latestGraphData.edges?.length || 0} edges`);
            renderKnowledgeGraph(latestGraphData);
        } else {
            // Fallback: reload from API (the graph was saved during streaming)
            try {
                const finalRes = await fetch(`${API_BASE}/intel/kg/data?limit=0&use_ai=false&use_litellm=false`);
                if (finalRes.ok) {
                    const finalData = await finalRes.json();
                    if (finalData && finalData.nodes && finalData.nodes.length > 0) {
                        console.log(`Loaded saved graph: ${finalData.nodes.length} nodes`);
                        renderKnowledgeGraph(finalData);
                    }
                }
            } catch (loadErr) {
                console.error('Failed to load saved graph:', loadErr);
            }
        }

    } catch (e) {
        console.error("Stream error:", e);
        showNotification('error', 'Generation Failed', e.message);
        window.isKGGenerating = false;
    } finally {
        window.isKGGenerating = false;
    }
}

async function generateKGFromIntel(forceAll = false) {
    try {
        if (window.isKGGenerating) {
            // Safety: auto-reset if stuck for more than 5 minutes
            const stuckTime = Date.now() - (window.kgGenStartTime || 0);
            if (stuckTime > 5 * 60 * 1000) {
                console.warn('[KG] Resetting stuck isKGGenerating flag');
                window.isKGGenerating = false;
            } else {
                showNotification('warning', 'Busy', 'Generation already in progress');
                return;
            }
        }

        if (forceAll) {
            if (!confirm('This will regenerate the knowledge graph from ALL intel items (ignoring previously processed items). This may take several minutes. Continue?')) {
                return;
            }
        }

        // Track start time for stuck detection
        window.kgGenStartTime = Date.now();

        // Force limit=0 (all items)
        const limit = 0;

        const modeLabel = forceAll ? 'Regenerate All (from scratch)' : 'Process New Items';
        showNotification('info', 'Generating KG', `Starting: ${modeLabel}...`);
        await streamGenerateKG(limit, forceAll);

    } catch (err) {
        console.error('Intel KG generation error:', err);
        showNotification('error', 'KG Error', err.message || 'Failed to generate knowledge graph from intel');
    }
}

async function uploadToNeo4j() {
    try {
        showNotification('info', 'Uploading to Neo4j', 'Uploading knowledge graph to Neo4j...');
        const res = await fetch(`${API_BASE}/neo4j/upload`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (res.ok) {
            const data = await res.json();
            showNotification('success', 'Upload Complete', data.message || 'Knowledge graph uploaded to Neo4j');
        } else {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to upload to Neo4j');
        }
    } catch (err) {
        console.error('Neo4j upload error:', err);
        showNotification('error', 'Upload Error', err.message || 'Failed to upload to Neo4j');
    }
}

function renderKnowledgeGraph(data) {
    const container = document.getElementById('kg-canvas');
    if (!container) return;

    // Hide empty state
    const emptyState = container.querySelector('.kg-empty-state');
    if (emptyState) {
        emptyState.style.display = 'none';
    }

    // Check if we have data
    const visData = data.vis_data || data;
    if (!visData || !visData.nodes || visData.nodes.length === 0) {
        if (emptyState) {
            emptyState.style.display = 'flex';
            emptyState.innerHTML = `
                <div style="text-align: center; max-width: 600px;">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">📊</div>
                    <div style="font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem;">No Knowledge Graph Data</div>
                    <div style="font-size: 0.875rem; margin-bottom: 1.5rem; color: var(--text-secondary);">
                        Generate a knowledge graph from threats, assets, or intelligence items
                    </div>
                    <button class="btn btn-primary" onclick="generateKG()">🔄 Generate KG</button>
                </div>
            `;
        }
        return;
    }

    // Clear container for new graph
    container.innerHTML = '';

    // Use vis.js to render
    const nodes = new vis.DataSet((visData.nodes || []).map(n => ({
        id: n.id || n.node_id,
        label: n.label || n.name || n.id || 'Unknown',
        color: getNodeColor(n.type || n.node_type),
        shape: 'dot',
        size: n.size || 20,
        title: n.title || `${n.label || n.name || n.id}\nType: ${n.type || n.node_type || 'Unknown'}`,
        font: { color: '#ffffff', size: 14 },
        // Store original data for click handler
        _originalData: n
    })));

    const edges = new vis.DataSet((visData.edges || []).map(e => ({
        from: e.source || e.from,
        to: e.target || e.to,
        label: e.relation || e.label || '',
        arrows: 'to',
        color: { color: '#6366f1', highlight: '#8b5cf6' },
        font: { color: '#94a3b8', size: 10, align: 'middle' },
        // Store original data for click handler
        _originalData: e
    })));

    // Update counts
    // Update counts if elements exist
    const nodeCountEl = document.getElementById('kg-node-count');
    if (nodeCountEl) nodeCountEl.textContent = nodes.length;

    const edgeCountEl = document.getElementById('kg-edge-count');
    if (edgeCountEl) edgeCountEl.textContent = edges.length;

    const network = new vis.Network(container, { nodes, edges }, {
        physics: {
            enabled: true,
            stabilization: {
                iterations: 150,
                fit: true,
                updateInterval: 25
            },
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.2,
                springLength: 150,
                springConstant: 0.05,
                damping: 0.4,
                avoidOverlap: 1.0
            },
            maxVelocity: 3,
            minVelocity: 0.05,
            solver: 'barnesHut',
            timestep: 0.35
        },
        nodes: {
            font: { color: '#ffffff', size: 14 },
            borderWidth: 2,
            shadow: true,
            margin: 10
        },
        edges: {
            color: { color: '#6366f1', highlight: '#8b5cf6' },
            font: { color: '#94a3b8', size: 10, align: 'middle' },
            arrows: { to: { enabled: true, scaleFactor: 1.2 } },
            smooth: { type: 'continuous', roundness: 0.5 }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            zoomView: true,
            dragView: true,
            dragNodes: true
        }
    });

    // Stop physics after stabilization to prevent nodes from moving
    let kgStabilizationComplete = false;
    let kgStabilizationTimeout = null;

    network.once('stabilizationEnd', () => {
        kgStabilizationComplete = true;
        if (kgStabilizationTimeout) {
            clearTimeout(kgStabilizationTimeout);
        }
        network.setOptions({ physics: { enabled: false } });
        setTimeout(() => {
            network.setOptions({ physics: { enabled: false } });
        }, 100);
    });

    // Force disable after timeout
    kgStabilizationTimeout = setTimeout(() => {
        if (!kgStabilizationComplete) {
            kgStabilizationComplete = true;
            network.setOptions({ physics: { enabled: false } });
        }
    }, 5000);

    // Prevent physics from re-enabling on interaction
    network.on('dragStart', () => {
        if (kgStabilizationComplete) {
            network.setOptions({ physics: { enabled: false } });
        }
    });

    network.on('dragEnd', () => {
        if (kgStabilizationComplete) {
            network.setOptions({ physics: { enabled: false } });
        }
    });

    // Handle node click - show details panel
    network.on('click', (params) => {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            if (node && node._originalData) {
                showNodeDetails(node._originalData);
            }
        } else if (params.edges.length > 0) {
            const edge = edges.get(params.edges[0]);
            if (edge && edge._originalData) {
                showEdgeDetails(edge._originalData);
            }
        } else {
            // Click on empty space - close details
            closeNodeDetails();
        }
    });

    // Add double-click handler for opening all source URLs
    network.on('doubleClick', (params) => {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            if (node && node._originalData) {
                const nodeData = node._originalData;
                const properties = nodeData.properties || {};
                const sourceUrls = properties.source_urls || [];

                // Open all source URLs
                let openedCount = 0;
                sourceUrls.forEach(url => {
                    if (url) {
                        window.open(url, '_blank');
                        openedCount++;
                    }
                });

                if (openedCount > 0) {
                    showNotification('success', 'Opened Sources', `Opened ${openedCount} source URL(s) for: ${node.label}`);
                } else {
                    showNotification('info', 'No Sources', `No source URLs available for: ${node.label}`);
                }
            }
        }
    });

    // Store globally for updates
    window.kgNodes = nodes;
    window.kgEdges = edges;
    window.kgNetwork = network;
}

function updateKnowledgeGraph(data) {
    if (!window.kgNodes || !window.kgEdges) {
        renderKnowledgeGraph(data);
        return;
    }

    if (data.nodes) {
        const newNodes = data.nodes.map(n => ({
            id: n.id || n.node_id,
            label: n.label || n.name || n.id || 'Unknown',
            title: n.title || n.label,
            group: n.group || n.node_type || 'Entity',
            color: getNodeColor(n.type || n.node_type),
            shape: 'dot',
            size: n.size || 20,
            font: { color: '#ffffff', size: 14 },
            _originalData: n,
            ...n
        }));
        window.kgNodes.update(newNodes);
    }

    if (data.edges) {
        const newEdges = data.edges.map(e => ({
            id: e.id || `${e.source}-${e.target}-${e.relationship}`,
            from: e.source || e.from,
            to: e.target || e.to,
            label: e.relation || e.label || '',
            arrows: 'to',
            color: { color: '#6366f1', highlight: '#8b5cf6' },
            font: { color: '#94a3b8', size: 10, align: 'middle' },
            _originalData: e,
            ...e
        }));
        window.kgEdges.update(newEdges);
    }

    // Update counts (with null checks for DOM elements)
    const nodeCountEl2 = document.getElementById('kg-node-count');
    if (window.kgNodes && nodeCountEl2) nodeCountEl2.textContent = window.kgNodes.length;
    const edgeCountEl2 = document.getElementById('kg-edge-count');
    if (window.kgEdges && edgeCountEl2) edgeCountEl2.textContent = window.kgEdges.length;
}

function getNodeColor(type) {
    const colors = {
        threat: '#ef4444',
        asset: '#3b82f6',
        control: '#10b981',
        evidence: '#D97706',
        'Threat': '#ef4444',
        'Vulnerability': '#f97316',
        'Technique': '#8b5cf6',
        'Component': '#3b82f6',
        'Tool': '#06b6d4',
        'Entity': '#6366f1'
    };
    return colors[type] || '#6366f1';
}

// ============== Intel Knowledge Graph Functions ==============

function switchIntelView(view) {
    const listView = document.getElementById('intel-list-view');
    const kgView = document.getElementById('intel-kg-view');
    const listBtn = document.getElementById('intel-list-view-btn');
    const kgBtn = document.getElementById('intel-kg-view-btn');
    const filters = document.getElementById('intel-filters');
    const kgGenerateBtn = document.getElementById('intel-kg-generate-btn');

    if (view === 'list') {
        listView.style.display = 'block';
        kgView.style.display = 'none';
        listBtn.classList.add('active');
        kgBtn.classList.remove('active');
        filters.style.display = 'flex';
        kgGenerateBtn.style.display = 'none';
    } else {
        listView.style.display = 'none';
        kgView.style.display = 'block';
        listBtn.classList.remove('active');
        kgBtn.classList.add('active');
        filters.style.display = 'none';
        kgGenerateBtn.style.display = 'inline-block';
        loadIntelKG();
    }
}

async function checkNeo4jStatus() {
    try {
        const res = await fetch(`${API_BASE}/system/neo4j-status`);
        if (res.ok) {
            const data = await res.json();
            const warningEl = document.getElementById('neo4j-warning');
            if (warningEl) {
                // Show warning if NOT available
                warningEl.style.display = data.available ? 'none' : 'block';
            }
        }
    } catch (err) {
        console.error('Failed to check Neo4j status:', err);
    }
}

async function loadIntelKG() {
    // Check Neo4j status
    checkNeo4jStatus();

    // Wait a bit for DOM to be ready if switching tabs
    await new Promise(resolve => setTimeout(resolve, 100));

    const canvas = document.getElementById('kg-canvas');
    const container = document.getElementById('kg-canvas-container');

    if (!canvas) {
        console.error('KG canvas not found. Make sure you are on the Knowledge Graph tab.');
        return;
    }

    if (!container) {
        console.warn('KG container not found, using canvas parent');
    }

    const emptyState = document.getElementById('kg-empty-state');
    const statsEl = document.getElementById('kg-stats');

    try {
        if (emptyState) emptyState.style.display = 'none';
        canvas.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-secondary);">Loading knowledge graph...</div>';

        // Load existing/cached KG data (DO NOT auto-generate)
        let res = await fetch(`${API_BASE}/intel/kg/data?limit=0&use_ai=false&use_litellm=false`);
        let data = null;

        if (res.ok) {
            data = await res.json();
        }

        // If no data, show empty state with generate button (never auto-generate)
        if (!data || !data.nodes || data.nodes.length === 0) {
            console.log('No existing KG data found. Showing empty state.');
            canvas.innerHTML = `
                <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-secondary); padding: 40px;">
                    <div style="font-size: 3rem; margin-bottom: 16px;">🕸️</div>
                    <div style="font-size: 1.125rem; font-weight: 600; margin-bottom: 8px;">No Knowledge Graph Data</div>
                    <div style="font-size: 0.875rem; text-align: center; margin-bottom: 24px;">Click "Generate from Intel" to build the knowledge graph from intelligence items.</div>
                    <button class="btn btn-primary" onclick="generateKGFromIntel()">🔗 Generate from Intel</button>
                </div>
            `;
            if (statsEl) statsEl.textContent = 'Nodes: 0, Edges: 0';
            return;
        }

        // We have persisted data, render it
        renderKnowledgeGraph(data);

        // Update stats with processing status
        if (statsEl) {
            let statusText = `Nodes: ${data.nodes.length}, Edges: ${data.edges?.length || 0}`;
            try {
                const statusRes = await fetch(`${API_BASE}/intel/kg/status`);
                if (statusRes.ok) {
                    const st = await statusRes.json();
                    if (st.all_processed) {
                        statusText += ` | ✅ All ${st.processed} items processed`;
                    } else if (st.unprocessed > 0) {
                        statusText += ` | ⚠️ ${st.unprocessed} unprocessed items remaining`;
                    }
                }
            } catch (e) { /* status check is optional */ }
            statsEl.textContent = statusText;
        }
    } catch (err) {
        console.error('Intel KG load error:', err);
        if (canvas) {
            canvas.innerHTML = `
                <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-secondary); padding: 40px;">
                    <div style="font-size: 2rem; margin-bottom: 16px; color: var(--error-color);">⚠️</div>
                    <div style="font-size: 1.125rem; font-weight: 600; margin-bottom: 8px; color: var(--error-color);">Error Loading Knowledge Graph</div>
                    <div style="font-size: 0.875rem; text-align: center; margin-bottom: 24px;">${err.message || 'Unknown error'}</div>
                    <button class="btn btn-primary" onclick="generateKGFromIntel()">Try Generate Again</button>
                </div>
            `;
        }
    }
}

function renderIntelKG(data, container) {
    if (!container || !data.nodes) return;

    // Clear container
    container.innerHTML = '';

    // Use vis.js to render
    const nodes = new vis.DataSet(data.nodes.map(n => ({
        id: n.id,
        label: n.label || n.name || n.id,
        title: `${n.label || n.id}\nType: ${n.type || 'Entity'}\n${n.properties?.description || ''}`,
        color: {
            background: getNodeColor(n.type),
            border: '#1a1a2e',
            highlight: {
                background: getNodeColor(n.type),
                border: '#ffffff'
            }
        },
        shape: 'dot',
        size: 20 + (n.properties?.source_count || 0) * 2,
        font: { color: '#ffffff', size: 14 },
        borderWidth: 2,
        // Store original data for details panel
        _originalData: n
    })));

    const edges = new vis.DataSet((data.edges || []).map(e => ({
        from: e.from || e.source,
        to: e.to || e.target,
        label: e.label || e.relationship || '',
        arrows: 'to',
        color: { color: '#6366f1', highlight: '#e94560' },
        font: { color: '#94a3b8', size: 11, align: 'middle' },
        width: 2,
        _originalData: e
    })));

    const network = new vis.Network(container, { nodes, edges }, {
        physics: {
            enabled: true,
            stabilization: {
                iterations: 200,
                fit: true,
                updateInterval: 25,
                onlyDynamicEdges: false
            },
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.2,
                springLength: 150,
                springConstant: 0.05,
                damping: 0.4,
                avoidOverlap: 1.0
            },
            repulsion: {
                nodeDistance: 120,
                centralGravity: 0.2,
                springLength: 150,
                springConstant: 0.05,
                damping: 0.4
            },
            maxVelocity: 3,
            minVelocity: 0.05,
            solver: 'barnesHut',
            timestep: 0.35
        },
        nodes: {
            font: { color: '#ffffff', size: 14 },
            borderWidth: 2,
            shadow: true,
            margin: 10  // Add margin to prevent overlap
        },
        edges: {
            color: { color: '#6366f1', highlight: '#e94560' },
            font: { color: '#94a3b8', size: 11, align: 'middle' },
            arrows: { to: { enabled: true, scaleFactor: 1.2 } },
            smooth: { type: 'continuous', roundness: 0.5 },
            width: 2
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            zoomView: true,
            dragView: true,
            dragNodes: true
        },
        layout: {
            improvedLayout: false,  // Disabled to avoid positioning errors
            hierarchical: {
                enabled: false
            }
        }
    });

    // Stop physics after stabilization to prevent nodes from moving
    let intelKgStabilizationComplete = false;
    let intelKgStabilizationTimeout = null;

    network.once('stabilizationEnd', () => {
        intelKgStabilizationComplete = true;
        if (intelKgStabilizationTimeout) {
            clearTimeout(intelKgStabilizationTimeout);
        }
        // Completely disable physics
        network.setOptions({
            physics: {
                enabled: false
            }
        });
        // Double-check after a short delay to ensure it's really off
        setTimeout(() => {
            network.setOptions({ physics: { enabled: false } });
        }, 100);
        console.log('[IntelKG] Physics disabled after stabilization');
    });

    // Force disable after timeout (5 seconds) as a safety measure
    intelKgStabilizationTimeout = setTimeout(() => {
        if (!intelKgStabilizationComplete) {
            intelKgStabilizationComplete = true;
            network.setOptions({ physics: { enabled: false } });
            console.log('[IntelKG] Physics force-disabled after timeout');
        }
    }, 5000);

    // Also disable physics on stabilization progress to ensure it stops
    network.on('stabilizationProgress', (params) => {
        if (params.iterations >= 150) {
            // Force disable if taking too long
            if (!intelKgStabilizationComplete) {
                network.setOptions({ physics: { enabled: false } });
                intelKgStabilizationComplete = true;
                if (intelKgStabilizationTimeout) {
                    clearTimeout(intelKgStabilizationTimeout);
                }
                console.log('[IntelKG] Physics force-disabled after 150 iterations');
            }
        }
    });

    // Prevent physics from re-enabling on any interaction
    const disablePhysicsIfComplete = () => {
        if (intelKgStabilizationComplete) {
            network.setOptions({ physics: { enabled: false } });
        }
    };

    network.on('dragStart', disablePhysicsIfComplete);
    network.on('dragEnd', disablePhysicsIfComplete);
    network.on('startStabilizing', () => {
        // If stabilization starts again, disable it immediately if we're already done
        if (intelKgStabilizationComplete) {
            network.setOptions({ physics: { enabled: false } });
        }
    });

    // Handle node click - show details panel
    network.on('click', (params) => {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            if (node && node._originalData) {
                showNodeDetails(node._originalData);
            }
        } else if (params.edges.length > 0) {
            const edge = edges.get(params.edges[0]);
            if (edge && edge._originalData) {
                showEdgeDetails(edge._originalData);
            }
        } else {
            // Click on empty space - close details
            closeNodeDetails();
        }
    });
}

function showNodeDetails(nodeData) {
    const detailsPanel = document.getElementById('kg-node-details');
    const detailsContent = document.getElementById('kg-node-details-content');

    if (!detailsPanel || !detailsContent) {
        console.error('Details panel elements not found');
        return;
    }

    // Debug: log the node data
    console.log('Node data:', nodeData);

    const properties = nodeData.properties || {};
    let sourceUrls = properties.source_urls || [];
    const primaryUrl = properties.primary_url;
    const description = properties.description || 'No description available';
    const sourceCount = properties.source_count || 0;
    const nodeType = nodeData.type || nodeData.node_type || 'Entity';

    // Ensure sourceUrls is an array
    if (!Array.isArray(sourceUrls)) {
        sourceUrls = [];
    }

    // Add primaryUrl to sourceUrls if it exists and is not already there
    if (primaryUrl && !sourceUrls.includes(primaryUrl)) {
        sourceUrls.unshift(primaryUrl);
    }

    // Filter out empty or invalid URLs
    sourceUrls = sourceUrls.filter(url => url && typeof url === 'string' && url.trim().length > 0);

    console.log('Source URLs:', sourceUrls);
    console.log('Primary URL:', primaryUrl);

    let html = `
        <div style="margin-bottom: 16px;">
            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">Name</div>
            <div style="font-size: 1.1rem; font-weight: 600; color: var(--text-primary);">${nodeData.label || nodeData.name || nodeData.id}</div>
        </div>
        
        <div style="margin-bottom: 16px;">
            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">Type</div>
            <div style="font-size: 0.9rem; color: var(--text-primary);">${nodeType}</div>
        </div>
        
        <div style="margin-bottom: 16px;">
            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">Description</div>
            <div style="font-size: 0.9rem; color: var(--text-primary); line-height: 1.5; max-height: 150px; overflow-y: auto;">${description}</div>
        </div>
        
        <div style="margin-bottom: 16px;">
            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">Source Count</div>
            <div style="font-size: 0.9rem; color: var(--text-primary);">${sourceUrls.length} source(s)</div>
        </div>
    `;

    if (sourceUrls.length > 0) {
        html += `
            <div style="margin-bottom: 16px;">
                <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 8px;">
                    Source URLs <span style="color: var(--text-secondary); font-weight: normal;">(${sourceUrls.length} total)</span>
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <select id="kg-source-url-select" 
                            style="flex: 1; padding: 8px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--bg-primary); color: var(--text-primary); font-size: 0.85rem; cursor: pointer;"
                            onchange="updateSourceUrlDisplay(this)">
                        ${sourceUrls.map((url, idx) => {
            const displayUrl = url.length > 80 ? url.substring(0, 80) + '...' : url;
            const isPrimary = idx === 0 && url === primaryUrl;
            return `<option value="${url}" ${isPrimary ? 'selected' : ''}>${isPrimary ? '⭐ ' : ''}${displayUrl}</option>`;
        }).join('')}
                    </select>
                    <button onclick="openSelectedSourceUrl()" 
                            style="padding: 8px 16px; border-radius: 4px; border: 1px solid var(--border-color); background: #3b82f6; color: white; font-size: 0.85rem; cursor: pointer; white-space: nowrap;"
                            onmouseover="this.style.background='#2563eb'" 
                            onmouseout="this.style.background='#3b82f6'">
                        🔗 Open
                    </button>
                </div>
                <div id="kg-selected-url-display" style="margin-top: 8px; font-size: 0.75rem; color: var(--text-secondary); word-break: break-all; max-height: 60px; overflow-y: auto;">
                    ${sourceUrls[0] ? (sourceUrls[0].length > 100 ? sourceUrls[0].substring(0, 100) + '...' : sourceUrls[0]) : ''}
                </div>
            </div>
        `;
    } else {
        html += `
            <div style="margin-bottom: 16px;">
                <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 8px;">Source URLs</div>
                <div style="font-size: 0.85rem; color: var(--text-secondary); font-style: italic;">No source URLs available</div>
            </div>
        `;
    }

    detailsContent.innerHTML = html;
    detailsPanel.style.display = 'block';

    // Debug: verify links were created
    setTimeout(() => {
        const links = detailsContent.querySelectorAll('a');
        console.log(`Created ${links.length} links in details panel`);
        links.forEach((link, idx) => {
            console.log(`Link ${idx + 1}:`, link.href, link.textContent);
        });
    }, 100);
}

function showEdgeDetails(edgeData) {
    const detailsPanel = document.getElementById('kg-node-details');
    const detailsContent = document.getElementById('kg-node-details-content');

    if (!detailsPanel || !detailsContent) return;

    const properties = edgeData.properties || {};
    const sourceUrls = properties.source_urls || [];
    const description = properties.description || 'No description available';

    let html = `
        <div style="margin-bottom: 16px;">
            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">Relationship</div>
            <div style="font-size: 1.1rem; font-weight: 600; color: var(--text-primary);">${edgeData.label || edgeData.relationship || 'Unknown'}</div>
        </div>
        
        <div style="margin-bottom: 16px;">
            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">Description</div>
            <div style="font-size: 0.9rem; color: var(--text-primary); line-height: 1.5;">${description}</div>
        </div>
    `;

    if (sourceUrls.length > 0) {
        html += `
            <div style="margin-bottom: 16px;">
                <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 8px;">Source URLs</div>
                <div style="display: flex; flex-direction: column; gap: 8px;">
        `;

        sourceUrls.slice(0, 5).forEach((url, idx) => {
            html += `
                <a href="${url}" target="_blank" style="font-size: 0.85rem; color: var(--primary-color); text-decoration: none; word-break: break-all; padding: 8px; background: var(--bg-primary); border-radius: 4px; border: 1px solid var(--border-color);">
                    🔗 Source ${idx + 1}
                </a>
            `;
        });

        html += `</div></div>`;
    }

    detailsContent.innerHTML = html;
    detailsPanel.style.display = 'block';
}

function closeNodeDetails() {
    const detailsPanel = document.getElementById('kg-node-details');
    if (detailsPanel) {
        detailsPanel.style.display = 'none';
    }
}

function updateSourceUrlDisplay(selectElement) {
    const displayDiv = document.getElementById('kg-selected-url-display');
    if (displayDiv && selectElement) {
        const selectedUrl = selectElement.value;
        displayDiv.textContent = selectedUrl.length > 100 ? selectedUrl.substring(0, 100) + '...' : selectedUrl;
    }
}

function openSelectedSourceUrl() {
    const selectElement = document.getElementById('kg-source-url-select');
    if (selectElement && selectElement.value) {
        const url = selectElement.value;
        console.log('Opening selected URL:', url);
        window.open(url, '_blank', 'noopener,noreferrer');
    }
}

function updateEdgeSourceUrlDisplay(selectElement) {
    // Optional: Update display for edge URLs if needed
}

function openSelectedEdgeSourceUrl() {
    const selectElement = document.getElementById('kg-edge-source-url-select');
    if (selectElement && selectElement.value) {
        const url = selectElement.value;
        console.log('Opening selected edge URL:', url);
        window.open(url, '_blank', 'noopener,noreferrer');
    }
}

async function generateIntelKG() {
    showNotification('info', 'Generating', 'Creating knowledge graph from intelligence items...');
    try {
        const res = await fetch(`${API_BASE}/intel/kg/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ use_ai: true, use_litellm: true, limit: 100 })
        });

        if (res.ok) {
            const data = await res.json();

            // Check if we got an error message but still got a response
            if (data.error) {
                showNotification('warning', 'KG Generation', data.message || data.error || 'No relevant intel items found');
                // Try to render empty graph or show helpful message
                if (data.nodes && data.edges) {
                    await loadIntelKG();
                } else {
                    // Show empty state
                    const canvas = document.getElementById('intel-kg-canvas');
                    if (canvas) {
                        canvas.innerHTML = `
                            <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-secondary); padding: 40px;">
                                <div style="font-size: 3rem; margin-bottom: 16px;">📊</div>
                                <div style="font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; color: var(--text-primary);">No Knowledge Graph Data</div>
                                <div style="font-size: 0.875rem; text-align: center; margin-bottom: 24px;">
                                    ${data.message || data.error || 'No relevant intelligence items available to build a knowledge graph.'}<br/>
                                    Please gather intelligence first or process existing items.
                                </div>
                                <button class="btn btn-primary" onclick="gatherIntel()">Gather Intelligence</button>
                            </div>
                        `;
                    }
                }
            } else {
                showNotification('success', 'Generated', `Knowledge graph created with ${data.stats?.nodes || 0} nodes and ${data.stats?.edges || 0} edges`);
                await loadIntelKG();
            }
        } else {
            const error = await res.json().catch(() => ({}));
            throw new Error(error.error || error.message || 'Failed to generate knowledge graph');
        }
    } catch (e) {
        console.error('Intel KG generation error:', e);
        showNotification('error', 'Error', e.message || 'Failed to generate knowledge graph');
    }
}

// Export functions
window.switchIntelView = switchIntelView;
window.loadIntelKG = loadIntelKG;
window.generateIntelKG = generateIntelKG;
window.generateKG = generateKG;
window.generateKGFromIntel = generateKGFromIntel;
window.uploadToNeo4j = uploadToNeo4j;
window.loadKnowledgeGraph = loadKnowledgeGraph;
window.showNodeDetails = showNodeDetails;
window.showEdgeDetails = showEdgeDetails;
window.closeNodeDetails = closeNodeDetails;
window.updateSourceUrlDisplay = updateSourceUrlDisplay;
window.openSelectedSourceUrl = openSelectedSourceUrl;
window.updateEdgeSourceUrlDisplay = updateEdgeSourceUrlDisplay;
window.openSelectedEdgeSourceUrl = openSelectedEdgeSourceUrl;

// ============== Scanner Functions ==============
// ============== Scanner Functions ==============
// (Legacy scanner functions removed)














// Export scanner functions


// ============== Modal Functions ==============
function openModal(modalId) {
    const overlay = document.getElementById(modalId);
    if (overlay) {
        overlay.classList.add('active');
    }
}

function closeModal(modalId) {
    const overlay = document.getElementById(modalId);
    if (overlay) {
        overlay.classList.remove('active');
        // Remove element after animation
        setTimeout(() => {
            if (overlay.parentNode) {
                overlay.parentNode.removeChild(overlay);
            }
        }, 300);
    }
}






// ============== Configuration Management ==============




// ============== MCP Knowledge Base ==============




// ============== Database Management ==============


// ============== Export for global access ==============
window.deleteNode = deleteNode;
window.gatherIntel = gatherIntel;


window.closeModal = closeModal;
window.zoomIn = zoomIn;
window.zoomOut = zoomOut;
window.resetZoom = resetZoom;
window.saveCanvas = saveCanvas;
window.loadCanvas = loadCanvas;
window.loadSelectedCanvas = loadSelectedCanvas;
window.saveCanvasFromModal = saveCanvasFromModal;
window.selectCanvasForSave = selectCanvasForSave;

window.switchTab = switchTab;
window.loadIntelItems = loadIntelItems;
window.openIntelSource = openIntelSource;


// ============== Custom Threat & Evidence Creation ==============
function openCreateThreatModal() {
    const modal = document.getElementById('create-threat-modal');
    if (modal) {
        modal.classList.add('active');
        // Reset form
        document.getElementById('threat-name').value = '';
        document.getElementById('threat-description').value = '';
        document.getElementById('threat-category').value = 'tampering';
        document.getElementById('threat-risk-level').value = 'medium';
        document.getElementById('threat-risk-score').value = '7.0';
        document.getElementById('threat-attack-vector').value = '';
        document.getElementById('threat-impact').value = '';
        document.getElementById('threat-mitigations').value = '';
        document.getElementById('threat-tags').value = '';
    }
}

function openCreateEvidenceModal() {
    const modal = document.getElementById('create-evidence-modal');
    if (modal) {
        modal.classList.add('active');
        // Reset form
        document.getElementById('evidence-test-name').value = '';
        document.getElementById('evidence-test-type').value = 'fuzz_test';
        document.getElementById('evidence-target-asset').value = '';
        document.getElementById('evidence-target-tool').value = '';
        document.getElementById('evidence-success').value = 'false';
        document.getElementById('evidence-success-rate').value = '0.0';
        document.getElementById('evidence-payload').value = '';
        document.getElementById('evidence-response').value = '';
        document.getElementById('evidence-analysis').value = '';
        document.getElementById('evidence-vulnerability').value = 'false';
    }
}

async function createCustomThreat() {
    const name = document.getElementById('threat-name').value.trim();
    const description = document.getElementById('threat-description').value.trim();

    if (!name || !description) {
        showNotification('error', 'Validation Error', 'Name and description are required');
        return;
    }

    const category = document.getElementById('threat-category').value;
    const riskLevel = document.getElementById('threat-risk-level').value;
    const riskScore = parseFloat(document.getElementById('threat-risk-score').value) || 7.0;
    const attackVector = document.getElementById('threat-attack-vector').value.trim();
    const impact = document.getElementById('threat-impact').value.trim();
    const mitigations = document.getElementById('threat-mitigations').value.trim();
    const tagsStr = document.getElementById('threat-tags').value.trim();
    const tags = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(t => t) : [];

    const threatData = {
        name: name,
        description: description,
        stride_category: category,
        risk_level: riskLevel,
        risk_score: riskScore,
        threat_type: 'custom',
        attack_vector: attackVector || null,
        impact: impact || null,
        mitigations: mitigations ? [mitigations] : [],
        tags: tags,
        source: 'manual',
        project_id: 'default-project'
    };

    try {
        const res = await fetch(`${API_BASE}/threats`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(threatData)
        });

        if (res.ok) {
            showNotification('success', 'Threat Created', `Threat "${name}" has been created successfully`);
            closeModal('create-threat-modal');
            await loadInitialData(); // Refresh data
        } else {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to create threat');
        }
    } catch (err) {
        console.error('Create threat error:', err);
        showNotification('error', 'Create Error', 'Failed to create threat: ' + err.message);
    }
}

async function createCustomEvidence() {
    const testName = document.getElementById('evidence-test-name').value.trim();
    const testType = document.getElementById('evidence-test-type').value;

    if (!testName) {
        showNotification('error', 'Validation Error', 'Test name is required');
        return;
    }

    const targetAsset = document.getElementById('evidence-target-asset').value.trim();
    const targetTool = document.getElementById('evidence-target-tool').value.trim();
    const success = document.getElementById('evidence-success').value === 'true';
    const successRate = parseFloat(document.getElementById('evidence-success-rate').value) || 0.0;
    const payload = document.getElementById('evidence-payload').value.trim();
    const response = document.getElementById('evidence-response').value.trim();
    const analysis = document.getElementById('evidence-analysis').value.trim();
    const vulnerability = document.getElementById('evidence-vulnerability').value === 'true';

    const evidenceData = {
        test_type: testType,
        test_name: testName,
        target_asset: targetAsset || null,
        target_tool: targetTool || null,
        success: success,
        attack_success_rate: successRate,
        payload_used: payload || null,
        response_received: response || null,
        ai_analysis: analysis || null,
        vulnerability_confirmed: vulnerability,
        project_id: 'default-project'
    };

    try {
        const res = await fetch(`${API_BASE}/evidence`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(evidenceData)
        });

        if (res.ok) {
            showNotification('success', 'Evidence Created', `Evidence "${testName}" has been created successfully`);
            closeModal('create-evidence-modal');
            await loadInitialData(); // Refresh data
        } else {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to create evidence');
        }
    } catch (err) {
        console.error('Create evidence error:', err);
        showNotification('error', 'Create Error', 'Failed to create evidence: ' + err.message);
    }
}

function updateEvidencePalette() {
    const container = document.getElementById('evidence-items');
    if (!container) return;

    if (!AppState.evidence || AppState.evidence.length === 0) {
        container.innerHTML = '<div class="card-meta" style="padding: 10px;">No attack evidence yet</div>';
        return;
    }

    const html = AppState.evidence.map(evidence => `
        <div class="drag-card" 
             draggable="true" 
             data-card-type="evidence" 
             data-id="${evidence.id}"
             data-name="${evidence.test_name || 'Untitled Evidence'}">
            <div class="card-icon evidence">📋</div>
            <div class="card-info">
                <div class="card-name">${evidence.test_name || 'Untitled Evidence'}</div>
                <div class="card-meta">${evidence.test_type || 'Evidence'}</div>
            </div>
        </div>
    `).join('');

    container.innerHTML = html;

    // Re-setup drag events
    container.querySelectorAll('.drag-card').forEach(card => {
        card.addEventListener('dragstart', handleDragStart);
        card.addEventListener('dragend', handleDragEnd);
    });
}

window.openCreateThreatModal = openCreateThreatModal;
window.openCreateEvidenceModal = openCreateEvidenceModal;
window.createCustomThreat = createCustomThreat;
window.createCustomEvidence = createCustomEvidence;
