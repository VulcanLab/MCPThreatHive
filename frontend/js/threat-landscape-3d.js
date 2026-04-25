/**
 * 3D Threat Landscape Visualization
 * Renders MCP-38 threats as a 3D city using Three.js
 */

const ThreatLandscape = (function () {
    let scene, camera, renderer, controls;
    let buildings = [];
    let raycaster, mouse;
    let hoveredBuilding = null;
    let selectedBuilding = null;
    let container = null;
    let isInitialized = false;
    let animationId = null;

    // Colors for attack surfaces
    const SURFACE_COLORS = {
        server_apis: 0x3b82f6,
        tool_metadata: 0x22c55e,
        runtime_flow: 0xef4444,
        transport: 0xf59e0b
    };

    /**
     * Initialize the 3D scene
     */
    function init(containerId) {
        container = document.getElementById(containerId);
        if (!container) {
            console.error('Container not found:', containerId);
            return false;
        }

        // Scene setup
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x1a1a2e);

        // Camera
        const width = container.clientWidth;
        const height = container.clientHeight;
        camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
        camera.position.set(15, 20, 25);
        camera.lookAt(0, 0, 0);

        // Renderer
        renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(width, height);
        renderer.shadowMap.enabled = true;
        container.appendChild(renderer.domElement);

        // Controls
        controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;
        controls.maxPolarAngle = Math.PI / 2.1;
        controls.autoRotate = false;
        controls.autoRotateSpeed = 0.5;

        // Enhanced Lighting
        // Ambient light - soft base illumination
        const ambientLight = new THREE.AmbientLight(0x707070, 0.6);
        scene.add(ambientLight);

        // Directional light 1 - front-right (main key light)
        const directionalLight1 = new THREE.DirectionalLight(0xe0e0e0, 1.2);
        directionalLight1.position.set(50, 30, 20);
        directionalLight1.castShadow = true;
        directionalLight1.shadow.mapSize.width = 2048;
        directionalLight1.shadow.mapSize.height = 2048;
        directionalLight1.shadow.camera.near = 0.5;
        directionalLight1.shadow.camera.far = 100;
        directionalLight1.shadow.camera.left = -30;
        directionalLight1.shadow.camera.right = 30;
        directionalLight1.shadow.camera.top = 30;
        directionalLight1.shadow.camera.bottom = -30;
        scene.add(directionalLight1);

        // Directional light 2 - back-left (fill light)
        const directionalLight2 = new THREE.DirectionalLight(0xb0c4de, 0.8);
        directionalLight2.position.set(-40, 20, -15);
        scene.add(directionalLight2);

        // Hemisphere light for natural sky/ground coloring
        const hemiLight = new THREE.HemisphereLight(0x4a5568, 0x1a1a2e, 0.4);
        scene.add(hemiLight);

        // Fog for depth atmosphere
        scene.fog = new THREE.Fog(0x1a1a2e, 40, 80);

        // Ground plane with better material
        const groundGeometry = new THREE.PlaneGeometry(60, 40);
        const groundMaterial = new THREE.MeshStandardMaterial({
            color: 0x0f172a,
            metalness: 0.2,
            roughness: 0.9,
            envMapIntensity: 0.5
        });
        const ground = new THREE.Mesh(groundGeometry, groundMaterial);
        ground.rotation.x = -Math.PI / 2;
        ground.position.y = 0;
        ground.receiveShadow = true;
        scene.add(ground);

        // Enhanced grid with subtle glow effect
        const gridHelper = new THREE.GridHelper(60, 60, 0x3b82f6, 0x1e3a5f);
        gridHelper.position.y = 0.02;
        gridHelper.material.opacity = 0.3;
        gridHelper.material.transparent = true;
        scene.add(gridHelper);

        // Raycaster for mouse interaction
        raycaster = new THREE.Raycaster();
        mouse = new THREE.Vector2();

        // Event listeners
        container.addEventListener('mousemove', onMouseMove, false);
        container.addEventListener('click', onClick, false);
        window.addEventListener('resize', onWindowResize, false);

        isInitialized = true;
        animate();

        return true;
    }

    /**
     * Create zone platforms for attack surfaces
     */
    let zonePlatforms = [];
    let buildingLabels = [];

    function createZonePlatforms() {
        // Clear existing platforms
        zonePlatforms.forEach(p => scene.remove(p));
        zonePlatforms = [];

        const zones = [
            { surface: 'server_apis', color: 0x3b82f6, x: -12, z: -5, width: 18, depth: 14, label: 'Server APIs' },
            { surface: 'tool_metadata', color: 0x22c55e, x: 10, z: -5, width: 14, depth: 14, label: 'Tool Metadata' },
            { surface: 'runtime_flow', color: 0xef4444, x: -12, z: 10, width: 18, depth: 12, label: 'Runtime Flow' },
            { surface: 'transport', color: 0xf59e0b, x: 10, z: 10, width: 14, depth: 12, label: 'Transport' }
        ];

        zones.forEach(zone => {
            // Platform base
            const platformGeometry = new THREE.BoxGeometry(zone.width, 0.15, zone.depth);
            const platformMaterial = new THREE.MeshStandardMaterial({
                color: zone.color,
                metalness: 0.4,
                roughness: 0.6,
                transparent: true,
                opacity: 0.3
            });
            const platform = new THREE.Mesh(platformGeometry, platformMaterial);
            platform.position.set(zone.x, 0.075, zone.z);
            platform.receiveShadow = true;
            scene.add(platform);
            zonePlatforms.push(platform);

            // Platform edge glow
            const edgeGeometry = new THREE.EdgesGeometry(platformGeometry);
            const edgeMaterial = new THREE.LineBasicMaterial({
                color: zone.color,
                transparent: true,
                opacity: 0.6
            });
            const edges = new THREE.LineSegments(edgeGeometry, edgeMaterial);
            edges.position.copy(platform.position);
            scene.add(edges);
            zonePlatforms.push(edges);

            // Zone label (3D text sprite)
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            canvas.width = 256;
            canvas.height = 64;
            context.fillStyle = 'transparent';
            context.fillRect(0, 0, canvas.width, canvas.height);
            context.font = 'bold 24px Inter, sans-serif';
            context.fillStyle = '#' + zone.color.toString(16).padStart(6, '0');
            context.textAlign = 'center';
            context.fillText(zone.label, canvas.width / 2, 40);

            const texture = new THREE.CanvasTexture(canvas);
            const spriteMaterial = new THREE.SpriteMaterial({
                map: texture,
                transparent: true,
                opacity: 0.8
            });
            const sprite = new THREE.Sprite(spriteMaterial);
            sprite.position.set(zone.x, 0.5, zone.z);
            sprite.scale.set(8, 2, 1);
            scene.add(sprite);
            zonePlatforms.push(sprite);
        });
    }

    /**
     * Create buildings from threat data
     */
    function createBuildings(data) {
        // Clear existing buildings and labels
        buildings.forEach(b => {
            scene.remove(b.mesh);
            if (b.label) scene.remove(b.label);
            if (b.glow) scene.remove(b.glow);
        });
        buildings = [];

        if (!data || !data.buildings) return;

        // Create zone platforms first
        createZonePlatforms();

        data.buildings.forEach(buildingData => {
            // Enhanced geometry with slight bevel feel (using segments)
            const geometry = new THREE.BoxGeometry(
                buildingData.width * 0.9,
                buildingData.height,
                buildingData.depth * 0.9,
                1, 2, 1
            );

            const baseColor = SURFACE_COLORS[buildingData.surface] || 0x666666;
            const isCritical = buildingData.severity >= 9;
            const isHigh = buildingData.severity >= 7;

            // Enhanced material with better lighting response
            const material = new THREE.MeshStandardMaterial({
                color: baseColor,
                metalness: isCritical ? 0.5 : 0.35,
                roughness: isCritical ? 0.4 : 0.6,
                emissive: baseColor,
                emissiveIntensity: isCritical ? 0.25 : isHigh ? 0.15 : 0.08
            });

            const mesh = new THREE.Mesh(geometry, material);
            mesh.position.set(
                buildingData.x,
                buildingData.height / 2 + 0.15, // Raised for platform
                buildingData.z
            );
            mesh.castShadow = true;
            mesh.receiveShadow = true;
            mesh.userData = buildingData;

            scene.add(mesh);

            const buildingObj = {
                mesh,
                data: buildingData,
                originalColor: baseColor,
                originalEmissive: isCritical ? 0.25 : isHigh ? 0.15 : 0.08
            };

            // Add glow effect for critical threats
            if (isCritical) {
                const glowGeometry = new THREE.BoxGeometry(
                    buildingData.width * 1.05,
                    buildingData.height * 1.02,
                    buildingData.depth * 1.05
                );
                const glowMaterial = new THREE.MeshBasicMaterial({
                    color: 0xff4444,
                    transparent: true,
                    opacity: 0.15,
                    side: THREE.BackSide
                });
                const glow = new THREE.Mesh(glowGeometry, glowMaterial);
                glow.position.copy(mesh.position);
                scene.add(glow);
                buildingObj.glow = glow;
            }

            // Add floating label for high+ severity threats
            if (isHigh) {
                const canvas = document.createElement('canvas');
                const context = canvas.getContext('2d');
                canvas.width = 128;
                canvas.height = 32;
                context.fillStyle = 'rgba(0,0,0,0.6)';
                context.roundRect(0, 0, canvas.width, canvas.height, 4);
                context.fill();
                context.font = 'bold 14px Inter, monospace';
                context.fillStyle = isCritical ? '#ef4444' : '#f97316';
                context.textAlign = 'center';
                context.fillText(buildingData.id, canvas.width / 2, 22);

                const texture = new THREE.CanvasTexture(canvas);
                const labelMaterial = new THREE.SpriteMaterial({
                    map: texture,
                    transparent: true
                });
                const label = new THREE.Sprite(labelMaterial);
                label.position.set(
                    buildingData.x,
                    buildingData.height + 1.5,
                    buildingData.z
                );
                label.scale.set(2.5, 0.6, 1);
                scene.add(label);
                buildingObj.label = label;
            }

            buildings.push(buildingObj);
        });
    }

    /**
     * Animation loop
     */
    function animate() {
        animationId = requestAnimationFrame(animate);
        controls.update();
        renderer.render(scene, camera);
    }

    /**
     * Handle mouse move for hover effects
     */
    function onMouseMove(event) {
        if (!container) return;

        const rect = container.getBoundingClientRect();
        mouse.x = ((event.clientX - rect.left) / container.clientWidth) * 2 - 1;
        mouse.y = -((event.clientY - rect.top) / container.clientHeight) * 2 + 1;

        raycaster.setFromCamera(mouse, camera);
        const intersects = raycaster.intersectObjects(buildings.map(b => b.mesh));

        if (intersects.length > 0) {
            const newHovered = intersects[0].object;

            if (newHovered !== hoveredBuilding) {
                // Restore previous hovered building
                if (hoveredBuilding && hoveredBuilding !== selectedBuilding) {
                    const prevBuilding = buildings.find(b => b.mesh === hoveredBuilding);
                    if (prevBuilding) {
                        prevBuilding.mesh.material.emissiveIntensity = prevBuilding.originalEmissive || 0.1;
                    }
                }

                hoveredBuilding = newHovered;

                // Dim all other buildings, brighten hovered
                buildings.forEach(b => {
                    if (b.mesh === hoveredBuilding) {
                        // Brighten hovered building
                        b.mesh.material.emissiveIntensity = 0.5;
                        b.mesh.scale.setScalar(1.02); // Slight scale up
                    } else if (b.mesh !== selectedBuilding) {
                        // Dim other buildings
                        b.mesh.material.emissiveIntensity = 0.02;
                    }
                });
            }

            container.style.cursor = 'pointer';
            showTooltip(event.clientX, event.clientY, hoveredBuilding.userData);
        } else {
            // Restore all buildings when not hovering
            if (hoveredBuilding) {
                buildings.forEach(b => {
                    if (b.mesh !== selectedBuilding) {
                        b.mesh.material.emissiveIntensity = b.originalEmissive || 0.1;
                        b.mesh.scale.setScalar(1.0);
                    }
                });
                hoveredBuilding = null;
            }
            container.style.cursor = 'default';
            hideTooltip();
        }
    }

    /**
     * Handle click for selection
     */
    function onClick(event) {
        if (!container) return;

        const rect = container.getBoundingClientRect();
        mouse.x = ((event.clientX - rect.left) / container.clientWidth) * 2 - 1;
        mouse.y = -((event.clientY - rect.top) / container.clientHeight) * 2 + 1;

        raycaster.setFromCamera(mouse, camera);
        const intersects = raycaster.intersectObjects(buildings.map(b => b.mesh));

        // Reset previous selection
        if (selectedBuilding) {
            const building = buildings.find(b => b.mesh === selectedBuilding);
            if (building) {
                building.mesh.material.emissive.setHex(building.originalColor);
                building.mesh.material.emissiveIntensity = 0.1;
            }
        }

        if (intersects.length > 0) {
            selectedBuilding = intersects[0].object;
            selectedBuilding.material.emissiveIntensity = 0.6;

            // Show details panel
            showDetailsPanel(selectedBuilding.userData);
        } else {
            selectedBuilding = null;
            hideDetailsPanel();
        }
    }

    /**
     * Handle window resize
     */
    function onWindowResize() {
        if (!container || !camera || !renderer) return;

        const width = container.clientWidth;
        const height = container.clientHeight;

        // Only resize if dimensions are valid
        if (width > 0 && height > 0) {
            camera.aspect = width / height;
            camera.updateProjectionMatrix();
            renderer.setSize(width, height);
        }
    }

    /**
     * Force resize (useful when tab becomes visible)
     */
    function forceResize() {
        // Use setTimeout to ensure container has rendered
        setTimeout(() => {
            onWindowResize();
        }, 100);
    }

    /**
     * Show tooltip
     */
    function showTooltip(x, y, data) {
        let tooltip = document.getElementById('landscape-tooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = 'landscape-tooltip';
            tooltip.className = 'landscape-tooltip';
            document.body.appendChild(tooltip);
        }

        tooltip.innerHTML = `
            <div class="tooltip-title">${data.id}: ${data.name}</div>
            <div class="tooltip-row">Severity: <span class="severity-${data.severity >= 9 ? 'critical' : data.severity >= 7 ? 'high' : 'medium'}">${data.severity}/10</span></div>
            <div class="tooltip-row">Surface: ${data.surface.replace('_', ' ')}</div>
            ${data.detections > 0 ? `<div class="tooltip-row">Detections: ${data.detections}</div>` : ''}
        `;

        tooltip.style.left = (x + 15) + 'px';
        tooltip.style.top = (y + 15) + 'px';
        tooltip.style.display = 'block';
    }

    /**
     * Hide tooltip
     */
    function hideTooltip() {
        const tooltip = document.getElementById('landscape-tooltip');
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    }

    /**
     * Show details panel
     */
    function showDetailsPanel(data) {
        const panel = document.getElementById('landscape-details');
        if (!panel) return;

        const surfaceLabels = {
            server_apis: 'Server APIs & Functionality',
            tool_metadata: 'Tool Metadata & Toolchain',
            runtime_flow: 'Runtime Invocation Flow',
            transport: 'Transport & Session'
        };

        panel.innerHTML = `
            <div class="details-header">
                <h3>${data.id}</h3>
                <span class="severity-badge severity-${data.severity >= 9 ? 'critical' : data.severity >= 7 ? 'high' : 'medium'}">
                    Severity ${data.severity}/10
                </span>
            </div>
            <div class="details-name">${data.name}</div>
            <div class="details-section">
                <div class="details-label">Attack Surface</div>
                <div class="details-value">${surfaceLabels[data.surface] || data.surface}</div>
            </div>
            <div class="details-section">
                <div class="details-label">Risk Level</div>
                <div class="details-value" style="color: ${data.risk_level === 'Critical' ? '#dc2626' : data.risk_level === 'High' ? '#ef4444' : data.risk_level === 'Low' ? '#22c55e' : '#f59e0b'};">${data.risk_level || 'Medium'}</div>
            </div>
            <div class="details-actions">
                <button class="btn btn-primary btn-sm" onclick="ThreatLandscape.viewThreatDetails('${data.id}')">
                    View Full Details
                </button>
            </div>
        `;
        panel.style.display = 'block';
    }

    /**
     * Hide details panel
     */
    function hideDetailsPanel() {
        const panel = document.getElementById('landscape-details');
        if (panel) {
            panel.style.display = 'none';
        }
    }

    /**
     * Load landscape data from API
     */
    async function loadLandscape() {
        try {
            const response = await fetch('/api/threats/landscape');
            if (!response.ok) throw new Error('Failed to load landscape data');

            const data = await response.json();
            createBuildings(data);
            updateLegend(data.legend);
            updateStats(data.metadata);

            return data;
        } catch (error) {
            console.error('Error loading landscape:', error);
            return null;
        }
    }

    /**
     * Update legend
     */
    function updateLegend(legend) {
        const legendContainer = document.getElementById('landscape-legend');
        if (!legendContainer || !legend) return;

        legendContainer.innerHTML = legend.map(item => `
            <div class="legend-item">
                <span class="legend-color" style="background: ${item.color}"></span>
                <span class="legend-label">${item.label}</span>
            </div>
        `).join('');
    }

    /**
     * Update statistics
     */
    function updateStats(metadata) {
        const statsContainer = document.getElementById('landscape-stats');
        if (!statsContainer || !metadata) return;

        statsContainer.innerHTML = `
            <div class="stat-item">
                <span class="stat-value">${metadata.total_threats}</span>
                <span class="stat-label">Total Threats</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${metadata.max_severity}</span>
                <span class="stat-label">Max Severity</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${Object.keys(metadata.surfaces).length}</span>
                <span class="stat-label">Attack Surfaces</span>
            </div>
        `;
    }

    /**
     * View threat details (show detailed modal)
     */
    function viewThreatDetails(threatId) {
        // Find the building data
        const building = buildings.find(b => b.data.id === threatId);
        if (!building) {
            console.warn('Threat not found:', threatId);
            return;
        }

        const data = building.data;

        // Risk level color mapping
        const riskColors = {
            'Critical': '#dc2626',
            'High': '#ef4444',
            'Medium': '#f59e0b',
            'Low': '#22c55e'
        };

        // Complexity color mapping
        const complexityColors = {
            'High': '#ef4444',
            'Medium': '#f59e0b',
            'Low': '#22c55e'
        };

        // Create and show modal
        let modal = document.getElementById('threat-detail-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'threat-detail-modal';
            modal.className = 'modal';
            document.body.appendChild(modal);
        }

        modal.innerHTML = `
            <div class="modal-content" style="max-width: 700px; max-height: 85vh; overflow-y: auto;">
                <div class="modal-header">
                    <h2>${data.id}: ${data.name}</h2>
                    <button class="modal-close" onclick="document.getElementById('threat-detail-modal').style.display='none'">&times;</button>
                </div>
                <div class="modal-body" style="padding: 24px;">
                    <!-- Risk Indicators Row -->
                    <div style="display: flex; gap: 24px; margin-bottom: 24px; flex-wrap: wrap;">
                        <div style="flex: 1; min-width: 120px; text-align: center; padding: 16px; background: rgba(255,255,255,0.05); border-radius: 12px;">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 8px;">SEVERITY</div>
                            <div style="font-size: 2rem; font-weight: 700; color: ${data.severity >= 9 ? '#ef4444' : data.severity >= 7 ? '#f97316' : '#D4AF37'};">
                                ${data.severity}/10
                            </div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 4px;">Based on impact & exploitability</div>
                        </div>
                        <div style="flex: 1; min-width: 120px; text-align: center; padding: 16px; background: rgba(255,255,255,0.05); border-radius: 12px;">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 8px;">RISK LEVEL</div>
                            <div style="font-size: 1.5rem; font-weight: 600; color: ${riskColors[data.risk_level] || '#f59e0b'};">
                                ${data.risk_level || 'Medium'}
                            </div>
                        </div>
                        <div style="flex: 1; min-width: 120px; text-align: center; padding: 16px; background: rgba(255,255,255,0.05); border-radius: 12px;">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 8px;">COMPLEXITY</div>
                            <div style="font-size: 1.5rem; font-weight: 600; color: ${complexityColors[data.complexity] || '#f59e0b'};">
                                ${data.complexity || 'Medium'}
                            </div>
                            <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 4px;">Attack difficulty</div>
                        </div>
                    </div>

                    <!-- Category & Surface -->
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
                        <div style="padding: 12px; background: rgba(255,255,255,0.03); border-radius: 8px; border-left: 3px solid var(--primary);">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 4px;">CATEGORY</div>
                            <div style="font-size: 0.95rem; color: var(--text-primary);">${data.category || 'N/A'}</div>
                        </div>
                        <div style="padding: 12px; background: rgba(255,255,255,0.03); border-radius: 8px; border-left: 3px solid ${data.color};">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 4px;">ATTACK SURFACE</div>
                            <div style="font-size: 0.95rem; color: var(--text-primary);">${data.surface.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</div>
                        </div>
                    </div>

                    <!-- Description -->
                    <div style="margin-bottom: 20px;">
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 8px; font-weight: 500;">📋 DESCRIPTION</div>
                        <div style="font-size: 0.95rem; line-height: 1.6; color: var(--text-secondary); padding: 16px; background: rgba(255,255,255,0.03); border-radius: 8px;">
                            ${data.description || 'No description available.'}
                        </div>
                    </div>

                    <!-- Mitigation -->
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 8px; font-weight: 500;">🛡️ MITIGATION</div>
                        <div style="font-size: 0.95rem; line-height: 1.6; color: var(--success); padding: 16px; background: rgba(34, 197, 94, 0.1); border-radius: 8px; border: 1px solid rgba(34, 197, 94, 0.2);">
                            ${data.mitigation || 'No mitigation guidance available.'}
                        </div>
                    </div>
                </div>
                <div class="modal-footer" style="padding: 16px 24px; border-top: 1px solid var(--border-color);">
                    <button class="btn btn-secondary" onclick="document.getElementById('threat-detail-modal').style.display='none'">Close</button>
                </div>
            </div>
        `;

        modal.style.display = 'flex';
    }

    /**
     * Reset camera position
     */
    function resetCamera() {
        camera.position.set(15, 20, 25);
        camera.lookAt(0, 0, 0);
        controls.reset();
    }

    /**
     * Cleanup
     */
    function dispose() {
        if (animationId) {
            cancelAnimationFrame(animationId);
        }

        buildings.forEach(b => {
            b.mesh.geometry.dispose();
            b.mesh.material.dispose();
            scene.remove(b.mesh);
        });
        buildings = [];

        if (renderer) {
            renderer.dispose();
            if (container && renderer.domElement.parentElement === container) {
                container.removeChild(renderer.domElement);
            }
        }

        container?.removeEventListener('mousemove', onMouseMove);
        container?.removeEventListener('click', onClick);
        window.removeEventListener('resize', onWindowResize);

        isInitialized = false;
    }

    /**
     * Toggle camera auto-rotate
     */
    function toggleAutoRotate() {
        if (controls) {
            controls.autoRotate = !controls.autoRotate;
            return controls.autoRotate;
        }
        return false;
    }

    /**
     * Zoom camera to focus on a building
     */
    function focusOnBuilding(threatId) {
        const building = buildings.find(b => b.data.id === threatId);
        if (!building || !camera || !controls) return;

        const targetPos = building.mesh.position.clone();
        const offset = new THREE.Vector3(8, 8, 8);
        const newCamPos = targetPos.clone().add(offset);

        // Smooth camera transition would require animation library
        camera.position.copy(newCamPos);
        controls.target.copy(targetPos);
        controls.update();
    }

    // Public API
    return {
        init,
        loadLandscape,
        resetCamera,
        dispose,
        viewThreatDetails,
        forceResize,
        toggleAutoRotate,
        focusOnBuilding,
        isInitialized: () => isInitialized
    };
})();

// Export for global access
window.ThreatLandscape = ThreatLandscape;
