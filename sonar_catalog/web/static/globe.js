// Globe view for sonar file visualization using CesiumJS

let viewer = null;
let currentEntities = [];
let currentTrackEntity = null;

// Format colors for map markers
const FORMAT_COLORS = {
    xtf: [0, 255, 255, 200],    // cyan
    jsf: [255, 165, 0, 200],    // orange
    s7k: [0, 255, 0, 200],      // lime
    all: [255, 255, 0, 200],    // yellow
    kmall: [255, 0, 255, 200],  // magenta
    bag: [100, 149, 237, 200],  // cornflower
    segy: [250, 128, 114, 200], // salmon
};
const DEFAULT_COLOR = [255, 255, 255, 200];

function formatSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, size = bytes;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return size.toFixed(1) + ' ' + units[i];
}

function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function initGlobe() {
    // Disable ion (we use OSM tiles, no API key needed)
    Cesium.Ion.defaultAccessToken = undefined;

    viewer = new Cesium.Viewer('cesiumContainer', {
        baseLayer: new Cesium.ImageryLayer(
            new Cesium.OpenStreetMapImageryProvider({
                url: 'https://tile.openstreetmap.org/'
            })
        ),
        baseLayerPicker: false,
        geocoder: false,
        homeButton: true,
        sceneModePicker: true,
        timeline: false,
        animation: false,
        navigationHelpButton: false,
        infoBox: true,
        selectionIndicator: true,
    });

    // Dark ocean background
    viewer.scene.globe.baseColor = Cesium.Color.fromCssColorString('#0a1628');
    viewer.scene.backgroundColor = Cesium.Color.fromCssColorString('#0a0a1a');

    // Fly to data extent
    try {
        const resp = await fetch('/api/geo/bounds');
        if (resp.ok) {
            const bounds = await resp.json();
            viewer.camera.flyTo({
                destination: Cesium.Rectangle.fromDegrees(
                    bounds.lon_min - 1, bounds.lat_min - 1,
                    bounds.lon_max + 1, bounds.lat_max + 1
                ),
                duration: 2,
            });
            document.getElementById('globe-point-count').textContent =
                bounds.file_count.toLocaleString() + ' files with navigation data';
        }
    } catch (e) {
        document.getElementById('globe-point-count').textContent = 'No navigation data yet';
    }

    // Load points
    await loadPoints();

    // Load format filter
    try {
        const resp = await fetch('/api/formats');
        const formats = await resp.json();
        const sel = document.getElementById('globe-format-filter');
        for (const f of formats) {
            const opt = document.createElement('option');
            opt.value = f;
            opt.textContent = f;
            sel.appendChild(opt);
        }
    } catch (e) {}

    document.getElementById('globe-format-filter').addEventListener('change', loadPoints);

    // Track display on entity selection
    viewer.selectedEntityChanged.addEventListener(async function(entity) {
        if (!entity || !entity.properties || !entity.properties.content_hash) return;
        const hash = entity.properties.content_hash.getValue();
        await loadTrack(hash);
    });
}

async function loadPoints() {
    const fmt = document.getElementById('globe-format-filter').value;
    const params = new URLSearchParams();
    if (fmt) params.set('format', fmt);
    params.set('limit', 50000);

    try {
        const resp = await fetch('/api/geo/points?' + params);
        const points = await resp.json();

        // Clear existing
        for (const e of currentEntities) {
            viewer.entities.remove(e);
        }
        currentEntities = [];

        for (const pt of points) {
            const rgba = FORMAT_COLORS[pt.sonar_format] || DEFAULT_COLOR;
            const color = new Cesium.Color(rgba[0]/255, rgba[1]/255, rgba[2]/255, rgba[3]/255);

            const entity = viewer.entities.add({
                position: Cesium.Cartesian3.fromDegrees(pt.lon, pt.lat),
                point: {
                    pixelSize: 6,
                    color: color,
                    outlineColor: Cesium.Color.BLACK,
                    outlineWidth: 1,
                },
                properties: {
                    content_hash: pt.content_hash,
                    sonar_format: pt.sonar_format,
                },
                description:
                    '<b>' + escapeHtml(pt.file_name || 'Unknown') + '</b><br>' +
                    'Format: ' + escapeHtml(pt.sonar_format || '-') + '<br>' +
                    'Size: ' + formatSize(pt.file_size) + '<br>' +
                    'Hash: <code>' + (pt.content_hash || '').substring(0, 16) + '</code>',
            });
            currentEntities.push(entity);
        }

        document.getElementById('globe-point-count').textContent =
            points.length.toLocaleString() + ' files shown';
    } catch (e) {
        console.error('Failed to load points:', e);
    }
}

async function loadTrack(hash) {
    // Remove previous track
    if (currentTrackEntity) {
        viewer.entities.remove(currentTrackEntity);
        currentTrackEntity = null;
    }

    try {
        const resp = await fetch('/api/geo/track/' + hash);
        if (!resp.ok) return;
        const data = await resp.json();

        if (data.track && data.track.length > 1) {
            // Track is [[lat, lon], ...], CesiumJS wants (lon, lat)
            const coords = [];
            for (const p of data.track) {
                coords.push(p[1], p[0]); // lon, lat
            }
            const positions = Cesium.Cartesian3.fromDegreesArray(coords);

            currentTrackEntity = viewer.entities.add({
                polyline: {
                    positions: positions,
                    width: 3,
                    material: new Cesium.PolylineGlowMaterialProperty({
                        glowPower: 0.25,
                        color: Cesium.Color.CYAN,
                    }),
                    clampToGround: true,
                },
            });
        }
    } catch (e) {
        console.error('Failed to load track:', e);
    }
}

document.addEventListener('DOMContentLoaded', initGlobe);
