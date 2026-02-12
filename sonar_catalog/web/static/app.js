// ---------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------

function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
    document.getElementById('page-' + name).classList.remove('hidden');
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-page="' + name + '"]').classList.add('active');

    if (name === 'duplicates') loadDuplicates();
    if (name === 'hosts') loadHosts();
    if (name === 'stats') loadStats();
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0, size = bytes;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return size.toFixed(1) + ' ' + units[i];
}

function parseSize(str) {
    if (!str) return null;
    str = str.trim().toUpperCase();
    const mult = {B:1, K:1024, KB:1024, M:1024**2, MB:1024**2,
                  G:1024**3, GB:1024**3, T:1024**4, TB:1024**4};
    for (const [suffix, m] of Object.entries(mult).sort((a,b) => b[0].length - a[0].length)) {
        if (str.endsWith(suffix)) {
            return Math.floor(parseFloat(str.slice(0, -suffix.length)) * m);
        }
    }
    return parseInt(str) || null;
}

function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------
// Search
// ---------------------------------------------------------------

async function doSearch() {
    const q = document.getElementById('search-input').value.trim();
    const server = document.getElementById('filter-server').value;
    const format = document.getElementById('filter-format').value;
    const minSize = parseSize(document.getElementById('filter-min-size').value);
    const maxSize = parseSize(document.getElementById('filter-max-size').value);

    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (server) params.set('server', server);
    if (format) params.set('format', format);
    if (minSize) params.set('min_size', minSize);
    if (maxSize) params.set('max_size', maxSize);
    params.set('limit', 200);

    const container = document.getElementById('search-results');
    container.innerHTML = '<span class="text-gray-500">Searching...</span>';

    try {
        const resp = await fetch('/api/search?' + params);
        const data = await resp.json();
        renderSearchResults(data, container);
    } catch (e) {
        container.innerHTML = '<span class="text-red-400">Error: ' + escapeHtml(e.message) + '</span>';
    }
}

function renderSearchResults(data, container) {
    if (!data.length) {
        container.innerHTML = '<span class="text-gray-500">No results found.</span>';
        return;
    }

    let html = '<div class="text-gray-500 mb-2">' + data.length + ' results</div>';
    html += '<div class="overflow-x-auto"><table class="results-table"><thead><tr>';
    html += '<th>Server</th><th>Size</th><th>Format</th><th>Path</th>';
    html += '</tr></thead><tbody>';

    for (const r of data) {
        const fmt = r.sonar_format || r.mime_type || '-';
        const path = r.canonical_path || '';
        html += '<tr class="clickable" onclick="showFileDetail(\'' + escapeHtml(r.content_hash) + '\')">';
        html += '<td>' + escapeHtml(r.nfs_server) + '</td>';
        html += '<td class="whitespace-nowrap">' + formatSize(r.file_size) + '</td>';
        html += '<td>' + escapeHtml(fmt) + '</td>';
        html += '<td class="truncate-path" title="' + escapeHtml(path) + '">' + escapeHtml(path) + '</td>';
        html += '</tr>';
    }

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// ---------------------------------------------------------------
// File detail modal
// ---------------------------------------------------------------

async function showFileDetail(hash) {
    document.getElementById('modal-overlay').classList.remove('hidden');
    const content = document.getElementById('modal-content');
    content.innerHTML = '<span class="text-gray-500">Loading...</span>';

    try {
        const resp = await fetch('/api/files/' + hash);
        const data = await resp.json();

        if (data.error) {
            content.innerHTML = '<span class="text-red-400">' + escapeHtml(data.error) + '</span>';
            return;
        }

        const f = data.file;
        let html = '<div class="space-y-4">';
        html += '<div class="grid grid-cols-2 gap-x-6 gap-y-2">';
        html += '<div><span class="text-gray-500">Hash:</span> <span class="font-mono text-xs">' + escapeHtml(f.content_hash) + '</span></div>';
        html += '<div><span class="text-gray-500">Size:</span> ' + formatSize(f.file_size) + '</div>';
        html += '<div><span class="text-gray-500">Format:</span> ' + escapeHtml(f.sonar_format || '-') + '</div>';
        html += '<div><span class="text-gray-500">MIME:</span> ' + escapeHtml(f.mime_type || '-') + '</div>';
        html += '</div>';

        if (data.locations && data.locations.length) {
            html += '<div class="mt-4"><h4 class="text-white font-medium mb-2">Locations (' + data.locations.length + ')</h4>';
            html += '<div class="space-y-2">';
            for (const loc of data.locations) {
                html += '<div class="bg-gray-800 rounded-lg p-3">';
                html += '<div class="font-mono text-xs text-ocean-300">' + escapeHtml(loc.canonical_path) + '</div>';
                html += '<div class="text-xs text-gray-500 mt-1">';
                html += 'Server: ' + escapeHtml(loc.nfs_server);
                if (loc.access_path) html += ' &middot; Access: ' + escapeHtml(loc.access_path);
                if (loc.mtime) html += ' &middot; Modified: ' + escapeHtml(loc.mtime);
                html += '</div></div>';
            }
            html += '</div></div>';
        }

        html += '</div>';
        content.innerHTML = html;
    } catch (e) {
        content.innerHTML = '<span class="text-red-400">Error: ' + escapeHtml(e.message) + '</span>';
    }
}

function closeModal() {
    document.getElementById('modal-overlay').classList.add('hidden');
}

// ---------------------------------------------------------------
// Duplicates
// ---------------------------------------------------------------

async function loadDuplicates() {
    const container = document.getElementById('dupes-results');
    container.innerHTML = '<span class="text-gray-500">Loading...</span>';

    try {
        const resp = await fetch('/api/duplicates?limit=100');
        const data = await resp.json();

        if (!data.length) {
            container.innerHTML = '<span class="text-gray-500">No duplicates found.</span>';
            return;
        }

        let html = '<div class="overflow-x-auto"><table class="results-table"><thead><tr>';
        html += '<th>Hash</th><th>Size</th><th>Servers</th><th>Locations</th><th>Format</th>';
        html += '</tr></thead><tbody>';

        for (const d of data) {
            html += '<tr class="clickable" onclick="showFileDetail(\'' + escapeHtml(d.content_hash) + '\')">';
            html += '<td class="font-mono text-xs">' + escapeHtml(d.content_hash.substring(0, 16)) + '</td>';
            html += '<td class="whitespace-nowrap">' + formatSize(d.file_size) + '</td>';
            html += '<td class="text-center">' + d.server_count + '</td>';
            html += '<td class="text-center">' + d.location_count + '</td>';
            html += '<td>' + escapeHtml(d.sonar_format || '-') + '</td>';
            html += '</tr>';
        }

        html += '</tbody></table></div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<span class="text-red-400">Error: ' + escapeHtml(e.message) + '</span>';
    }
}

// ---------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------

async function loadHosts() {
    const container = document.getElementById('hosts-results');
    container.innerHTML = '<span class="text-gray-500">Loading...</span>';

    try {
        const resp = await fetch('/api/hosts');
        const data = await resp.json();

        if (!data.length) {
            container.innerHTML = '<span class="text-gray-500">No hosts discovered yet.</span>';
            return;
        }

        let html = '<div class="overflow-x-auto"><table class="results-table"><thead><tr>';
        html += '<th>IP</th><th>Hostname</th><th>Method</th><th>SSH</th><th>Status</th><th>Files</th>';
        html += '</tr></thead><tbody>';

        for (const h of data) {
            const sshBadge = h.ssh
                ? '<span class="text-green-400">OK</span>'
                : '<span class="text-red-400">NO</span>';
            html += '<tr>';
            html += '<td class="font-mono text-xs">' + escapeHtml(h.ip) + '</td>';
            html += '<td>' + escapeHtml(h.hostname) + '</td>';
            html += '<td>' + escapeHtml(h.method) + '</td>';
            html += '<td class="text-center">' + sshBadge + '</td>';
            html += '<td>' + escapeHtml(h.status) + '</td>';
            html += '<td class="text-right">' + h.files.toLocaleString() + '</td>';
            html += '</tr>';
        }

        html += '</tbody></table></div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<span class="text-red-400">Error: ' + escapeHtml(e.message) + '</span>';
    }
}

// ---------------------------------------------------------------
// Stats
// ---------------------------------------------------------------

async function loadStats() {
    const container = document.getElementById('stats-results');
    container.innerHTML = '<span class="text-gray-500">Loading...</span>';

    try {
        const resp = await fetch('/api/stats');
        const s = await resp.json();

        const dedup = (s.total_locations / Math.max(s.unique_files, 1)).toFixed(1);

        let html = '<div class="grid grid-cols-2 md:grid-cols-4 gap-4">';

        const cards = [
            ['Unique Files', s.unique_files.toLocaleString()],
            ['Total Locations', s.total_locations.toLocaleString()],
            ['Unique Data Size', formatSize(s.unique_bytes)],
            ['Dedup Ratio', dedup + 'x'],
            ['NFS Servers', s.nfs_servers_with_data],
            ['NFS Locations', s.nfs_locations.toLocaleString()],
            ['Local Locations', s.local_locations.toLocaleString()],
            ['Sonar Formats', s.sonar_formats],
        ];

        for (const [label, value] of cards) {
            html += '<div class="stat-card"><div class="label">' + label + '</div>';
            html += '<div class="value">' + value + '</div></div>';
        }

        html += '</div>';
        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = '<span class="text-red-400">Error: ' + escapeHtml(e.message) + '</span>';
    }
}

// ---------------------------------------------------------------
// Init
// ---------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
    showPage('search');

    // Load filter dropdowns
    fetch('/api/servers').then(r => r.json()).then(servers => {
        const sel = document.getElementById('filter-server');
        for (const s of servers) {
            const opt = document.createElement('option');
            opt.value = s;
            opt.textContent = s;
            sel.appendChild(opt);
        }
    }).catch(() => {});

    fetch('/api/formats').then(r => r.json()).then(formats => {
        const sel = document.getElementById('filter-format');
        for (const f of formats) {
            const opt = document.createElement('option');
            opt.value = f;
            opt.textContent = f;
            sel.appendChild(opt);
        }
    }).catch(() => {});
});
