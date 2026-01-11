const API_BASE = '/api';
let threats = [];
let currentThreatPage = 1;
const THREATS_PER_PAGE = 20;
const killchainCache = new Map();
let reasonModal;

const killchainPanel = document.getElementById('killchainPanel');
const killchainContent = document.getElementById('killchainContent');
const killchainTitle = document.getElementById('killchainTitle');
const killchainCloseBtn = document.getElementById('killchainClose');

// Get severity score for sorting
function getSeverityScore(threat) {
    if (Number.isFinite(threat['protocol-score'])) return threat['protocol-score'];
    const verdictRank = { malicious: 4, suspicious: 2, benign: 1 };
    return verdictRank[threat.verdict?.toLowerCase()] || 0;
}

function getConfidenceScore(threat) {
    const c = Number(threat?.confidence);
    return Number.isFinite(c) ? c : 0;
}

// Sort by severity 
function sortThreats(threatsToSort) {
    return [...threatsToSort].sort((a, b) => {
        const diff = getSeverityScore(b) - getSeverityScore(a);
        if (diff !== 0) return diff;

        const confDiff = getConfidenceScore(b) - getConfidenceScore(a);
        if (confDiff !== 0) return confDiff;

        return String(a.ip).localeCompare(String(b.ip));
    });
}

window.redirectToSearch = function(searchTerm) {
    window.location.href = `search.html?search=${encodeURIComponent(searchTerm)}`;
};

// Killchain handlers
if (killchainCloseBtn) {
    killchainCloseBtn.addEventListener('click', () => {
        killchainPanel.classList.add('hidden');
        killchainContent.innerHTML = '<div class="killchain-empty">Aucune IP sélectionnée</div>';
    });
}

async function openKillchain(ip) {
    if (!killchainPanel || !killchainContent) return;

    killchainPanel.classList.remove('hidden');
    killchainTitle.textContent = `${ip}`;
    killchainContent.innerHTML = '<div class="killchain-loading"> Loading Killchain...</div>';

    try {
        const events = await fetchKillchain(ip);
        renderKillchain(ip, events);
        killchainPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
        console.error(err);
        killchainContent.innerHTML = '<div class="killchain-empty">Unable to load killchain</div>';
    }
}

async function fetchKillchain(ip) {
    if (killchainCache.has(ip)) return killchainCache.get(ip);

    const response = await fetch(`${API_BASE}/threats/${encodeURIComponent(ip)}/killchain`);
    if (!response.ok) throw new Error(`Killchain API error ${response.status}`);

    const payload = await response.json();
    const events = Array.isArray(payload?.events) ? payload.events : Array.isArray(payload) ? payload : [];
    killchainCache.set(ip, events);
    return events;
}

function normalizeEvent(event) {
    const rawTime = event.timestamp || event.time || event.date || event.datetime;
    const ts = rawTime ? new Date(rawTime).getTime() : NaN;
    const protocol = (event.protocol || event.proto || 'other').toLowerCase();
    const description = event.description || event.action || event.event || '';
    return { ts, protocol, description };
}

function formatEventTime(ts) {
    if (!Number.isFinite(ts)) return 'Temps inconnu';
    const d = new Date(ts);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

function protocolClass(protocol) {
    const map = {
        ssh: 'protocol-ssh',
        ftp: 'protocol-ftp',
        http: 'protocol-http',
        modbus: 'protocol-modbus',
        mqtt: 'protocol-mqtt'
    };
    return map[protocol] || 'protocol-other';
}

function renderKillchain(ip, rawEvents) {
    if (!killchainContent) return;

    const events = rawEvents.map(normalizeEvent).filter(e => Number.isFinite(e.ts));

    if (events.length === 0) {
        killchainContent.innerHTML = '<div class="killchain-empty">Aucun événement trouvé pour cette IP</div>';
        return;
    }
    const protoMap = new Map();
    events.forEach(evt => {
        const proto = evt.protocol;
        const found = protoMap.get(proto) || { protocol: proto, start: evt.ts, end: evt.ts, first: evt.ts };
        found.start = Math.min(found.start, evt.ts);
        found.end = Math.max(found.end, evt.ts);
        found.first = Math.min(found.first, evt.ts);
        protoMap.set(proto, found);
    });

    const grouped = Array.from(protoMap.values()).sort((a, b) => {
        const aKey = a.start !== a.end ? a.end : a.first;
        const bKey = b.start !== b.end ? b.end : b.first;
        return aKey - bKey;
    });

    const steps = grouped.map((item, idx) => {
        const cls = protocolClass(item.protocol);
        const step = idx + 1;
        const range = item.start === item.end
            ? formatEventTime(item.start)
            : `${formatEventTime(item.start)} → ${formatEventTime(item.end)}`;
        return `
            <div class="killchain-step">
                <div class="killchain-step-index">${step}</div>
                <div class="killchain-step-dot ${cls}"></div>
                <div class="killchain-step-body">
                    <div class="killchain-step-title">${item.protocol.toUpperCase()}</div>
                    <div class="killchain-step-meta">${range}</div>
                </div>
            </div>`;
    }).join('');

    const legendProtocols = Array.from(new Set(grouped.map(e => protocolClass(e.protocol))));

    const legend = legendProtocols.map(cls => {
        const label = cls.replace('protocol-', '').toUpperCase();
        return `<span class="killchain-legend-item"><span class="killchain-legend-swatch ${cls}"></span>${label}</span>`;
    }).join('');

    killchainContent.innerHTML = `
        <div class="killchain-steps">${steps}</div>
        <div class="killchain-legend">${legend}</div>
    `;
}

window.openKillchain = openKillchain;

// Load threats data
async function loadThreats() {
    try {
        const statsGrid = document.getElementById('threatStatsGrid');
        const filterSelect = document.getElementById('filterType');
        
        filterSelect.disabled = true;
        
        const response = await fetch(`${API_BASE}/threats`);
        if (!response.ok) throw new Error(`API error ${response.status}`);
        threats = sortThreats(await response.json());
        generateThreatStatistics();
        renderThreatChart();
        renderMaliciousList(threats);
        setupExportButton();
        
        filterSelect.disabled = false;
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('threatStatsGrid').innerHTML = `
            <div class="stat-card error" style="grid-column: span 1;">
                <div class="stat-value">⚠</div>
                <div class="stat-label">Unable to load threats</div>
            </div>`;
    }
}

// Threats stats
function generateThreatStatistics() {
    const stats = {
        totalThreats: threats.length,
        benignThreats: threats.filter(threat => threat.verdict?.toLowerCase() === 'benign').length,
        suspiciousThreats: threats.filter(threat => threat.verdict?.toLowerCase() === 'suspicious').length,
        maliciousThreats: threats.filter(threat => threat.verdict?.toLowerCase() === 'malicious').length,
    };

    const statsHTML = `
        <div class="stat-card">
            <div class="stat-value">${stats.totalThreats}</div>
            <div class="stat-label">Total Threats</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.benignThreats}</div>
            <div class="stat-label">Benign</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.suspiciousThreats}</div>
            <div class="stat-label">Suspicious</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.maliciousThreats}</div>
            <div class="stat-label">Malicious</div>
        </div>
    `;

    document.getElementById('threatStatsGrid').innerHTML = statsHTML;
}

function renderThreatChart() {
    const chartCanvas = document.getElementById('threatChart');
    if (!chartCanvas) return;

    const threatsByVerdict = threats.reduce((acc, threat) => {
        const verdict = threat.verdict?.toLowerCase() || 'unknown';
        acc[verdict] = (acc[verdict] || 0) + 1;
        return acc;
    }, {});

    const verdictOrder = ['benign', 'suspicious', 'malicious'];
    const verdictColors = {
        'benign': '#10b981',
        'suspicious': '#f59e0b',
        'malicious': '#ef4444'
    };

    const labels = verdictOrder.filter(v => threatsByVerdict[v]);
    const data = labels.map(v => threatsByVerdict[v]);
    const colors = labels.map(v => verdictColors[v]);

    new Chart(chartCanvas, {
        type: 'bar',
        data: {
            labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{
                label: 'Threat Count',
                data: data,
                backgroundColor: colors,
                borderRadius: 8,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#64748b'
                    }
                },
                x: {
                    beginAtZero: true,
                    grid: {
                        color: '#e2e8f0'
                    },
                    ticks: {
                        color: '#64748b'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Threats list
function escapeHtml(text = '') {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatConfidence(threat) {
    const c = threat?.confidence;
    if (Number.isFinite(c)) {
        return `${Math.round(c * 100)}%`;
    }
    return 'N/A';
}

function formatReasons(threat) {
    const reasons = Array.isArray(threat?.reasons) ? threat.reasons : [];
    if (!reasons.length) return '-';
    const text = reasons.join(' • ');
    return `<span class="reason-chip" title="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
}

function ensureReasonModal() {
    if (reasonModal) return reasonModal;
    const overlay = document.createElement('div');
    overlay.className = 'reason-modal-overlay hidden';
    overlay.innerHTML = `
        <div class="reason-modal" role="dialog" aria-modal="true" aria-labelledby="reasonModalTitle">
            <div class="reason-modal-header">
                <div>
                    <p class="reason-modal-label">Threat details</p>
                    <div class="reason-modal-title-row">
                        <h3 id="reasonModalTitle">Details</h3>
                        <span id="reasonModalVerdict" class="verdict-chip verdict-benign">BENIGN</span>
                    </div>
                </div>
                <button class="reason-modal-close" aria-label="Close" id="reasonModalClose">×</button>
            </div>
            <div class="reason-modal-body">
                <div class="reason-meta" id="reasonMeta"></div>
                <div class="reason-list" id="reasonList"></div>
            </div>
        </div>`;

    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            overlay.classList.add('hidden');
        }
    });

    document.body.appendChild(overlay);
    const closeBtn = overlay.querySelector('#reasonModalClose');
    closeBtn.addEventListener('click', () => overlay.classList.add('hidden'));

    reasonModal = overlay;
    return overlay;
}

window.openReasonModal = function(ip) {
    const threat = threats.find(t => t.ip === ip);
    if (!threat) return;
    const overlay = ensureReasonModal();
    const meta = overlay.querySelector('#reasonMeta');
    const list = overlay.querySelector('#reasonList');
    const title = overlay.querySelector('#reasonModalTitle');
    const verdictChip = overlay.querySelector('#reasonModalVerdict');

    const verdict = (threat.verdict || 'unknown').toLowerCase();
    const verdictLabel = (threat.verdict || 'unknown').toUpperCase();
    const verdictClass = getVerdictClass(threat.verdict);
    const score = threat['protocol-score'] ?? 'N/A';
    const confidence = formatConfidence(threat);
    const firstSeen = threat.first_seen || 'N/A';
    const lastSeen = threat.last_seen || 'N/A';

    const headerText = `Details for ${ip}`;
    title.textContent = headerText;
    if (verdictChip) {
        verdictChip.textContent = verdictLabel;
        verdictChip.className = `verdict-chip ${verdictClass}`;
    }
    meta.innerHTML = `
        <div class="reason-hero">
            <div>
                <p class="reason-modal-label">IP address</p>
                <h3>${ip}</h3>
            </div>
        </div>
        <div class="reason-metrics two-col">
            <div class="metric-chip">
                <span>Score</span>
                <strong>${score}</strong>
            </div>
            <div class="metric-chip">
                <span>Confidence</span>
                <strong>${confidence}</strong>
            </div>
            <div class="metric-chip">
                <span>First seen</span>
                <strong>${firstSeen}</strong>
            </div>
            <div class="metric-chip">
                <span>Last seen</span>
                <strong>${lastSeen}</strong>
            </div>
        </div>
    `;

    const reasons = Array.isArray(threat.reasons) ? threat.reasons : [];
    if (!reasons.length) {
        list.innerHTML = '<div class="reason-empty">No reasons available</div>';
    } else {
        list.innerHTML = `
            <div class="reason-list-title">Reasons</div>
            <ul class="reason-pill-list">
                ${reasons.map(r => `<li><span class="pill-bullet"></span><span>${escapeHtml(r)}</span></li>`).join('')}
            </ul>
        `;
    }

    overlay.classList.remove('hidden');
};

function renderMaliciousList(threatsToRender) {
    const listContainer = document.getElementById('maliciousList');
    const sortedThreats = sortThreats(threatsToRender);
    
    if (sortedThreats.length === 0) {
        listContainer.innerHTML = '<div class="no-results">No threats found</div>';
        return;
    }

    currentThreatPage = 1;
    const totalPages = Math.ceil(sortedThreats.length / THREATS_PER_PAGE);
    
    function renderPage(pageNum) {
        const startIdx = (pageNum - 1) * THREATS_PER_PAGE;
        const endIdx = startIdx + THREATS_PER_PAGE;
        const pageThreats = sortedThreats.slice(startIdx, endIdx);

        const paginationHTML = totalPages > 1 ? `
            <div class="pagination-container">
                <button class="pagination-btn" ${pageNum === 1 ? 'disabled' : ''} onclick="goToThreatPage(${pageNum - 1})">← Previous</button>
                <span class="pagination-info">Page ${pageNum} of ${totalPages} (${sortedThreats.length} total)</span>
                <button class="pagination-btn" ${pageNum === totalPages ? 'disabled' : ''} onclick="goToThreatPage(${pageNum + 1})">Next →</button>
            </div>
        ` : '';

        listContainer.innerHTML = `
            ${paginationHTML}
            <table class="log-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>IP Address</th>
                        <th>Verdict</th>
                        <th>Score</th>
                        <th>Confidence</th>
                        <th>Details</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${pageThreats.map(threat => `
                        <tr>
                            <td>${(threat.type || 'IP').toUpperCase()}</td>
                            <td>${threat.ip}</td>
                            <td>
                                <span class="verdict-tag ${getVerdictClass(threat.verdict)}">
                                    ${(threat.verdict || 'unknown').toUpperCase()}
                                </span>
                            </td>
                            <td><code>${threat['protocol-score'] || 'N/A'}</code></td>
                            <td><code>${formatConfidence(threat)}</code></td>
                            <td>
                                <button class="action-btn action-details" onclick="openReasonModal('${threat.ip}')">DETAILS</button>
                            </td>
                            <td>
                                <div class="threat-actions">
                                    <button class="action-btn action-killchain" onclick="openKillchain('${threat.ip}')">KILLCHAIN</button>
                                    <button class="action-btn action-logs" onclick="redirectToSearch('ip:${threat.ip}')">LOGS</button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            ${paginationHTML}
        `;
    }

    window.goToThreatPage = function(pageNum) {
        if (pageNum >= 1 && pageNum <= totalPages) {
            currentThreatPage = pageNum;
            renderPage(pageNum);
        }
    };

    renderPage(currentThreatPage);
}

// Export button
function setupExportButton() {
    const stixButton = document.getElementById('exportStixButton');
    if (stixButton) {
        stixButton.onclick = () => {
            if (!threats || threats.length === 0) return;
            const bundle = buildStixBundle(threats);
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
            const fileName = `melissae-iocs_stix_${timestamp}.json`;
            const dataStr = JSON.stringify(bundle, null, 2);
            const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`;

            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', fileName);
            document.body.appendChild(linkElement);
            linkElement.click();
            document.body.removeChild(linkElement);
        };
    }
}

function buildStixBundle(threatList) {
    const now = new Date().toISOString();
    const identityId = `identity--${uuidv4()}`;

    const identity = {
        type: 'identity',
        spec_version: '2.1',
        id: identityId,
        created: now,
        modified: now,
        name: 'Melissae',
        identity_class: 'organization'
    };

    const indicators = threatList.map(threat => {
        const indicatorId = `indicator--${uuidv4()}`;
        const ip = threat.ip;
        const verdict = (threat.verdict || 'unknown').toLowerCase();
        const score = threat['protocol-score'];
        const scoreText = Number.isFinite(score) ? `with a score of ${score}` : 'with no score available';

        return {
            type: 'indicator',
            spec_version: '2.1',
            id: indicatorId,
            created: now,
            modified: now,
            name: `Melissae IOC ${ip}`,
            description: `${verdict} IP detected on a Melissae honeypot endpoint ${scoreText}`,
            labels: ['malicious-activity', verdict],
            pattern_type: 'stix',
            pattern: `[ipv4-addr:value = '${ip}']`,
            valid_from: now,
            created_by_ref: identityId,
            x_melissae_verdict: verdict,
            x_melissae_score: score
        };
    });

    return {
        type: 'bundle',
        id: `bundle--${uuidv4()}`,
        objects: [identity, ...indicators]
    };
}

function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = crypto.getRandomValues(new Uint8Array(1))[0] & 15;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}

function getVerdictClass(verdict) {
    const classes = {
        'benign': 'verdict-benign',
        'suspicious': 'verdict-suspicious',
        'malicious': 'verdict-malicious'
    };
    return classes[verdict?.toLowerCase()] || 'verdict-benign';
}

// Verdict filtering
const filterElement = document.getElementById('filterType');
if (filterElement) {
    filterElement.addEventListener('change', event => {
        const filter = event.target.value;
        const filteredThreats = filter === 'all'
            ? threats
            : threats.filter(threat => threat.verdict?.toLowerCase() === filter);

        renderMaliciousList(filteredThreats);
    });
}

loadThreats();
