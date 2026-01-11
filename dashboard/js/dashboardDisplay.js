const API_BASE = '/api';
let logs = [];

window.redirectToSearch = function(searchTerm) {
    window.location.href = `search.html?search=${encodeURIComponent(searchTerm)}`;
};

async function loadLogs() {
    try {
        const statsGrid = document.getElementById('statsGrid');
        statsGrid.innerHTML = '<div class="stat-card" style="grid-column: span 1;"><div class="stat-value">↻</div><div class="stat-label">Loading...</div></div>';
        
        const response = await fetch(`${API_BASE}/logs`);
        if (!response.ok) throw new Error(`API error ${response.status}`);
        logs = await response.json();
        generateStatistics();
        renderCharts();
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('statsGrid').innerHTML = `
            <div class="stat-card error" style="grid-column: span 1;">
                <div class="stat-value">⚠</div>
                <div class="stat-label">Unable to load data</div>
            </div>`;
    }
}

// Modules statistics
function generateStatistics() {
    const stats = {
        totalLogs: logs.length,
        sshLogs: logs.filter(log => log.protocol === 'ssh').length,
        ftpLogs: logs.filter(log => log.protocol === 'ftp').length,
        uniqueIPs: new Set(logs.map(log => log.ip)).size,
        httpLogs: logs.filter(log => log.protocol === 'http').length,
        modbusLogs: logs.filter(log => log.protocol === 'modbus').length,
        mqttLogs: logs.filter(log => log.protocol === 'mqtt').length,
        successSSHLogins: logs.filter(log => log.action?.toLowerCase().includes('successful') && log.protocol === 'ssh').length,
        successFTPLogins: logs.filter(log => log.action?.toLowerCase().includes('successful') && log.protocol === 'ftp').length,
        failedSSHAttempts: logs.filter(log => log.action?.toLowerCase().includes('failed') && log.protocol === 'ssh').length,
        failedFTPAttempts: logs.filter(log => log.action?.toLowerCase().includes('failed') && log.protocol === 'ftp').length,
        modbusReads: logs.filter(log => log.protocol === 'modbus' && log.action?.toLowerCase().includes('read')).length,
        modbusWrites: logs.filter(log => log.protocol === 'modbus' && log.action?.toLowerCase().includes('write')).length
    };

    const statsHTML = `
        <div class="stat-card">
            <div class="stat-value">${stats.totalLogs}</div>
            <div class="stat-label">Total Logs</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.uniqueIPs}</div>
            <div class="stat-label">Unique IPs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:http')" title="Click to search">
            <div class="stat-value">${stats.httpLogs}</div>
            <div class="stat-label">HTTP Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:ssh')" title="Click to search">
            <div class="stat-value">${stats.sshLogs}</div>
            <div class="stat-label">SSH Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:ftp')" title="Click to search">
            <div class="stat-value">${stats.ftpLogs}</div>
            <div class="stat-label">FTP Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:modbus')" title="Click to search">
            <div class="stat-value">${stats.modbusLogs}</div>
            <div class="stat-label">Modbus Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:mqtt')" title="Click to search">
            <div class="stat-value">${stats.mqttLogs}</div>
            <div class="stat-label">MQTT Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('action:failed and protocol:ssh')" title="Click to search">
            <div class="stat-value">${stats.failedSSHAttempts}</div>
            <div class="stat-label">Failed SSH Logins</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('action:failed and protocol:ftp')" title="Click to search">
            <div class="stat-value">${stats.failedFTPAttempts}</div>
            <div class="stat-label">Failed FTP Logins</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('action:read and protocol:modbus')" title="Click to search">
            <div class="stat-value">${stats.modbusReads}</div>
            <div class="stat-label">Modbus Reads</div>
        </div>
        <div class="stat-card ${stats.successSSHLogins > 0 ? 'alert' : 'success'}" onclick="redirectToSearch('action:successful and protocol:ssh')" title="Click to search">
            <div class="stat-value">${stats.successSSHLogins}</div>
            <div class="stat-label">Successful SSH Logins</div>
        </div>
        <div class="stat-card ${stats.successFTPLogins > 0 ? 'alert' : 'success'}" onclick="redirectToSearch('action:successful and protocol:ftp')" title="Click to search">
            <div class="stat-value">${stats.successFTPLogins}</div>
            <div class="stat-label">Successful FTP Logins</div>
        </div>
        <div class="stat-card ${stats.modbusWrites > 0 ? 'alert' : 'success'}" onclick="redirectToSearch('action:write and protocol:modbus')" title="Click to search">
            <div class="stat-value">${stats.modbusWrites}</div>
            <div class="stat-label">Modbus Writes</div>
        </div>
    `;

    document.getElementById('statsGrid').innerHTML = statsHTML;
}

// Charts 
function renderCharts() {
    const hours = Array.from({length: 24}, (_, i) => `${i.toString().padStart(2, '0')}h`);
    const activityData = new Array(24).fill(0);
    
    logs.forEach(log => {
        const hour = parseInt(log.hour?.split(':')[0]) || 0;
        if (hour >= 0 && hour < 24) activityData[hour]++;
    });

    const activityChartCanvas = document.getElementById('activityChart');
    activityChartCanvas.style.cursor = 'pointer';
    
    const activityChart = new Chart(activityChartCanvas, {
        type: 'line',
        data: {
            labels: hours,
            datasets: [{
                label: 'Activity',
                data: activityData,
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointRadius: 5,
                pointBackgroundColor: '#ef4444',
                pointBorderColor: 'white',
                pointBorderWidth: 2,
                pointHoverRadius: 7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: {
                padding: {
                    top: 20,
                    bottom: 20
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: '#e0e0e0',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#666666'
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#666666'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                filler: {
                    propagate: true
                }
            }
        }
    });

    activityChartCanvas.onclick = (event) => {
        const canvasPosition = Chart.helpers.getRelativePosition(event, activityChart);
        const dataX = activityChart.scales.x.getValueForPixel(canvasPosition.x);
        if (dataX >= 0 && dataX < 24) {
            const hour = Math.floor(dataX);
            redirectToSearch(`hour:${hour.toString().padStart(2, '0')}`);
        }
    };

    const protocolData = {
        ssh: logs.filter(log => log.protocol === 'ssh').length,
        ftp: logs.filter(log => log.protocol === 'ftp').length,
        http: logs.filter(log => log.protocol === 'http').length,
        modbus: logs.filter(log => log.protocol === 'modbus').length,
        mqtt: logs.filter(log => log.protocol === 'mqtt').length
    };

    const protocolColors = ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ef4444'];
    const protocolNames = ['SSH', 'FTP', 'HTTP', 'Modbus', 'MQTT'];
    const protocolKeys = ['ssh', 'ftp', 'http', 'modbus', 'mqtt'];

    const protocolChartCanvas = document.getElementById('protocolChart');
    protocolChartCanvas.style.cursor = 'pointer';
    
    const protocolChart = new Chart(protocolChartCanvas, {
        type: 'doughnut',
        data: {
            labels: protocolNames,
            datasets: [{
                data: [protocolData.ssh, protocolData.ftp, protocolData.http, protocolData.modbus, protocolData.mqtt],
                backgroundColor: protocolColors,
                borderColor: 'white',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 13,
                            weight: 500
                        },
                        color: '#666666'
                    }
                }
            }
        }
    });

    protocolChartCanvas.onclick = (event) => {
        const canvasPosition = Chart.helpers.getRelativePosition(event, protocolChart);
        const dataX = protocolChart.scales.x?.getValueForPixel(canvasPosition.x);
        const canvasElements = protocolChart.getElementsAtEventForMode(
            event,
            'nearest',
            { intersect: true },
            true
        );
        if (canvasElements.length > 0) {
            const protocol = protocolKeys[canvasElements[0].index];
            redirectToSearch(`protocol:${protocol}`);
        }
    };

    const ipCounts = logs.reduce((acc, log) => {
        const ip = log.ip || 'Unknown';
        acc[ip] = (acc[ip] || 0) + 1;
        return acc;
    }, {});

    const sortedIPs = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    const ipsData = {
        labels: sortedIPs.map(ip => ip[0]),
        counts: sortedIPs.map(ip => ip[1])
    };

    const dangerColors = ['#ef4444', '#f87171', '#fca5a5', '#dc2626', '#991b1b'];

    const ipsChartCanvas = document.getElementById('ipsChart');
    ipsChartCanvas.style.cursor = 'pointer';
    
    const ipsChart = new Chart(ipsChartCanvas, {
        type: 'doughnut',
        data: {
            labels: ipsData.labels,
            datasets: [{
                data: ipsData.counts,
                backgroundColor: dangerColors,
                borderColor: 'white',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12,
                            weight: 500
                        },
                        color: '#666666'
                    }
                }
            }
        }
    });

    ipsChartCanvas.onclick = (event) => {
        const canvasElements = ipsChart.getElementsAtEventForMode(
            event,
            'nearest',
            { intersect: true },
            true
        );
        if (canvasElements.length > 0) {
            const ip = ipsData.labels[canvasElements[0].index];
            redirectToSearch(`ip:${ip}`);
        }
    };
}

loadLogs();
