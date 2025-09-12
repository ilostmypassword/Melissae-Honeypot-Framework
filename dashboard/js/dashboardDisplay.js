let logs = [];

window.redirectToSearch = function(searchTerm) {
    window.location.href = `search.html?search=${encodeURIComponent(searchTerm)}`;
};

async function loadLogs() {
    try {
        const response = await fetch('json/logs.json');
        if (!response.ok) throw new Error('File not found');
        logs = await response.json();
        generateStatistics();
        renderCharts();
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('statsGrid').innerHTML = `
            <div class="stat-card error">
                <div class="stat-value">!</div>
                <div class="stat-label">Error</div>
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
        successSSHLogins: logs.filter(log => log.action === 'Login successful' && log.protocol === 'ssh').length,
        successFTPLogins: logs.filter(log => log.action === 'Login successful' && log.protocol === 'ftp').length,
        failedSSHAttempts: logs.filter(log => log.action.includes('Login failed') && log.protocol === 'ssh').length,
        failedFTPAttempts: logs.filter(log => log.action.includes('Login failed') && log.protocol === 'ftp').length,
        modbusReads: logs.filter(log => log.protocol === 'modbus' && log.action.includes('Read request')).length,
        modbusWrites: logs.filter(log => log.protocol === 'modbus' && log.action.includes('Write')).length
    };

    const statsHTML = `
        <div class="stat-card"">
            <div class="stat-value">${stats.totalLogs}</div>
            <div class="stat-label">Total Logs</div>
        </div>
        <div class="stat-card"">
            <div class="stat-value">${stats.uniqueIPs}</div>
            <div class="stat-label">Threat IPs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:http')">
            <div class="stat-value">${stats.httpLogs}</div>
            <div class="stat-label">HTTP Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:ssh')">
            <div class="stat-value">${stats.sshLogs}</div>
            <div class="stat-label">SSH Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:ftp')">
            <div class="stat-value">${stats.ftpLogs}</div>
            <div class="stat-label">FTP Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:modbus')">
            <div class="stat-value">${stats.modbusLogs}</div>
            <div class="stat-label">Modbus Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('protocol:mqtt')">
            <div class="stat-value">${stats.mqttLogs}</div>
            <div class="stat-label">MQTT Logs</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('action:failed and protocol:ssh')">
            <div class="stat-value">${stats.failedSSHAttempts}</div>
            <div class="stat-label">Failed SSH Logins</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('action:failed and protocol:ftp')">
            <div class="stat-value">${stats.failedFTPAttempts}</div>
            <div class="stat-label">Failed FTP Logins</div>
        </div>
        <div class="stat-card" onclick="redirectToSearch('action:read and protocol:modbus')">
            <div class="stat-value">${stats.modbusReads}</div>
            <div class="stat-label">Modbus Reads</div>
        </div>
        <div class="stat-card ${stats.successSSHLogins > 0 ? 'alert' : 'success'}" onclick="redirectToSearch('action:successful and protocol:ssh')">
            <div class="stat-value">${stats.successSSHLogins}</div>
            <div class="stat-label">Successful SSH Logins</div>
        </div>
        <div class="stat-card ${stats.successFTPLogins > 0 ? 'alert' : 'success'}" onclick="redirectToSearch('action:successful and protocol:ftp')">
            <div class="stat-value">${stats.successFTPLogins}</div>
            <div class="stat-label">Successful FTP Logins</div>
        </div>
        <div class="stat-card ${stats.modbusWrites > 0 ? 'alert' : 'success'}" onclick="redirectToSearch('action:write and protocol:modbus')">
            <div class="stat-value">${stats.modbusWrites}</div>
            <div class="stat-label">Modbus Writes</div>
        </div>
    `;

    document.getElementById('statsGrid').innerHTML = statsHTML;
}

// Charts 
function renderCharts() {
    const hours = Array.from({length: 24}, (_, i) => `${i}h`);
    const activityData = new Array(24).fill(0);
    
    logs.forEach(log => {
        const hour = parseInt(log.hour.split(':')[0]);
        activityData[hour]++;
    });

    new Chart(document.getElementById('activityChart'), {
        type: 'line',
        data: {
            labels: hours,
            datasets: [{
                label: 'Activity',
                data: activityData,
                borderColor: '#eb4e4e7c',
                fill: true,
                tension: 0.4
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
                        color: '#f8f9fa'
                    }
                },
                x: {
                    grid: {
                        display: false
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

    const protocolData = {
        ssh: logs.filter(log => log.protocol === 'ssh').length,
        ftp: logs.filter(log => log.protocol === 'ftp').length,
        http: logs.filter(log => log.protocol === 'http').length,
        modbus: logs.filter(log => log.protocol === 'modbus').length,
        mqtt: logs.filter(log => log.protocol === 'mqtt').length
    };

    new Chart(document.getElementById('protocolChart'), {
        type: 'doughnut',
        data: {
            labels: ['SSH', 'FTP', 'HTTP', 'Modbus', 'MQTT'],
            datasets: [{
                data: [protocolData.ssh, protocolData.ftp, protocolData.http, protocolData.modbus, protocolData.mqtt],
                backgroundColor: ['#aab2c2', '#b3c2aa', "#b2aac2", "#c2aab2", "#e7e18cff"]
            }]
        },
        options: {
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    const ipCounts = logs.reduce((acc, log) => {
        acc[log.ip] = (acc[log.ip] || 0) + 1;
        return acc;
    }, {});

    const sortedIPs = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    const ipsData = {
        labels: sortedIPs.map(ip => ip[0]),
        counts: sortedIPs.map(ip => ip[1])
    };

    new Chart(document.getElementById('ipsChart'), {
        type: 'doughnut',
        data: {
            labels: ipsData.labels,
            datasets: [{
                data: ipsData.counts,
                backgroundColor: [
                    '#eca1a1',
                    '#b7afaf',
                    '#9a5555',
                    '#5d5a5a',
                    '#b12929'
                ]
            }]
        },
        options: {
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        boxWidth: 15,
                        padding: 15
                    }
                }
            }
        }
    });
}

loadLogs();
