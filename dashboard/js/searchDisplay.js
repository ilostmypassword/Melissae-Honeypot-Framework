// Display table
export function displayResults(filteredLogs, searchTerms) {
    const resultsDiv = document.getElementById('results');
    const table = resultsDiv.querySelector('.log-table');
    const tbody = table.querySelector('tbody');
    const noResults = resultsDiv.querySelector('.no-results');

    tbody.innerHTML = '';
    
    if (filteredLogs.length === 0) {
        table.style.display = 'none';
        noResults.textContent = 'No results found.';
        noResults.style.display = 'block';
        return;
    }

    filteredLogs.forEach(log => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${formatProtocol(log.protocol)}</td>
            <td>${log.date}</td>
            <td>${log.hour}</td>
            <td>${highlightText(log.ip, searchTerms)}</td>
            <td>${highlightText(log.user || '-', searchTerms)}</td>
            <td>${highlightText(log.action, searchTerms)}</td>
            <td>${highlightText(log["user-agent"] || '-', searchTerms)}
            <td>${highlightText(log.path || '-', searchTerms)}
        `;
        
        tbody.appendChild(row);
    });

    table.style.display = 'table';
    noResults.style.display = 'none';
}

// Format protocols
function formatProtocol(protocol) {
    const colors = {
        'ssh': 'protocol-ssh',
        'ftp': 'protocol-ftp',
        'http': 'protocol-http',
        'modbus': 'protocol-modbus',
        'mqtt': 'protocol-mqtt'
    };
    return `<span class="protocol-tag ${colors[protocol] || ''}">${protocol.toUpperCase()}</span>`;
}

function highlightText(text, terms) {
    if (!terms || terms.length === 0) return text;
    
    terms.forEach(term => {
        const regex = new RegExp(`(${term})`, 'gi');
        text = text.replace(regex, '<span class="highlight">$1</span>');
    });
    
    return text;
}

// Export button
export function setupExportButton(filteredLogs) {
    const exportButton = document.getElementById('exportButton');
    const searchQuery = document.getElementById('searchInput').value.trim();
    
    if (filteredLogs.length > 0) {
        exportButton.style.display = 'inline-block';
        exportButton.onclick = () => {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const sanitizedQuery = searchQuery.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_');
            const fileName = `melissae-logs_${sanitizedQuery || 'all'}_${timestamp}.json`;
            
            const dataStr = JSON.stringify(filteredLogs, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
            
            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', fileName);
            linkElement.click();
        };
    } else {
        exportButton.style.display = 'none';
    }
}
