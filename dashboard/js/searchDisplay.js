// Display table
let currentSearchPage = 1;
const LOGS_PER_PAGE = 50;
let lastSearchTerms = [];

// Check which columns have data
function getColumnsWithData(filteredLogs) {
    const hasData = {
        protocol: true,
        date: true,
        hour: true,
        ip: true,
        user: false,
        action: true,
        userAgent: false,
        path: false
    };

    filteredLogs.forEach(log => {
        if (log.user && log.user.trim()) hasData.user = true;
        if (log["user-agent"] && log["user-agent"].trim()) hasData.userAgent = true;
        if (log.path && log.path.trim()) hasData.path = true;
    });

    return hasData;
}

export function displayResults(filteredLogs, searchTerms) {
    const resultsDiv = document.getElementById('results');
    const wrapper = resultsDiv.querySelector('.log-table-wrapper');
    const table = resultsDiv.querySelector('.log-table');
    const thead = table.querySelector('thead');
    const noResults = resultsDiv.querySelector('.no-results');
    const headerNames = ['protocol', 'date', 'hour', 'ip', 'user', 'action', 'userAgent', 'path'];

    resultsDiv.style.display = 'block';

    if (filteredLogs.length === 0) {
        wrapper.style.display = 'none';
        table.style.display = 'none';
        noResults.innerHTML = '<strong>No results found</strong><br><small>Try adjusting your search criteria</small>';
        noResults.style.display = 'block';
        return;
    }

    currentSearchPage = 1;
    lastSearchTerms = searchTerms;
    const totalPages = Math.ceil(filteredLogs.length / LOGS_PER_PAGE);
    const columnsWithData = getColumnsWithData(filteredLogs);
    
    // Update header visibility and count visible columns
    const headers = thead.querySelectorAll('th');
    let visibleColumnCount = 0;
    headers.forEach((th, idx) => {
        const colName = headerNames[idx];
        if (!columnsWithData[colName]) {
            th.style.display = 'none';
        } else {
            th.style.display = '';
            visibleColumnCount++;
        }
    });
    
    // Add class to table based on visible column count
    table.className = 'log-table';
    if (visibleColumnCount <= 4) {
        table.classList.add('cols-4');
    } else if (visibleColumnCount <= 6) {
        table.classList.add('cols-6');
    } else {
        table.classList.add('cols-8');
    }
    
    function renderSearchPage(pageNum) {
        const startIdx = (pageNum - 1) * LOGS_PER_PAGE;
        const endIdx = startIdx + LOGS_PER_PAGE;
        const pageLogs = filteredLogs.slice(startIdx, endIdx);
        const tbody = table.querySelector('tbody');

        tbody.innerHTML = '';
        
        pageLogs.forEach(log => {
            const row = document.createElement('tr');
            
            const cells = [
                formatProtocol(log.protocol),
                `<code>${log.date}</code>`,
                `<code>${log.hour}</code>`,
                `<code>${highlightText(log.ip, searchTerms)}</code>`,
                highlightText(log.user || '-', searchTerms),
                highlightText(log.action, searchTerms),
                `<span class="user-agent-cell">${highlightText(log["user-agent"] || '-', searchTerms)}</span>`,
                `<span class="path-cell">${highlightText(log.path || '-', searchTerms)}</span>`
            ];

            row.innerHTML = cells.map((cell, idx) => {
                const colName = headerNames[idx];
                const display = columnsWithData[colName] ? '' : 'style="display: none;"';
                return `<td ${display}>${cell}</td>`;
            }).join('');
            
            tbody.appendChild(row);
        });

        const paginationHTML = totalPages > 1 ? `
            <div class="pagination-container">
                <button class="pagination-btn" ${pageNum === 1 ? 'disabled' : ''} onclick="goToSearchPage(${pageNum - 1})">← Previous</button>
                <span class="pagination-info">Page ${pageNum} of ${totalPages} (${filteredLogs.length} total)</span>
                <button class="pagination-btn" ${pageNum === totalPages ? 'disabled' : ''} onclick="goToSearchPage(${pageNum + 1})">Next →</button>
            </div>
        ` : '';

        const paginationContainers = resultsDiv.querySelectorAll('.pagination-container');
        paginationContainers.forEach(p => p.remove());
        
        if (totalPages > 1) {
            const topPagination = document.createElement('div');
            topPagination.innerHTML = paginationHTML;
            resultsDiv.insertBefore(topPagination.firstElementChild, wrapper);
            
            const bottomPagination = document.createElement('div');
            bottomPagination.innerHTML = paginationHTML;
            resultsDiv.insertBefore(bottomPagination.firstElementChild, wrapper.nextSibling);
        }
    }

    window.goToSearchPage = function(pageNum) {
        if (pageNum >= 1 && pageNum <= totalPages) {
            currentSearchPage = pageNum;
            renderSearchPage(pageNum);
        }
    };

    wrapper.style.display = 'block';
    table.style.display = 'table';
    noResults.style.display = 'none';
    resultsDiv.style.display = 'block';
    renderSearchPage(currentSearchPage);
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
    return `<span class="protocol-tag ${colors[protocol?.toLowerCase()] || ''}">${protocol?.toUpperCase() || 'N/A'}</span>`;
}

function highlightText(text, terms) {
    if (!text || !terms || terms.length === 0) return text;
    
    let highlighted = String(text);
    terms.forEach(term => {
        if (term.trim()) {
            const cleanTerm = term.replace(/^[!=]+/, '').trim();
            const regex = new RegExp(`(${cleanTerm})`, 'gi');
            highlighted = highlighted.replace(regex, '<span class="highlight">$1</span>');
        }
    });
    
    return highlighted;
}

// Export button
export function setupExportButton(filteredLogs) {
    const exportButton = document.getElementById('exportButton');
    const searchQuery = document.getElementById('searchInput')?.value?.trim() || '';
    
    if (filteredLogs.length > 0) {
        exportButton.style.display = 'inline-block';
        exportButton.textContent = `Export (${filteredLogs.length} logs)`;
        exportButton.onclick = () => {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
            const sanitizedQuery = searchQuery.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').slice(0, 30);
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
