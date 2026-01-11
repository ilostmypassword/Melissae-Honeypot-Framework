const API_BASE = '/api';
export let logs = [];

// Fetch all logs from the API and cache them locally
export async function loadLogs() {
    try {
        const response = await fetch(`${API_BASE}/logs`);
        if (!response.ok) throw new Error(`API error ${response.status}`);
        logs = await response.json();
    } catch (error) {
        console.error("Oh no !", error);
        alert('Error while loading log files');
    }
}

// Search logic
function matchesTerm(log, term) {
    let isNegation = false;
    term = term.trim();

    if (/^(NOT\s+|!)/i.test(term)) {
        isNegation = true;
        term = term.replace(/^(NOT\s+|!)/i, '').trim();
    }

    let match = false;
    if (term.includes(':')) {
        const [field, value] = term.split(':');
        switch(field.toLowerCase()) {
            case 'protocol': match = log.protocol?.toLowerCase().includes(value.toLowerCase()); break;
            case 'action': match = log.action?.toLowerCase().includes(value.toLowerCase()); break;
            case 'ip': match = log.ip?.toLowerCase().includes(value.toLowerCase()); break;
            case 'date': match = log.date?.toLowerCase().includes(value.toLowerCase()); break;
            case 'hour': match = checkHourMatch(log.hour, value); break;
            case 'user': match = (log.user || '').toLowerCase().includes(value.toLowerCase()); break;
            case 'user-agent': match = log["user-agent"]?.toLowerCase().includes(value.toLowerCase()); break;
            case 'path': match = log.path?.toLowerCase().includes(value.toLowerCase()); break;
            default: match = false;
        }
    } else {
        match = Object.values(log).some(val => 
            String(val).toLowerCase().includes(term.toLowerCase())
        );
    }

    return isNegation ? !match : match;
}

// Compare only the hour component between a log entry and a search value
function checkHourMatch(logHour, searchValue) {
    if (!logHour) return false;
    const logHourPart = logHour.toLowerCase().split(':')[0];
    const searchHour = searchValue.toLowerCase().split(':')[0];
    return logHourPart === searchHour;
}

// Parse a query into groups and return matching logs with matched terms
export function searchLogs(query) {
    const termsWithOperators = query.split(/(\bAND\b|\bOR\b)/i);
    const searchGroups = [];
    let currentGroup = [];
    let lastOperator = 'AND';

    termsWithOperators.forEach(term => {
        term = term.trim();
        if (!term) return;
        if (term.match(/^AND$/i)) {
            if (currentGroup.length > 0) {
                searchGroups.push({ terms: currentGroup, operator: lastOperator });
                currentGroup = [];
            }
            lastOperator = 'AND';
        } else if (term.match(/^OR$/i)) {
            if (currentGroup.length > 0) {
                searchGroups.push({ terms: currentGroup, operator: lastOperator });
                currentGroup = [];
            }
            lastOperator = 'OR';
        } else {
            if (term.length >= 2) {
                if (term.includes(':') && term.split(':')[1].trim() === '') return;
                currentGroup.push(term);
            }
        }
    });
    if (currentGroup.length > 0) {
        searchGroups.push({ terms: currentGroup, operator: lastOperator });
    }

    if (searchGroups.length === 0) return { results: [], terms: [] };

    let filteredLogs = [];
    searchGroups.forEach((group, index) => {
        const groupResults = logs.filter(log => 
            group.terms.every(term => matchesTerm(log, term))
        );
        if (index === 0) {
            filteredLogs = groupResults;
        } else {
            if (group.operator === 'AND') {
                filteredLogs = filteredLogs.filter(log => 
                    groupResults.some(r => r === log)
                );
            } else { 
                const newLogs = groupResults.filter(log => 
                    !filteredLogs.some(f => f === log)
                );
                filteredLogs = [...filteredLogs, ...newLogs];
            }
        }
    });
    return { results: filteredLogs, terms: searchGroups.flatMap(g => g.terms) };
}

// Wire up the search UI to execute queries and render results
export function setupSearch(onResults) {
    function handleSearch() {
        const query = document.getElementById('searchInput').value.trim();
        const { results, terms } = searchLogs(query);
        onResults(results, terms);
    }

    function handleURLSearchParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const searchParam = urlParams.get('search');
        if (searchParam) {
            const searchInput = document.getElementById('searchInput');
            searchInput.value = decodeURIComponent(searchParam);
            setTimeout(handleSearch, 50);
        }
    }

    handleURLSearchParams();
    document.getElementById('searchButton').addEventListener('click', handleSearch);
    document.getElementById('searchInput').addEventListener('keyup', (e) => {
        if (e.key === 'Enter') handleSearch();
    });
}
