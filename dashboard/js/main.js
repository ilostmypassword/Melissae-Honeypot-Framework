import { loadLogs, setupSearch } from './searchEngine.js';
import { displayResults, setupExportButton } from './searchDisplay.js';

await loadLogs();
setupSearch((filteredLogs, searchTerms) => {
    displayResults(filteredLogs, searchTerms);
    setupExportButton(filteredLogs);
});
