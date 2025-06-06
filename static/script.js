// static/script.js

let currentPage = 1;
let pageSize = 10; // Initialized from the select element on DOMContentLoaded

// New state variables for sorting
let currentSortBy = 'publishedDate'; // Default sort key
let currentSortOrder = 'desc'; // Default sort order

async function fetchAndDisplayCVEs() {
    const cveId = document.getElementById('cveIdFilter').value;
    const year = document.getElementById('yearFilter').value;
    const score = document.getElementById('scoreFilter').value;
    const lastModifiedNDays = document.getElementById('lastModifiedFilter').value;
    
    // Get the current selected pageSize
    pageSize = document.getElementById('pageSizeSelect').value;

    const queryParams = new URLSearchParams({
        page: currentPage,
        pageSize: pageSize,
        sortBy: currentSortBy,      // Add sort by parameter
        sortOrder: currentSortOrder // Add sort order parameter
    });

    if (cveId) queryParams.append('cveId', cveId);
    if (year) queryParams.append('year', year);
    if (score) queryParams.append('score', score);
    if (lastModifiedNDays) queryParams.append('lastModifiedNDays', lastModifiedNDays);

    try {
        const response = await fetch(`/api/cves?${queryParams.toString()}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json(); // Assuming data contains { cves: [...], totalRecords, page, pageSize, totalPages }

        const cves = data.cves;
        const totalRecords = data.totalRecords;
        const totalPages = data.totalPages;
        const recordCountDisplay = document.getElementById('recordCountDisplay');

        // Update record count display
        const startRecord = (currentPage - 1) * pageSize + 1;
        const endRecord = Math.min(currentPage * pageSize, totalRecords);
        if (totalRecords > 0) {
            recordCountDisplay.textContent = `${startRecord} - ${endRecord} of ${totalRecords} records`;
        } else {
            recordCountDisplay.textContent = 'No records found.';
        }


        const cveListBody = document.getElementById('cveListBody');
        cveListBody.innerHTML = ''; // Clear existing table rows

        // Adjust colspan if "CVSS v3 Base Score" column is removed.
        // Original columns: CVE ID, Description, Published Date, Last Modified Date, Status, CVSS v3, CVSS v2, Identifier (8 columns total)
        // If Description is removed, it becomes 7 columns.
        // If CVSS v3 is also removed, it becomes 6 columns.
        // Assuming your HTML table headers are now: CVE ID, Description, Published Date, Last Modified Date, Status, CVSS v2 Base Score, Identifier
        // That's 7 columns. If Description is NOT a column, then it's 6 columns.
        // Based on the previous HTML update, Description is removed. So it should be 6 columns.
        // Let's assume you have: CVE ID, Published Date, Last Modified Date, Status, CVSS v2 Base Score, Identifier (6 columns)
        const numberOfColumns = 6; // Adjusted from 7 assuming Description is also removed from HTML headers

        if (cves.length === 0) {
            cveListBody.innerHTML = `<tr><td colspan="${numberOfColumns}" class="text-center">No CVEs found matching your criteria.</td></tr>`;
        } else {
            cves.forEach(cve => {
                const row = document.createElement('tr');
                // Add data-cve-id for click handling
                row.setAttribute('data-cve-id', cve.cve_id);
                row.style.cursor = 'pointer'; // Make it look clickable

                // Safely get CVSS v2 score
                const cvssV2Score = cve.cvss_v2 && cve.cvss_v2.length > 0
                    ? cve.cvss_v2[0].base_score
                    : null; // Use null if no V2 score

                row.innerHTML = `
                    <td>${cve.cve_id || 'N/A'}</td>
                    <td>${cve.published_date ? new Date(cve.published_date).toLocaleDateString() : 'N/A'}</td>
                    <td>${cve.last_modified_date ? new Date(cve.last_modified_date).toLocaleDateString() : 'N/A'}</td>
                    <td>${cve.status || 'N/A'}</td>
                    <td>
                        ${cvssV2Score !== null && typeof cvssV2Score !== 'undefined' ? cvssV2Score.toFixed(1) : 'N/A'}
                    </td>
                    <td>${cve.identifier || 'N/A'}</td>
                `;
                cveListBody.appendChild(row);
            });

            // Add click event listener to rows for navigation
            cveListBody.querySelectorAll('tr').forEach(row => {
                row.addEventListener('click', function() {
                    const cveId = this.getAttribute('data-cve-id');
                    if (cveId) {
                        window.location.href = `/static/cve-details.html?cveId=${cveId}`;
                    }
                });
            });
        }
        
        updatePaginationControls(totalPages);
        updateSortIcons(); // Call this to set the correct sort icon

    } catch (error) {
        console.error('Failed to load CVEs. Please check the API server. Error:', error);
        document.getElementById('cveListBody').innerHTML = `<td colspan="${numberOfColumns}" class="text-center text-danger">Error loading CVEs: ${error.message}. Please ensure the API server is running and data is available.</td>`;
        document.getElementById('recordCountDisplay').textContent = 'Error loading records.';
    }
}

function updatePaginationControls(totalPages) {
    const paginationControls = document.getElementById('paginationControls');
    paginationControls.innerHTML = ''; // Clear existing pagination buttons

    const maxPagesDisplay = 5; // How many page numbers to show directly (e.g., 1 ... 4 5 [6] 7 8 ... 20)
    let startPage, endPage;

    // Previous button
    const prevLi = document.createElement('li');
    prevLi.className = `page-item ${currentPage === 1 ? 'disabled' : ''}`;
    prevLi.innerHTML = `<a class="page-link" href="#" aria-label="Previous" data-page="${currentPage - 1}">Previous</a>`;
    paginationControls.appendChild(prevLi);

    if (totalPages <= maxPagesDisplay) {
        // Show all pages if total pages are few
        startPage = 1;
        endPage = totalPages;
    } else {
        // Calculate dynamic range for pages to display
        const middleOffset = Math.floor(maxPagesDisplay / 2);
        startPage = currentPage - middleOffset;
        endPage = currentPage + middleOffset;

        if (startPage < 1) {
            startPage = 1;
            endPage = maxPagesDisplay;
        }

        if (endPage > totalPages) {
            endPage = totalPages;
            startPage = totalPages - maxPagesDisplay + 1;
            if (startPage < 1) startPage = 1; // Ensure startPage doesn't go below 1
        }
    }

    // Add first page link if not in the current range
    if (startPage > 1) {
        const pageLi = document.createElement('li');
        pageLi.className = `page-item ${1 === currentPage ? 'active' : ''}`;
        pageLi.innerHTML = `<a class="page-link" href="#" data-page="1">1</a>`;
        paginationControls.appendChild(pageLi);
        if (startPage > 2) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = `page-item disabled`;
            ellipsisLi.innerHTML = `<span class="page-link">...</span>`;
            paginationControls.appendChild(ellipsisLi);
        }
    }

    // Add page links in the calculated range
    for (let i = startPage; i <= endPage; i++) {
        const pageLi = document.createElement('li');
        pageLi.className = `page-item ${i === currentPage ? 'active' : ''}`;
        pageLi.innerHTML = `<a class="page-link" href="#" data-page="${i}">${i}</a>`;
        paginationControls.appendChild(pageLi);
    }

    // Add last page link if not in the current range
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = `page-item disabled`;
            ellipsisLi.innerHTML = `<span class="page-link">...</span>`;
            paginationControls.appendChild(ellipsisLi);
        }
        const pageLi = document.createElement('li');
        pageLi.className = `page-item ${totalPages === currentPage ? 'active' : ''}`;
        pageLi.innerHTML = `<a class="page-link" href="#" data-page="${totalPages}">${totalPages}</a>`;
        paginationControls.appendChild(pageLi);
    }

    // Next button
    const nextLi = document.createElement('li');
    nextLi.className = `page-item ${currentPage === totalPages ? 'disabled' : ''}`;
    nextLi.innerHTML = `<a class="page-link" href="#" aria-label="Next" data-page="${currentPage + 1}">Next</a>`;
    paginationControls.appendChild(nextLi);

    // Add event listeners to pagination buttons
    paginationControls.querySelectorAll('.page-link').forEach(link => {
        link.addEventListener('click', (event) => {
            event.preventDefault();
            const newPage = parseInt(event.target.dataset.page);
            // Only change page if it's a valid number, within bounds, and not the current page
            if (!isNaN(newPage) && newPage > 0 && newPage <= totalPages && newPage !== currentPage) {
                currentPage = newPage;
                fetchAndDisplayCVEs();
            }
        });
    });
}

function updateSortIcons() {
    // Reset all sort icons
    document.querySelectorAll('.sort-icon').forEach(icon => {
        icon.className = 'sort-icon'; // Clear any existing Font Awesome classes
    });

    // Set icon for the currently sorted column
    const currentIcon = document.getElementById(`${currentSortBy}SortIcon`);
    if (currentIcon) {
        if (currentSortOrder === 'asc') {
            currentIcon.classList.add('fas', 'fa-sort-up'); // Up arrow for ascending
        } else {
            currentIcon.classList.add('fas', 'fa-sort-down'); // Down arrow for descending
        }
    }
}

// Event Listeners for Filters
document.getElementById('applyFiltersBtn').addEventListener('click', () => {
    currentPage = 1; // Reset to first page when filters are applied
    fetchAndDisplayCVEs();
});

document.getElementById('clearFiltersBtn').addEventListener('click', () => {
    document.getElementById('cveIdFilter').value = '';
    document.getElementById('yearFilter').value = '';
    document.getElementById('scoreFilter').value = '';
    document.getElementById('lastModifiedFilter').value = '';
    
    // Reset sorting to default
    currentSortBy = 'publishedDate';
    currentSortOrder = 'desc';
    
    currentPage = 1; // Reset to first page
    fetchAndDisplayCVEs();
});

// Event Listener for Results per page select
document.getElementById('pageSizeSelect').addEventListener('change', () => {
    currentPage = 1; // Reset to first page when page size changes
    fetchAndDisplayCVEs();
});

// Event Listeners for sortable table headers
document.querySelectorAll('.sortable').forEach(header => {
    header.addEventListener('click', () => {
        const sortKey = header.dataset.sortKey;
        if (currentSortBy === sortKey) {
            // If same column clicked, toggle sort order
            currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
        } else {
            // If different column clicked, set new sort key and default to descending
            currentSortBy = sortKey;
            currentSortOrder = 'desc';
        }
        currentPage = 1; // Reset to first page on sort
        fetchAndDisplayCVEs();
    });
});


// Initial load of CVEs when the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Set initial pageSize from dropdown
    pageSize = document.getElementById('pageSizeSelect').value;
    fetchAndDisplayCVEs();
});