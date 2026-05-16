/**
 * Attack Logs page JavaScript
 * Handles attack log listing with filtering and pagination
 */

let currentPage = 1;
const perPage = 30;

document.addEventListener('DOMContentLoaded', () => {
    loadAttacks();

    // Add filter event listeners
    document.getElementById('filter-type').addEventListener('change', () => {
        currentPage = 1;
        loadAttacks();
    });
    document.getElementById('filter-severity').addEventListener('change', () => {
        currentPage = 1;
        loadAttacks();
    });
});

/**
 * Load attack logs with filters
 */
async function loadAttacks() {
    const type = document.getElementById('filter-type').value;
    const severity = document.getElementById('filter-severity').value;

    let url = `/api/attacks?page=${currentPage}&per_page=${perPage}`;
    if (type) url += `&type=${type}`;
    if (severity) url += `&severity=${severity}`;

    try {
        const response = await fetch(url);
        const data = await response.json();

        const tbody = document.getElementById('attacks-table');

        if (data.attacks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No attack logs found.</td></tr>';
            document.getElementById('pagination').innerHTML = '';
            return;
        }

        tbody.innerHTML = data.attacks.map(attack => `
            <tr>
                <td>${formatDateTime(attack.timestamp)}</td>
                <td><code>${attack.source_ip}</code></td>
                <td>${attack.source_port || '-'}</td>
                <td><span class="severity-badge" style="background: rgba(26,115,232,0.2); color: #4da6ff;">${attack.honeypot_type.toUpperCase()}</span></td>
                <td>${truncate(attack.action, 40)}</td>
                <td><code>${attack.username_attempted || '-'}</code></td>
                <td><code>${attack.password_attempted ? '***' : '-'}</code></td>
                <td>${severityBadge(attack.severity)}</td>
            </tr>
        `).join('');

        // Update pagination
        renderPagination(data.pages, data.current_page);

    } catch (error) {
        console.error('Failed to load attacks:', error);
    }
}

/**
 * Render pagination controls
 */
function renderPagination(totalPages, current) {
    const container = document.getElementById('pagination');

    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    if (current > 1) {
        html += `<button onclick="goToPage(${current - 1})"><i class="fas fa-chevron-left"></i></button>`;
    }

    for (let i = 1; i <= Math.min(totalPages, 10); i++) {
        html += `<button class="${i === current ? 'active' : ''}" onclick="goToPage(${i})">${i}</button>`;
    }

    if (current < totalPages) {
        html += `<button onclick="goToPage(${current + 1})"><i class="fas fa-chevron-right"></i></button>`;
    }

    container.innerHTML = html;
}

function goToPage(page) {
    currentPage = page;
    loadAttacks();
}

function truncate(text, maxLen) {
    if (!text) return '-';
    return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
}
