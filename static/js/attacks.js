/**
 * Attack Logs page - Enhanced with AI classification and GeoIP data
 */
let currentPage = 1;
const perPage = 40;

document.addEventListener('DOMContentLoaded', () => {
    loadAttacks();
    document.getElementById('filter-type').addEventListener('change', () => { currentPage = 1; loadAttacks(); });
    document.getElementById('filter-severity').addEventListener('change', () => { currentPage = 1; loadAttacks(); });
});

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
            tbody.innerHTML = '<tr><td colspan="8" class="text-center py-12 text-gray-600">No attacks found.</td></tr>';
            return;
        }

        tbody.innerHTML = data.attacks.map(a => {
            const scoreColor = (a.threat_score || 0) >= 7 ? 'text-red-400' : (a.threat_score || 0) >= 4 ? 'text-yellow-400' : 'text-green-400';
            const sevColors = { critical: 'bg-red-500/20 text-red-400', high: 'bg-orange-500/20 text-orange-400', medium: 'bg-yellow-500/20 text-yellow-400', low: 'bg-green-500/20 text-green-400' };
            const flag = a.geoip_country_code ? `<span title="${a.geoip_country}">${a.geoip_country_code}</span>` : '-';
            return `<tr class="border-b border-cyber-border/30 hover:bg-white/[0.02]">
                <td class="py-2 px-3 text-gray-500">${formatDateTime(a.timestamp)}</td>
                <td class="py-2 font-mono text-cyber-blue">${a.source_ip}</td>
                <td class="py-2"><span class="px-2 py-0.5 rounded text-[10px] bg-blue-500/20 text-blue-300">${(a.honeypot_type||'').toUpperCase()}</span></td>
                <td class="py-2 text-gray-300 max-w-[200px] truncate">${a.action || '-'}</td>
                <td class="py-2 text-gray-400">${(a.ai_classification || '-').replace('_',' ')}</td>
                <td class="py-2 ${scoreColor} font-mono font-bold">${a.threat_score ? a.threat_score.toFixed(1) : '-'}</td>
                <td class="py-2 text-gray-400">${flag}</td>
                <td class="py-2">${severityBadge(a.severity)}</td>
            </tr>`;
        }).join('');

        renderPagination(data.pages, data.current_page);
    } catch (error) {
        console.error('Failed to load attacks:', error);
    }
}

function renderPagination(totalPages, current) {
    const container = document.getElementById('pagination');
    if (totalPages <= 1) { container.innerHTML = ''; return; }
    let html = '';
    if (current > 1) html += `<button onclick="goToPage(${current-1})" class="px-3 py-1 rounded bg-cyber-card border border-cyber-border text-gray-400 hover:text-white text-xs"><i class="fas fa-chevron-left"></i></button>`;
    for (let i = Math.max(1, current-3); i <= Math.min(totalPages, current+3); i++) {
        html += `<button onclick="goToPage(${i})" class="px-3 py-1 rounded text-xs ${i === current ? 'bg-cyber-blue text-white' : 'bg-cyber-card border border-cyber-border text-gray-400 hover:text-white'}">${i}</button>`;
    }
    if (current < totalPages) html += `<button onclick="goToPage(${current+1})" class="px-3 py-1 rounded bg-cyber-card border border-cyber-border text-gray-400 hover:text-white text-xs"><i class="fas fa-chevron-right"></i></button>`;
    container.innerHTML = html;
}
function goToPage(page) { currentPage = page; loadAttacks(); }
