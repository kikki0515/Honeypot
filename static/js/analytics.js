/**
 * Analytics page - Enhanced with AI classification charts and geo data
 */
let severityChart = null, protocolChart = null;

document.addEventListener('DOMContentLoaded', () => { loadAnalytics(); });

async function loadAnalytics() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        document.getElementById('critical-count').textContent = (data.attacks_by_severity?.critical || 0).toLocaleString();
        document.getElementById('high-count').textContent = (data.attacks_by_severity?.high || 0).toLocaleString();
        document.getElementById('unique-attackers').textContent = data.unique_ips.toLocaleString();
        document.getElementById('avg-score').textContent = (data.avg_threat_score || 0).toFixed(1);

        updateSeverityChart(data.attacks_by_severity || {});
        updateProtocolChart(data.attacks_by_type || {});
        updateTopAttackers(data.top_ips);
    } catch (error) { console.error('Failed to load analytics:', error); }
}

function updateSeverityChart(severityData) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    const labels = ['Critical', 'High', 'Medium', 'Low'];
    const values = [severityData.critical||0, severityData.high||0, severityData.medium||0, severityData.low||0];
    const colors = ['#ff3366', '#ff8800', '#ffaa00', '#00ff88'];
    if (severityChart) { severityChart.data.datasets[0].data = values; severityChart.update(); }
    else {
        severityChart = new Chart(ctx, { type: 'pie', data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#888', padding: 10, font: { size: 10 } } } } } });
    }
}

function updateProtocolChart(typeData) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    const labels = Object.keys(typeData).map(k => k.toUpperCase());
    const values = Object.values(typeData);
    const colors = ['#00ff88', '#00d4ff', '#ffaa00'];
    if (protocolChart) { protocolChart.data.labels = labels; protocolChart.data.datasets[0].data = values; protocolChart.update(); }
    else {
        protocolChart = new Chart(ctx, { type: 'bar', data: { labels, datasets: [{ data: values, backgroundColor: colors, borderRadius: 4 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
                scales: { x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888' } }, y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888' }, beginAtZero: true } } } });
    }
}

function updateTopAttackers(topIps) {
    const tbody = document.getElementById('top-attackers-table');
    if (!topIps || topIps.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="text-center py-8 text-gray-600">No data yet.</td></tr>'; return; }
    tbody.innerHTML = topIps.map((item, i) => {
        const threat = item.count > 50 ? 'critical' : item.count > 20 ? 'high' : item.count > 5 ? 'medium' : 'low';
        return `<tr class="border-b border-cyber-border/30"><td class="py-2 px-3 text-gray-500 font-bold">#${i+1}</td><td class="py-2 font-mono text-cyber-blue">${item.ip}</td><td class="py-2 text-white font-semibold">${item.count}</td><td class="py-2">${severityBadge(threat)}</td></tr>`;
    }).join('');
}
