/**
 * AI-Powered Dashboard JavaScript
 * Handles stats, charts, real-time AI feed, and WebSocket events
 */

let trendChart = null;
let classChart = null;

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadRecentAttacks();
    setInterval(loadStats, 30000);
    setInterval(loadRecentAttacks, 15000);
});

// Real-time AI event handling
socket.on('threat_detected', (data) => {
    addToAIFeed(data);
});

socket.on('ai_alert', (data) => {
    addToAIFeed(data, true);
});

socket.on('anomaly_detected', (data) => {
    addAnomalyToFeed(data);
});

function addToAIFeed(data, isAlert = false) {
    const feed = document.getElementById('ai-feed');
    const time = new Date().toLocaleTimeString();
    const colors = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-green-400' };
    const color = colors[data.risk_level || 'medium'] || 'text-gray-400';
    const prefix = isAlert ? '🚨' : '⚡';

    const entry = document.createElement('div');
    entry.className = `flex items-center gap-2 p-2 rounded bg-white/[0.02] border border-white/[0.03] animate-pulse-once`;
    entry.innerHTML = `
        <span class="text-gray-600">[${time}]</span>
        <span>${prefix}</span>
        <span class="${color} font-semibold">${(data.classification || 'unknown').replace('_', ' ').toUpperCase()}</span>
        <span class="text-gray-500">from</span>
        <span class="text-cyber-blue">${data.source_ip || 'N/A'}</span>
        <span class="text-gray-600">→ ${(data.honeypot_type || '').toUpperCase()}</span>
        <span class="ml-auto ${color}">${data.threat_score ? data.threat_score.toFixed(1) : '0'}/10</span>
    `;

    // Remove placeholder
    const placeholder = feed.querySelector('.text-gray-600:only-child');
    if (placeholder) placeholder.remove();

    feed.insertBefore(entry, feed.firstChild);
    if (feed.children.length > 30) feed.removeChild(feed.lastChild);
}

function addAnomalyToFeed(data) {
    const feed = document.getElementById('ai-feed');
    const time = new Date().toLocaleTimeString();

    const entry = document.createElement('div');
    entry.className = `flex items-center gap-2 p-2 rounded bg-purple-500/5 border border-purple-500/20`;
    entry.innerHTML = `
        <span class="text-gray-600">[${time}]</span>
        <span>🔮</span>
        <span class="text-purple-400 font-semibold">ANOMALY</span>
        <span class="text-gray-400">${data.description || 'Unusual pattern detected'}</span>
        <span class="ml-auto text-purple-400">${data.anomaly_score ? data.anomaly_score.toFixed(1) : '?'}</span>
    `;

    feed.insertBefore(entry, feed.firstChild);
    if (feed.children.length > 30) feed.removeChild(feed.lastChild);
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        document.getElementById('total-attacks').textContent = data.total_attacks.toLocaleString();
        document.getElementById('attacks-24h').textContent = data.attacks_24h.toLocaleString();
        document.getElementById('unique-ips').textContent = data.unique_ips.toLocaleString();
        document.getElementById('anomaly-count').textContent = (data.anomaly_count || 0).toLocaleString();
        document.getElementById('campaign-count').textContent = (data.campaign_count || 0).toLocaleString();

        updateTrendChart(data.hourly_trend);
        updateClassChart(data.ai_classifications || {});
        updateTopIPs(data.top_ips);
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

async function loadRecentAttacks() {
    try {
        const response = await fetch('/api/attacks/recent?limit=10');
        const data = await response.json();
        const tbody = document.getElementById('recent-attacks');

        if (data.attacks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center py-8 text-gray-600">No attacks yet. Start honeypot services.</td></tr>';
            return;
        }

        tbody.innerHTML = data.attacks.map(a => {
            const scoreColor = (a.threat_score || 0) >= 7 ? 'text-red-400' : (a.threat_score || 0) >= 4 ? 'text-yellow-400' : 'text-green-400';
            const sevColors = { critical: 'bg-red-500/20 text-red-400', high: 'bg-orange-500/20 text-orange-400', medium: 'bg-yellow-500/20 text-yellow-400', low: 'bg-green-500/20 text-green-400' };
            return `<tr class="border-b border-cyber-border/50 hover:bg-white/[0.02]">
                <td class="py-2 px-2 text-gray-500">${formatTime(a.timestamp)}</td>
                <td class="py-2 font-mono text-cyber-blue">${a.source_ip}</td>
                <td class="py-2"><span class="px-2 py-0.5 rounded text-[10px] bg-blue-500/20 text-blue-300">${(a.honeypot_type || '').toUpperCase()}</span></td>
                <td class="py-2 text-gray-300">${(a.ai_classification || '-').replace('_', ' ')}</td>
                <td class="py-2 ${scoreColor} font-semibold">${a.threat_score ? a.threat_score.toFixed(1) : '-'}</td>
                <td class="py-2"><span class="px-2 py-0.5 rounded text-[10px] ${sevColors[a.severity] || ''}">${a.severity}</span></td>
            </tr>`;
        }).join('');
    } catch (error) {
        console.error('Failed to load recent attacks:', error);
    }
}

function updateTrendChart(trendData) {
    const ctx = document.getElementById('trendChart').getContext('2d');
    const labels = trendData.map(d => d.hour);
    const values = trendData.map(d => d.count);

    if (trendChart) {
        trendChart.data.labels = labels;
        trendChart.data.datasets[0].data = values;
        trendChart.update();
    } else {
        trendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels, datasets: [{
                    data: values, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.05)',
                    fill: true, tension: 0.4, pointRadius: 1, borderWidth: 2
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#666', maxTicksLimit: 12 } },
                    y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#666' }, beginAtZero: true }
                }
            }
        });
    }
}

function updateClassChart(classData) {
    const ctx = document.getElementById('classChart').getContext('2d');
    const labels = Object.keys(classData).map(k => k.replace('_', ' '));
    const values = Object.values(classData);
    const colors = ['#00d4ff', '#ff3366', '#00ff88', '#ffaa00', '#aa44ff', '#ff6644', '#44ddff', '#88ff44'];

    if (classChart) {
        classChart.data.labels = labels;
        classChart.data.datasets[0].data = values;
        classChart.update();
    } else {
        classChart = new Chart(ctx, {
            type: 'doughnut',
            data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#888', padding: 8, font: { size: 10 } } } }
            }
        });
    }
}

function updateTopIPs(topIps) {
    const container = document.getElementById('top-ips');
    if (!topIps || topIps.length === 0) {
        container.innerHTML = '<p class="text-gray-600 text-xs">No data yet</p>';
        return;
    }
    container.innerHTML = topIps.slice(0, 8).map(item => `
        <div class="flex justify-between items-center p-2 rounded bg-white/[0.02] border border-white/[0.03]">
            <span class="font-mono text-xs text-cyber-blue">${item.ip}</span>
            <span class="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 font-semibold">${item.count}</span>
        </div>
    `).join('');
}

function updateRecentAttacks(data) { loadStats(); loadRecentAttacks(); }
