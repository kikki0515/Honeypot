/**
 * Dashboard page JavaScript
 * Handles stats loading, charts, and real-time updates
 */

let trendChart = null;
let typeChart = null;

// Load dashboard data on page load
document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadRecentAttacks();
    // Refresh every 30 seconds
    setInterval(loadStats, 30000);
    setInterval(loadRecentAttacks, 15000);
});

/**
 * Load dashboard statistics
 */
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        // Update stat cards
        document.getElementById('total-attacks').textContent = data.total_attacks.toLocaleString();
        document.getElementById('attacks-24h').textContent = data.attacks_24h.toLocaleString();
        document.getElementById('unique-ips').textContent = data.unique_ips.toLocaleString();

        // Count active services
        const servicesResponse = await fetch('/api/services');
        const servicesData = await servicesResponse.json();
        const activeCount = servicesData.services.filter(s => s.status === 'running').length;
        document.getElementById('active-services').textContent = activeCount;

        // Update charts
        updateTrendChart(data.hourly_trend);
        updateTypeChart(data.attacks_by_type);

        // Update top IPs
        updateTopIPs(data.top_ips);

    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

/**
 * Load recent attacks for the table
 */
async function loadRecentAttacks() {
    try {
        const response = await fetch('/api/attacks/recent?limit=10');
        const data = await response.json();

        const tbody = document.getElementById('recent-attacks');
        if (data.attacks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No attacks detected yet. Start honeypot services to begin monitoring.</td></tr>';
            return;
        }

        tbody.innerHTML = data.attacks.map(attack => `
            <tr>
                <td>${formatTime(attack.timestamp)}</td>
                <td><code>${attack.source_ip}</code></td>
                <td><span class="severity-badge severity-${attack.honeypot_type === 'ssh' ? 'high' : attack.honeypot_type === 'http' ? 'medium' : 'low'}" style="background: rgba(26,115,232,0.2); color: #4da6ff;">${attack.honeypot_type.toUpperCase()}</span></td>
                <td>${truncate(attack.action, 30)}</td>
                <td>${severityBadge(attack.severity)}</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Failed to load recent attacks:', error);
    }
}

/**
 * Update the attack trend chart (line chart)
 */
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
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: values,
                    borderColor: '#1a73e8',
                    backgroundColor: 'rgba(26, 115, 232, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointBackgroundColor: '#1a73e8'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#a0a0b5', maxTicksLimit: 12 }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#a0a0b5' },
                        beginAtZero: true
                    }
                }
            }
        });
    }
}

/**
 * Update the attack type chart (doughnut)
 */
function updateTypeChart(typeData) {
    const ctx = document.getElementById('typeChart').getContext('2d');

    const labels = Object.keys(typeData).map(k => k.toUpperCase());
    const values = Object.values(typeData);
    const colors = ['#28a745', '#1a73e8', '#ffc107', '#dc3545'];

    if (typeChart) {
        typeChart.data.labels = labels;
        typeChart.data.datasets[0].data = values;
        typeChart.update();
    } else {
        typeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#a0a0b5', padding: 12 }
                    }
                }
            }
        });
    }
}

/**
 * Update top IPs list
 */
function updateTopIPs(topIps) {
    const container = document.getElementById('top-ips');

    if (topIps.length === 0) {
        container.innerHTML = '<p class="empty-state">No data yet</p>';
        return;
    }

    container.innerHTML = topIps.slice(0, 8).map(item => `
        <div class="ip-item">
            <span class="ip-address">${item.ip}</span>
            <span class="ip-count">${item.count}</span>
        </div>
    `).join('');
}

/**
 * Handle real-time attack updates
 */
function updateRecentAttacks(attack) {
    // Reload stats and recent attacks
    loadStats();
    loadRecentAttacks();
}

/**
 * Truncate text
 */
function truncate(text, maxLen) {
    if (!text) return '-';
    return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
}
