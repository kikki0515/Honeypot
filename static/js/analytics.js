/**
 * Analytics page JavaScript
 * Handles analytics charts and statistics
 */

let severityChart = null;
let protocolChart = null;

document.addEventListener('DOMContentLoaded', () => {
    loadAnalytics();
});

/**
 * Load analytics data
 */
async function loadAnalytics() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        // Update stat cards
        const severityData = data.attacks_by_severity || {};
        document.getElementById('critical-count').textContent = (severityData['critical'] || 0).toLocaleString();
        document.getElementById('high-count').textContent = (severityData['high'] || 0).toLocaleString();
        document.getElementById('unique-attackers').textContent = data.unique_ips.toLocaleString();
        document.getElementById('login-attempts').textContent = data.total_attacks.toLocaleString();

        // Severity Distribution Chart
        updateSeverityChart(severityData);

        // Protocol Chart
        updateProtocolChart(data.attacks_by_type);

        // Top Attackers Table
        updateTopAttackers(data.top_ips);

    } catch (error) {
        console.error('Failed to load analytics:', error);
    }
}

function updateSeverityChart(severityData) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    const labels = ['Critical', 'High', 'Medium', 'Low'];
    const values = [
        severityData['critical'] || 0,
        severityData['high'] || 0,
        severityData['medium'] || 0,
        severityData['low'] || 0
    ];
    const colors = ['#ff4444', '#ff8800', '#ffcc00', '#44bb44'];

    if (severityChart) {
        severityChart.data.datasets[0].data = values;
        severityChart.update();
    } else {
        severityChart = new Chart(ctx, {
            type: 'pie',
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

function updateProtocolChart(typeData) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    const labels = Object.keys(typeData).map(k => k.toUpperCase());
    const values = Object.values(typeData);
    const colors = ['#28a745', '#1a73e8', '#ffc107'];

    if (protocolChart) {
        protocolChart.data.labels = labels;
        protocolChart.data.datasets[0].data = values;
        protocolChart.update();
    } else {
        protocolChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: values,
                    backgroundColor: colors,
                    borderRadius: 6
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
                        ticks: { color: '#a0a0b5' }
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

function updateTopAttackers(topIps) {
    const tbody = document.getElementById('top-attackers-table');

    if (!topIps || topIps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No data available yet.</td></tr>';
        return;
    }

    tbody.innerHTML = topIps.map((item, index) => {
        let threat = 'Low';
        let threatClass = 'low';
        if (item.count > 50) { threat = 'Critical'; threatClass = 'critical'; }
        else if (item.count > 20) { threat = 'High'; threatClass = 'high'; }
        else if (item.count > 5) { threat = 'Medium'; threatClass = 'medium'; }

        return `
            <tr>
                <td><strong>#${index + 1}</strong></td>
                <td><code>${item.ip}</code></td>
                <td>${item.count}</td>
                <td>${severityBadge(threatClass)}</td>
            </tr>
        `;
    }).join('');
}
