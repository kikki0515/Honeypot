/**
 * HaaS AI Platform - Core Application JavaScript
 * WebSocket connection, real-time notifications, and shared utilities
 */

const socket = io();

socket.on('connect', () => console.log('Connected to HaaS AI Platform'));
socket.on('disconnect', () => console.log('Disconnected'));

// Global notification system
socket.on('new_attack', (data) => {
    if (typeof updateRecentAttacks === 'function') updateRecentAttacks(data);
});

socket.on('ai_alert', (data) => {
    showNotification(data, 'critical');
});

socket.on('alert_triggered', (data) => {
    showNotification(data, 'alert');
});

socket.on('service_status', (data) => {
    if (typeof updateServiceStatus === 'function') updateServiceStatus(data);
});

function showNotification(data, type = 'info') {
    const notification = document.createElement('div');
    const colors = {
        critical: 'border-red-500 bg-red-500/10',
        alert: 'border-yellow-500 bg-yellow-500/10',
        info: 'border-blue-500 bg-blue-500/10'
    };

    notification.className = `fixed top-4 right-4 z-[9999] p-4 rounded-lg border ${colors[type] || colors.info} backdrop-blur-sm max-w-sm animate-slide-in`;
    notification.innerHTML = `
        <div class="flex items-start gap-3">
            <i class="fas fa-${type === 'critical' ? 'exclamation-triangle text-red-400' : 'bell text-yellow-400'} mt-0.5"></i>
            <div>
                <p class="text-sm font-semibold text-white">${data.reason || data.classification || 'Alert'}</p>
                <p class="text-xs text-gray-400 mt-1">${data.attack?.source_ip || data.source_ip || ''} → ${(data.attack?.honeypot_type || data.honeypot_type || '').toUpperCase()}</p>
                ${data.summary ? `<p class="text-xs text-gray-500 mt-1">${data.summary.substring(0, 100)}</p>` : ''}
            </div>
        </div>
    `;
    document.body.appendChild(notification);
    setTimeout(() => { notification.style.opacity = '0'; setTimeout(() => notification.remove(), 300); }, 5000);
}

function formatTime(isoString) {
    if (!isoString) return '-';
    return new Date(isoString).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDateTime(isoString) {
    if (!isoString) return '-';
    return new Date(isoString).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function severityBadge(severity) {
    const colors = { critical: 'bg-red-500/20 text-red-400', high: 'bg-orange-500/20 text-orange-400', medium: 'bg-yellow-500/20 text-yellow-400', low: 'bg-green-500/20 text-green-400' };
    return `<span class="px-2 py-0.5 rounded text-[10px] ${colors[severity] || ''}">${severity}</span>`;
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
    @keyframes slide-in { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    .animate-slide-in { animation: slide-in 0.3s ease; }
    @keyframes pulse-once { 0% { opacity: 0.5; } 50% { opacity: 1; } 100% { opacity: 1; } }
    .animate-pulse-once { animation: pulse-once 0.5s ease; }
`;
document.head.appendChild(style);
