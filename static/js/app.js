/**
 * Honeypot-as-a-Service - Main Application JavaScript
 * Handles WebSocket connection and real-time updates
 */

// Initialize Socket.IO connection
const socket = io();

socket.on('connect', () => {
    console.log('Connected to HaaS server');
});

socket.on('disconnect', () => {
    console.log('Disconnected from HaaS server');
});

// Listen for new attack events (real-time)
socket.on('new_attack', (data) => {
    console.log('New attack detected:', data);

    // Update dashboard if on dashboard page
    if (typeof updateRecentAttacks === 'function') {
        updateRecentAttacks(data);
    }

    // Show notification
    showNotification(data);
});

// Listen for service status changes
socket.on('service_status', (data) => {
    console.log('Service status update:', data);

    if (typeof updateServiceStatus === 'function') {
        updateServiceStatus(data);
    }
});

/**
 * Show a brief notification for new attacks
 */
function showNotification(attack) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${attack.severity}`;
    notification.innerHTML = `
        <i class="fas fa-exclamation-triangle"></i>
        <span><strong>${attack.honeypot_type.toUpperCase()}</strong>: ${attack.action} from ${attack.source_ip}</span>
    `;

    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        background: rgba(30, 30, 47, 0.95);
        border: 1px solid ${getSeverityColor(attack.severity)};
        border-radius: 8px;
        color: white;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 10px;
        z-index: 9999;
        animation: slideIn 0.3s ease;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    `;

    document.body.appendChild(notification);

    // Remove after 4 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

function getSeverityColor(severity) {
    const colors = {
        'critical': '#ff4444',
        'high': '#ff8800',
        'medium': '#ffcc00',
        'low': '#44bb44'
    };
    return colors[severity] || '#ffffff';
}

/**
 * Utility: Format timestamp for display
 */
function formatTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function formatDateTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

/**
 * Utility: Create severity badge HTML
 */
function severityBadge(severity) {
    return `<span class="severity-badge severity-${severity}">${severity}</span>`;
}

// Add CSS animation keyframes
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);
