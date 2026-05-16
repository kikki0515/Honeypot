/**
 * Services page JavaScript
 * Handles honeypot service management
 */

document.addEventListener('DOMContentLoaded', () => {
    loadServices();
    setInterval(loadServices, 10000);
});

/**
 * Load service statuses
 */
async function loadServices() {
    try {
        const response = await fetch('/api/services');
        const data = await response.json();

        data.services.forEach(service => {
            const statusEl = document.getElementById(`status-${service.service_type}`);
            const connEl = document.getElementById(`conn-${service.service_type}`);

            if (statusEl) {
                statusEl.textContent = service.status.charAt(0).toUpperCase() + service.status.slice(1);
                statusEl.className = `status-badge status-${service.status}`;
            }

            if (connEl) {
                connEl.textContent = service.total_connections;
            }

            // Update button
            const card = document.getElementById(`service-${service.service_type}`);
            if (card) {
                const btn = card.querySelector('.service-actions button');
                if (service.status === 'running') {
                    btn.className = 'btn btn-danger';
                    btn.innerHTML = '<i class="fas fa-stop"></i> Stop';
                } else {
                    btn.className = 'btn btn-success';
                    btn.innerHTML = '<i class="fas fa-play"></i> Start';
                }
            }
        });
    } catch (error) {
        console.error('Failed to load services:', error);
    }
}

/**
 * Toggle a honeypot service
 */
async function toggleService(serviceType) {
    try {
        const response = await fetch(`/api/services/${serviceType}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();
        console.log(`Service toggle: ${data.message}`);

        // Reload services after a brief delay
        setTimeout(loadServices, 500);

    } catch (error) {
        console.error('Failed to toggle service:', error);
        alert('Failed to toggle service. Check console for details.');
    }
}

/**
 * Handle real-time service status updates via WebSocket
 */
function updateServiceStatus(data) {
    loadServices();
}
