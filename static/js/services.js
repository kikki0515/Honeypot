/**
 * Services page - Honeypot service management
 */
document.addEventListener('DOMContentLoaded', () => { loadServices(); setInterval(loadServices, 10000); });

async function loadServices() {
    try {
        const response = await fetch('/api/services');
        const data = await response.json();
        data.services.forEach(service => {
            const statusEl = document.getElementById(`status-${service.service_type}`);
            const connEl = document.getElementById(`conn-${service.service_type}`);
            if (statusEl) {
                statusEl.textContent = service.status.charAt(0).toUpperCase() + service.status.slice(1);
                statusEl.className = service.status === 'running' ? 'px-3 py-1 rounded-full text-xs font-semibold bg-green-500/20 text-green-400' : 'px-3 py-1 rounded-full text-xs font-semibold bg-gray-500/20 text-gray-400';
            }
            if (connEl) connEl.textContent = service.total_connections;
            const card = document.getElementById(`service-${service.service_type}`);
            if (card) {
                const btn = card.querySelector('.toggle-btn');
                if (btn) {
                    if (service.status === 'running') { btn.className = 'toggle-btn px-4 py-2 rounded-lg text-sm bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition'; btn.innerHTML = '<i class="fas fa-stop"></i> Stop'; }
                    else { btn.className = 'toggle-btn px-4 py-2 rounded-lg text-sm bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30 transition'; btn.innerHTML = '<i class="fas fa-play"></i> Start'; }
                }
            }
        });
    } catch (error) { console.error('Failed to load services:', error); }
}

async function toggleService(serviceType) {
    try {
        await fetch(`/api/services/${serviceType}/toggle`, { method: 'POST' });
        setTimeout(loadServices, 500);
    } catch (error) { console.error('Failed to toggle service:', error); }
}

function updateServiceStatus(data) { loadServices(); }
