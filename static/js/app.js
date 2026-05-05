/* Status Panel — main app JS (vanilla, no jQuery) */

document.addEventListener('DOMContentLoaded', () => {
    // Sidebar toggle (mobile)
    const toggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    if (toggle && sidebar) {
        toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
        document.addEventListener('click', (e) => {
            if (sidebar.classList.contains('open') &&
                !sidebar.contains(e.target) &&
                !toggle.contains(e.target)) {
                sidebar.classList.remove('open');
            }
        });
    }

    // Tab controller
    document.querySelectorAll('[data-tab]').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.tab;
            btn.closest('.tab-bar').querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            const panel = document.getElementById(target);
            if (panel) panel.classList.add('active');
        });
    });

    // Dropdown toggles
    document.querySelectorAll('.dropdown > .btn').forEach(trigger => {
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const dd = trigger.closest('.dropdown');
            document.querySelectorAll('.dropdown.open').forEach(d => { if (d !== dd) d.classList.remove('open'); });
            dd.classList.toggle('open');
        });
    });
    document.addEventListener('click', () => {
        document.querySelectorAll('.dropdown.open').forEach(d => d.classList.remove('open'));
    });

    // Modal open/close
    document.querySelectorAll('[data-modal]').forEach(trigger => {
        trigger.addEventListener('click', (e) => {
            e.preventDefault();
            const modal = document.getElementById(trigger.dataset.modal);
            if (modal) modal.classList.add('open');
        });
    });
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            btn.closest('.modal-overlay').classList.remove('open');
        });
    });
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.classList.remove('open');
        });
    });

    // ---- Notification bell ----
    const bell = document.getElementById('notification-bell');
    const bellBadge = document.getElementById('bell-badge');
    const dropdown = document.getElementById('notification-dropdown');
    const notifList = document.getElementById('notification-list');
    const markAllBtn = document.getElementById('mark-all-read');

    if (bell && dropdown) {
        bell.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = dropdown.classList.toggle('open');
            if (isOpen) fetchNotifications();
        });

        document.addEventListener('click', (e) => {
            if (!dropdown.contains(e.target) && !bell.contains(e.target)) {
                dropdown.classList.remove('open');
            }
        });

        if (markAllBtn) {
            markAllBtn.addEventListener('click', async () => {
                try {
                    await fetch('/api/v1/notifications/read', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ all: true }),
                    });
                    fetchNotifications();
                    pollUnreadCount();
                } catch (_) {}
            });
        }

        function notifIcon(kind) {
            switch (kind) {
                case 'stack_update_available':
                    return '<span class="material-icons-outlined notif-icon update">system_update</span>';
                case 'stack_published':
                    return '<span class="material-icons-outlined notif-icon publish">new_releases</span>';
                default:
                    return '<span class="material-icons-outlined notif-icon system">info</span>';
            }
        }

        async function fetchNotifications() {
            try {
                const resp = await fetch('/api/v1/notifications');
                if (!resp.ok) return;
                const data = await resp.json();
                if (!data.notifications || data.notifications.length === 0) {
                    notifList.innerHTML = '<div class="notification-empty">No notifications</div>';
                    return;
                }
                notifList.innerHTML = data.notifications.map(n =>
                    `<div class="notification-item ${n.read ? '' : 'unread'}">
                        ${notifIcon(n.kind)}
                        <div class="notif-body">
                            <p class="notif-title">${escapeHtml(n.title)}</p>
                            <p class="notif-message">${escapeHtml(n.message)}</p>
                        </div>
                    </div>`
                ).join('');
            } catch (_) {}
        }

        async function pollUnreadCount() {
            try {
                const resp = await fetch('/api/v1/notifications/unread-count');
                if (!resp.ok) return;
                const data = await resp.json();
                const count = data.unread_count || 0;
                if (bellBadge) {
                    bellBadge.textContent = count > 99 ? '99+' : String(count);
                    bellBadge.classList.toggle('has-unread', count > 0);
                }
            } catch (_) {}
        }

        function escapeHtml(str) {
            const d = document.createElement('div');
            d.textContent = str;
            return d.innerHTML;
        }

        // Initial poll + periodic refresh
        pollUnreadCount();
        setInterval(pollUnreadCount, 60000);
    }
});