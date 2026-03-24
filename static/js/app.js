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
});