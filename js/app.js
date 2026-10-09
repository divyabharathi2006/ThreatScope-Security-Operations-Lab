(function () {
  document.addEventListener('DOMContentLoaded', () => {
    const rawState = localStorage.getItem('threatscope-local-v1');
    const parsedState = rawState ? JSON.parse(rawState) : null;
    if (!parsedState || !parsedState.schemaVersion) {
      StorageManager.saveState(StorageManager.getDefaultState());
    }

    const initialTheme = localStorage.getItem('threatscope-theme') || 'dark';
    UI.setTheme(initialTheme);
    const currentView = (window.location.hash || '#overview').replace('#', '');
    UI.renderView(currentView || 'overview');

    document.querySelectorAll('.nav-link').forEach((button) => {
      button.addEventListener('click', () => {
        const selectedView = button.dataset.view;
        window.history.pushState({ view: selectedView }, '', `#${selectedView}`);
        UI.renderView(selectedView);
      });
    });

    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        const nextTheme = document.body.classList.contains('light-theme') ? 'dark' : 'light';
        UI.setTheme(nextTheme);
      });
    }

    document.getElementById('globalSearch').addEventListener('input', (event) => {
      const state = StorageManager.loadState();
      state.filters.search = event.target.value;
      StorageManager.saveState(state);
    });

    window.addEventListener('popstate', () => {
      const next = (window.location.hash || '#overview').replace('#', '');
      UI.renderView(next || 'overview');
    });
  });
})();
