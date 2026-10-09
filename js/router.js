(function () {
  function navigate(viewName) {
    const safeView = viewName || 'overview';
    window.history.pushState({ view: safeView }, '', `#${safeView}`);
    UI.renderView(safeView);
  }

  function init() {
    const view = window.location.hash.replace('#', '') || 'overview';
    UI.renderView(view);
  }

  window.Router = { navigate, init };
})();
