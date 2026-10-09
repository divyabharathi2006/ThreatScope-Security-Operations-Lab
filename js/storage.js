(function () {
  const STORAGE_KEY = 'threatscope-local-v1';

  function deepClone(data) {
    return JSON.parse(JSON.stringify(data));
  }

  function getDefaultState() {
    return {
      schemaVersion: 1,
      theme: 'dark',
      filters: {
        severity: 'all',
        dateRange: '7d',
        search: '',
        page: 1
      },
      settings: {
        analystLabel: 'Analyst-01',
        threatSources: {
          virustotal: { enabled: false, apiKey: '', lastLookup: 'Unavailable', lastError: 'API key not configured', quota: 'Not configured' },
          google: { enabled: false, apiKey: '', lastLookup: 'Unavailable', lastError: 'API key not configured', quota: 'Not configured' },
          abuseipdb: { enabled: false, apiKey: '', lastLookup: 'Unavailable', lastError: 'API key not configured', quota: 'Not configured' }
        }
      },
      dashboard: {},
      suspiciousUrls: [],
      events: [],
      iocs: [],
      watchlist: [],
      intelligenceSources: [],
      scenarioProgress: {},
      investigations: [],
      notes: {},
      analystLabel: 'Analyst-01'
    };
  }

  function isLegacyDemoState(parsed) {
    if (!parsed || typeof parsed !== 'object') return false;
    const eventIds = Array.isArray(parsed.events) ? parsed.events.map((entry) => entry && entry.id).filter(Boolean) : [];
    const dashboard = parsed.dashboard || {};
    const suspiciousCount = Array.isArray(parsed.suspiciousUrls) ? parsed.suspiciousUrls.length : 0;
    return (
      dashboard.totalInvestigated === 184 ||
      dashboard.totalEvents === 428 ||
      eventIds.includes('EVT-1001') ||
      suspiciousCount > 0 && parsed.investigations && parsed.investigations.some((item) => item && item.id === 'INV-1001')
    );
  }

  function seedDemoData() {
    const base = window.demoData || {};
    const seeded = {
      ...getDefaultState(),
      theme: base.theme || 'dark',
      filters: { ...getDefaultState().filters, ...(base.filters || {}) },
      settings: { ...getDefaultState().settings, ...(base.settings || {}) },
      dashboard: deepClone(base.dashboard || {}),
      suspiciousUrls: deepClone(base.suspiciousUrls || []),
      events: deepClone(base.events || []),
      iocs: deepClone(base.iocs || []),
      watchlist: deepClone(base.watchlist || []),
      intelligenceSources: deepClone(base.intelligenceSources || []),
      scenarioProgress: deepClone(base.scenarioProgress || {}),
      investigations: deepClone(base.investigations || []),
      analystLabel: base.analystLabel || 'Analyst-01'
    };
    saveState(seeded);
    return seeded;
  }

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        return getDefaultState();
      }

      const parsed = JSON.parse(raw);
      const base = getDefaultState();
      if (!parsed || typeof parsed !== 'object') {
        return base;
      }

      if (isLegacyDemoState(parsed)) {
        const reset = getDefaultState();
        localStorage.setItem(STORAGE_KEY, JSON.stringify(reset));
        return reset;
      }

      return {
        ...base,
        ...parsed,
        filters: { ...base.filters, ...(parsed.filters || {}) },
        settings: { ...base.settings, ...(parsed.settings || {}) },
        dashboard: { ...base.dashboard, ...(parsed.dashboard || {}) },
        events: Array.isArray(parsed.events) ? parsed.events : base.events,
        iocs: Array.isArray(parsed.iocs) ? parsed.iocs : base.iocs,
        watchlist: Array.isArray(parsed.watchlist) ? parsed.watchlist : base.watchlist,
        investigations: Array.isArray(parsed.investigations) ? parsed.investigations : base.investigations,
        scenarioProgress: { ...base.scenarioProgress, ...(parsed.scenarioProgress || {}) },
        notes: parsed.notes || {},
        analystLabel: parsed.analystLabel || base.analystLabel
      };
    } catch (error) {
      console.warn('localStorage failed; restoring default state.', error);
      return getDefaultState();
    }
  }

  function saveState(state) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
      return true;
    } catch (error) {
      console.warn('Unable to save application state.', error);
      return false;
    }
  }

  function resetState() {
    const base = getDefaultState();
    saveState(base);
    return base;
  }

  function exportData() {
    const state = loadState();
    return JSON.stringify({ exportedAt: new Date().toISOString(), schemaVersion: 1, data: state }, null, 2);
  }

  function importData(payload) {
    try {
      const parsed = typeof payload === 'string' ? JSON.parse(payload) : payload;
      const data = parsed && parsed.data ? parsed.data : parsed;
      if (!data || typeof data !== 'object') {
        throw new Error('Import payload is not a valid object.');
      }
      const next = {
        ...getDefaultState(),
        ...data,
        filters: { ...getDefaultState().filters, ...(data.filters || {}) },
        settings: { ...getDefaultState().settings, ...(data.settings || {}) },
        dashboard: { ...getDefaultState().dashboard, ...(data.dashboard || {}) },
        events: Array.isArray(data.events) ? data.events : getDefaultState().events,
        iocs: Array.isArray(data.iocs) ? data.iocs : getDefaultState().iocs,
        watchlist: Array.isArray(data.watchlist) ? data.watchlist : getDefaultState().watchlist,
        investigations: Array.isArray(data.investigations) ? data.investigations : getDefaultState().investigations,
        scenarioProgress: { ...getDefaultState().scenarioProgress, ...(data.scenarioProgress || {}) }
      };
      saveState(next);
      return next;
    } catch (error) {
      console.warn('Import validation failed.', error);
      throw error;
    }
  }

  window.StorageManager = {
    STORAGE_KEY,
    getDefaultState,
    seedDemoData,
    loadState,
    saveState,
    resetState,
    exportData,
    importData
  };
})();
