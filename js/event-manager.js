(function () {
  function severityRank(level) {
    const map = { Informational: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
    return map[level] ?? 0;
  }

  function filterEvents(events, filters = {}) {
    const query = (filters.search || '').toLowerCase();
    const severity = (filters.severity || 'all').toLowerCase();
    const iocType = (filters.iocType || 'all').toLowerCase();
    const category = (filters.category || 'all').toLowerCase();

    return events.filter((event) => {
      const descriptionMatch = !query || (event.description || '').toLowerCase().includes(query) || (event.id || '').toLowerCase().includes(query);
      const severityMatch = severity === 'all' || (event.severity || '').toLowerCase() === severity;
      const iocTypeMatch = iocType === 'all' || (event.iocType || '').toLowerCase() === iocType;
      const categoryMatch = category === 'all' || (event.category || '').toLowerCase() === category;
      return descriptionMatch && severityMatch && iocTypeMatch && categoryMatch;
    });
  }

  function sortEvents(events, key = 'timestamp', direction = 'desc') {
    const normalized = [...events];
    normalized.sort((a, b) => {
      const valueA = key === 'severity' ? severityRank(a[key] || 'Informational') : new Date(a[key] || 0).getTime();
      const valueB = key === 'severity' ? severityRank(b[key] || 'Informational') : new Date(b[key] || 0).getTime();
      return direction === 'asc' ? valueA - valueB : valueB - valueA;
    });
    return normalized;
  }

  function paginate(items, page = 1, perPage = 8) {
    const start = (page - 1) * perPage;
    return {
      page,
      perPage,
      total: items.length,
      items: items.slice(start, start + perPage),
      totalPages: Math.max(1, Math.ceil(items.length / perPage))
    };
  }

  function getEventSummary(events) {
    const summary = {
      total: events.length,
      critical: events.filter((event) => event.severity === 'Critical').length,
      high: events.filter((event) => event.severity === 'High').length,
      medium: events.filter((event) => event.severity === 'Medium').length,
      informational: events.filter((event) => event.severity === 'Informational').length
    };
    return summary;
  }

  window.EventManager = {
    filterEvents,
    sortEvents,
    paginate,
    getEventSummary
  };
})();
