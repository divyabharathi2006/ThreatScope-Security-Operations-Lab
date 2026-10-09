(function () {
  function buildRelationshipGraph(records, events = []) {
    const nodes = [];
    const links = [];
    const seenNodes = new Set();

    records.forEach((record) => {
      const key = `${record.type}:${record.value}`;
      if (!seenNodes.has(key)) {
        seenNodes.add(key);
        nodes.push({ id: record.id, label: record.value, type: record.type });
      }

      if (Array.isArray(record.related)) {
        record.related.forEach((relatedId) => {
          const relatedEvent = events.find((event) => event.id === relatedId);
          const relatedRecord = records.find((item) => item.id === relatedId);
          if (relatedEvent || relatedRecord) {
            links.push({ source: record.id, target: relatedId, label: 'related' });
          }
        });
      }
    });

    return { nodes, links };
  }

  function addIocRecord(list, record) {
    const entry = {
      id: record.id || `IOC-${Date.now()}`,
      type: record.type || 'URL',
      value: record.value || '',
      classification: record.classification || 'Unknown',
      riskScore: Number(record.riskScore || 0),
      createdAt: record.createdAt || new Date().toISOString(),
      lastChecked: record.lastChecked || new Date().toISOString(),
      tags: record.tags || [],
      notes: record.notes || '',
      watchlist: Boolean(record.watchlist),
      history: Array.isArray(record.history) ? record.history : [],
      related: Array.isArray(record.related) ? record.related : []
    };
    list.unshift(entry);
    return entry;
  }

  function detectRecordClassification(value) {
    const type = Validation.detectIocType(value);
    if (type === 'URL') return 'Suspicious';
    if (type === 'Domain') return 'Likely malicious';
    return 'Unknown';
  }

  function buildNewRecord(rawValue, notes = '') {
    const value = Validation.sanitizeText(rawValue);
    const type = Validation.detectIocType(value);
    const risk = RiskEngine.calculateRiskScore(value, [{ label: 'New IOC observation', points: 12 }]);

    return {
      id: `IOC-${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
      type,
      value,
      classification: detectRecordClassification(value),
      riskScore: risk.score,
      createdAt: new Date().toISOString(),
      lastChecked: new Date().toISOString(),
      notes,
      tags: ['manual'],
      watchlist: false,
      history: ['IOC created', 'Initial heuristic review completed'],
      related: []
    };
  }

  window.IocAnalyzer = {
    buildRelationshipGraph,
    addIocRecord,
    buildNewRecord,
    detectRecordClassification
  };
})();
