(function () {
  const state = { currentView: 'overview', theme: 'dark', filters: {} };

  function setTheme(themeName) {
    const isDark = themeName !== 'light';
    document.body.classList.toggle('light-theme', !isDark);
    state.theme = isDark ? 'dark' : 'light';
    const themeButton = document.getElementById('themeToggle');
    if (themeButton) {
      themeButton.textContent = isDark ? '☼' : '☾';
    }
    localStorage.setItem('threatscope-theme', state.theme);
  }

  function showToast(message, kind = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    if (kind === 'error') toast.style.borderColor = 'rgba(255, 97, 97, 0.28)';
    else if (kind === 'success') toast.style.borderColor = 'rgba(90, 226, 164, 0.28)';
    container.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 2600);
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[character]);
  }

  function severityClass(value) {
    const severity = String(value || '').toLowerCase();
    return ['informational', 'low', 'medium', 'high', 'critical'].includes(severity) ? severity : 'informational';
  }
  function riskClass(value) {
    const risk = String(value || '').toLowerCase().replace(/\s+/g, '');
    return ['low', 'guarded', 'suspicious', 'high', 'critical', 'unknown'].includes(risk) ? risk : 'unknown';
  }

  function eventMatchesFilters(event, filters = {}, include = {}) {
    const query = String(filters.search || '').trim().toLowerCase();
    const searchable = [event.id, event.timestamp, event.category, event.iocType, event.ioc, event.description,
      event.sourceType, event.severity, event.status, event.analystAction, event.notes].join(' ').toLowerCase();
    const eventDate = String(event.timestamp || '').slice(0, 10);
    return (!query || searchable.includes(query))
      && (!include.severity || !filters.severity || filters.severity === 'all' || String(event.severity || '').toLowerCase() === filters.severity.toLowerCase())
      && (!include.type || !filters.type || filters.type === 'all' || String(event.iocType || '').toLowerCase() === filters.type.toLowerCase())
      && (!include.category || !filters.category || filters.category === 'all' || String(event.category || '').toLowerCase() === filters.category.toLowerCase())
      && (!filters.from || eventDate >= filters.from)
      && (!filters.to || eventDate <= filters.to);
  }

  function getTimelineEvents(appState) {
    const filters = appState.filters?.timeline || {};
    return EventManager.sortEvents((appState.events || []).filter((event) => eventMatchesFilters(event, filters, {
      severity: true, type: true, category: true
    })), 'timestamp', 'desc');
  }

  function getExplorerEvents(appState, useSelection = false) {
    const filters = appState.filters?.eventExplorer || {};
    const filtered = (appState.events || []).filter((event) => eventMatchesFilters(event, filters, {
      severity: true, type: true
    }));
    const selectedIds = Array.isArray(filters.selectedIds) ? filters.selectedIds : [];
    const scoped = useSelection && selectedIds.length
      ? filtered.filter((event) => selectedIds.includes(event.id))
      : filtered;
    const sortBy = filters.sortBy || 'timestamp';
    const direction = filters.sortDirection === 'asc' ? 1 : -1;
    return [...scoped].sort((a, b) => {
      const left = a[sortBy] ?? '';
      const right = b[sortBy] ?? '';
      if (sortBy === 'timestamp') return (new Date(left).getTime() - new Date(right).getTime()) * direction;
      if (sortBy === 'severity') {
        const rank = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };
        return ((rank[String(left).toLowerCase()] ?? -1) - (rank[String(right).toLowerCase()] ?? -1)) * direction;
      }
      return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: 'base' }) * direction;
    });
  }

  function eventCsvRows(events) {
    return events.map((event) => ({
      timestamp: event.timestamp || '', eventId: event.id || '', category: event.category || '',
      type: event.iocType || '', source: event.sourceType || 'Unspecified', ioc: event.ioc || '',
      severity: event.severity || 'Unknown', status: event.status || 'Open',
      analystAction: event.analystAction || '', notes: event.notes || ''
    }));
  }

  function notificationRecords(appState) {
    return (appState.events || []).filter((event) => {
      const severity = String(event.severity || '').toLowerCase();
      const status = String(event.status || '').toLowerCase();
      const resolved = ['resolved', 'closed', 'dismissed'].includes(status);
      return !resolved && (event.isAlert === true || ['high', 'critical'].includes(severity));
    }).map((event) => ({
      id: `event:${event.id}`,
      eventId: event.id,
      title: `${event.severity || 'Security'} event: ${event.category || 'Uncategorized'}`,
      detail: `${event.ioc || 'No indicator'} · ${event.status || 'Open'}`,
      timestamp: event.timestamp || ''
    }));
  }

  function reportContext(appState) {
    const events = getExplorerEvents(appState, true);
    const eventIds = new Set(events.map((event) => event.id));
    const eventIocs = new Set(events.map((event) => event.ioc).filter(Boolean));
    const iocs = (appState.iocs || []).filter((ioc) => eventIocs.has(ioc.value)
      || (Array.isArray(ioc.related) && ioc.related.some((related) => eventIds.has(related))));
    const investigations = (appState.investigations || []).filter((item) => eventIocs.has(item.value)
      || eventIocs.has(item.title) || eventIds.has(item.id));
    const explorerFilters = appState.filters?.eventExplorer || {};
    const selectedCount = (explorerFilters.selectedIds || []).filter((id) => events.some((event) => event.id === id)).length;
    return {
      analystLabel: appState.analystLabel || 'Analyst-01',
      investigations,
      iocs,
      events,
      summary: { eventCount: events.length, critical: events.filter((event) => event.severity === 'Critical').length,
        high: events.filter((event) => event.severity === 'High').length },
      scope: selectedCount ? `Selected events (${events.length})` : `Filtered events (${events.length})`,
      filters: { search: explorerFilters.search || '', severity: explorerFilters.severity || 'all',
        type: explorerFilters.type || 'all', from: explorerFilters.from || '', to: explorerFilters.to || '' }
    };
  }

  function getRiskGuidance(result) {
    const score = Number(result?.risk?.score || 0);
    const verdict = result?.risk?.verdict || 'Unknown';

    if (score >= 80 || verdict === 'Critical') {
      return {
        title: 'High risk — do not use this site',
        detail: 'This URL or domain shows strong signs of deception, phishing, or malicious infrastructure. Avoid logging in, never enter credentials, and verify the official site through a trusted, separate channel before continuing.'
      };
    }

    if (score >= 60 || verdict === 'High Risk') {
      return {
        title: 'Risky site — proceed with caution',
        detail: 'This indicator looks suspicious, but the evidence is not conclusive enough to confirm a full compromise. Do not click through, do not sign in, and verify the destination with the vendor or support team.'
      };
    }

    if (score >= 40 || verdict === 'Suspicious') {
      return {
        title: 'Suspicious behavior detected',
        detail: 'The site may be a scam or spoofing a legitimate service. Check the exact domain, review certificate details, and avoid sharing credentials or files.'
      };
    }

    return {
      title: 'Low confidence — use with caution',
      detail: 'These signals do not prove malicious behavior, but they are not enough to trust the destination fully. Re-check the URL, prefer the official app, and avoid sensitive actions until you have verified the domain.'
    };
  }

  function renderValue(label, value) {
    return `<div class="field"><label>${label}</label><div>${value}</div></div>`;
  }

  function renderOverview() {
    const appState = StorageManager.loadState();
    const events = appState.events || [];
    const stats = appState.dashboard || {};
    const cards = [
      { label: 'Total Indicators Investigated', value: Number(stats.totalInvestigated || 0), trend: '+0.0%' },
      { label: 'High-Risk Indicators', value: Number(stats.highRiskIndicators || 0), trend: '+0.0%' },
      { label: 'Critical Indicators', value: Number(stats.criticalIndicators || 0), trend: '+0.0%' },
      { label: 'Open Alerts', value: Number(stats.openAlerts || 0), trend: '+0.0%' },
      { label: 'Total Security Events', value: Number(stats.totalEvents || 0), trend: '+0.0%' }
    ];

    const severity = Array.isArray(stats.severityDistribution) && stats.severityDistribution.length
      ? stats.severityDistribution
      : [
          { label: 'Low', value: 0 },
          { label: 'Medium', value: 0 },
          { label: 'High', value: 0 },
          { label: 'Critical', value: 0 }
        ];

    const barHtml = severity.map((item) => `
      <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:0.5rem;">
        <div class="chart-bar" style="height:${Math.max(12, (item.value / 50) * 110 + 20)}px;"></div>
        <span class="muted">${escapeHtml(item.label)}</span>
      </div>
    `).join('');

    const eventsHtml = (events.slice(0, 5)).map((event) => `
      <div class="timeline-item">
        <div class="timeline-time">${new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
        <div>
          <strong>${escapeHtml(event.category || 'Uncategorized')}</strong>
          <div class="muted">${escapeHtml(event.description || '')}</div>
          <div class="table-actions"><span class="severity-pill ${severityClass(event.severity)}">${escapeHtml(event.severity || 'Unknown')}</span></div>
        </div>
      </div>
    `).join('') || '<div class="empty-state">No security activity has been ingested yet.</div>';

    return `
      <section class="page-header">
        <h2>Overview Dashboard</h2>
        <div class="page-actions">
          <button class="secondary-btn" data-action="refresh-dashboard">Refresh Feed</button>
          <button class="primary-btn" data-action="export-overview">Export Summary</button>
        </div>
      </section>

      <div class="kpi-grid">
        ${cards.map((card) => `
          <div class="kpi-card">
            <div class="kpi-label">${card.label}</div>
            <div class="kpi-value">${card.value}</div>
            <div class="kpi-trend">↗ ${card.trend}</div>
          </div>
        `).join('')}
      </div>

      <div class="two-col" style="margin-top:1rem;">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Threat Severity Distribution</h3>
          </div>
          <div class="chart-bars">${barHtml}</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Recent Activity</h3>
          </div>
          <div class="timeline-list">${eventsHtml}</div>
        </div>
      </div>

      <div class="card-grid" style="margin-top:1rem;">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Recent Suspicious URLs</h3>
          </div>
          <table class="list-table">
            <tbody>
              ${(appState.suspiciousUrls || []).map((row) => `
                <tr>
                  <td>${escapeHtml(row.url)}</td>
                  <td><span class="risk-badge ${riskClass(row.risk)}">${escapeHtml(row.risk || 'Unknown')}</span></td>
                  <td>${escapeHtml(row.status)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Latest Saved Events</h3>
          </div>
          <ul class="timeline-list">
            ${(events || []).slice(0, 4).map((event) => `
              <li><strong>${escapeHtml(event.id || 'Event')}</strong> — ${escapeHtml(event.description || '')}</li>
            `).join('')}
          </ul>
        </div>
      </div>
    `;
  }

  function renderUrlInspector() {
    return `
      <section class="page-header">
        <h2>URL and Domain Risk Inspector</h2>
      </section>
      <div class="two-col">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Analyze Indicator</h3>
          </div>
          <div class="field">
            <label for="riskUrlInput">URL / Domain / IP / Hash</label>
            <input id="riskUrlInput" type="text" placeholder="https://example.com/login or domain.example" />
          </div>
          <div class="page-actions" style="margin-top:1rem;">
            <button class="primary-btn" id="analyzeRiskBtn">Inspect</button>
            <button class="secondary-btn" id="saveInvestigationBtn">Save to History</button>
          </div>
          <div id="riskAnalysisResult" class="empty-state" style="margin-top:1rem;">Awaiting input.</div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Heuristic Findings</h3>
          </div>
          <div id="riskFindings" class="empty-state">No findings yet.</div>
        </div>
      </div>
    `;
  }

  function renderIocAnalyzer() {
    const appState = StorageManager.loadState();
    const rows = (appState.iocs || []).map((ioc) => `
      <tr>
        <td>${escapeHtml(ioc.type)}</td>
        <td>${escapeHtml(ioc.value)}</td>
        <td><span class="risk-badge ${riskClass(Number(ioc.riskScore) >= 80 ? 'critical' : Number(ioc.riskScore) >= 60 ? 'high' : Number(ioc.riskScore) >= 40 ? 'suspicious' : 'guarded')}">${escapeHtml(ioc.riskScore)}</span></td>
        <td>${escapeHtml(ioc.classification)}</td>
        <td>${ioc.watchlist ? 'Yes' : 'No'}</td>
      </tr>
    `).join('');

    return `
      <section class="page-header">
        <h2>IOC Analyzer</h2>
        <div class="page-actions">
          <button class="primary-btn" id="addIocBtn">Add IOC</button>
        </div>
      </section>
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Indicator Records</h3>
        </div>
        <table class="list-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Risk</th>
              <th>Classification</th>
              <th>Watchlist</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  }

  function renderTimeline() {
    const appState = StorageManager.loadState();
    const filters = appState.filters?.timeline || {};
    const timeline = getTimelineEvents(appState);
    const categories = [...new Set((appState.events || []).map((event) => event.category).filter(Boolean))].sort();
    const types = [...new Set((appState.events || []).map((event) => event.iocType).filter(Boolean))].sort();
    const html = timeline.map((event) => `
      <article class="timeline-item">
        <div class="timeline-time">${escapeHtml(Timeline.formatTimestamp(event.timestamp))}</div>
        <div>
          <div><strong>${escapeHtml(event.category || 'Uncategorized')}</strong> <span class="severity-pill ${severityClass(event.severity)}">${escapeHtml(event.severity || 'Unknown')}</span></div>
          <div class="muted">${escapeHtml(event.ioc || 'No indicator')} | ${escapeHtml(event.sourceType || 'Source unspecified')}</div>
          <div>${escapeHtml(event.description || 'No description recorded.')}</div>
          <button class="ghost-btn" data-event-open="${escapeHtml(event.id)}">View event details</button>
        </div>
      </article>
    `).join('');

    return `
      <section class="page-header">
        <h2>Threat Event Timeline</h2>
        <div class="page-actions"><button class="secondary-btn" id="exportTimelineBtn" ${timeline.length ? '' : 'disabled'}>Export filtered CSV</button></div>
      </section>
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Chronological Security Events</h3>
          <span class="muted">${timeline.length} matching event${timeline.length === 1 ? '' : 's'} · browser-local records</span>
        </div>
        <div class="form-grid timeline-filters">
          <div class="field"><label for="timelineSearch">Search</label><input id="timelineSearch" value="${escapeHtml(filters.search || '')}" placeholder="Search events and indicators" /></div>
          <div class="field"><label for="timelineType">Indicator type</label><select id="timelineType"><option value="all">All types</option>${types.map((type) => `<option value="${escapeHtml(type)}" ${filters.type === type ? 'selected' : ''}>${escapeHtml(type)}</option>`).join('')}</select></div>
          <div class="field"><label for="timelineSeverity">Severity</label><select id="timelineSeverity"><option value="all">All severities</option>${['Informational', 'Low', 'Medium', 'High', 'Critical'].map((value) => `<option value="${value.toLowerCase()}" ${String(filters.severity || 'all').toLowerCase() === value.toLowerCase() ? 'selected' : ''}>${value}</option>`).join('')}</select></div>
          <div class="field"><label for="timelineCategory">Category</label><select id="timelineCategory"><option value="all">All categories</option>${categories.map((category) => `<option value="${escapeHtml(category)}" ${filters.category === category ? 'selected' : ''}>${escapeHtml(category)}</option>`).join('')}</select></div>
          <div class="field"><label for="timelineFrom">From</label><input id="timelineFrom" type="date" value="${escapeHtml(filters.from || '')}" /></div>
          <div class="field"><label for="timelineTo">To</label><input id="timelineTo" type="date" value="${escapeHtml(filters.to || '')}" /></div>
        </div>
        <div class="timeline-list" style="margin-top:1rem;">${html || '<div class="empty-state">No saved events match these filters.</div>'}</div>
      </div>
    `;
  }

  function renderEventLog() {
    const appState = StorageManager.loadState();
    const filters = appState.filters?.eventExplorer || {};
    const filtered = getExplorerEvents(appState);
    const page = Math.max(1, Number(filters.page || 1));
    const perPage = 8;
    const totalPages = Math.max(1, Math.ceil(filtered.length / perPage));
    const currentPage = Math.min(page, totalPages);
    const pageEvents = filtered.slice((currentPage - 1) * perPage, currentPage * perPage);
    const selectedIds = Array.isArray(filters.selectedIds) ? filters.selectedIds : [];
    const selectedOnPage = pageEvents.length > 0 && pageEvents.every((event) => selectedIds.includes(event.id));
    const types = [...new Set((appState.events || []).map((event) => event.iocType).filter(Boolean))].sort();
    const sortHeaders = [['timestamp', 'Timestamp'], ['id', 'ID'], ['category', 'Category'], ['iocType', 'Type'],
      ['sourceType', 'Source'], ['ioc', 'IOC'], ['severity', 'Severity'], ['status', 'Status']];
    const rows = pageEvents.map((event) => {
      const resolved = ['resolved', 'closed'].includes(String(event.status || '').toLowerCase());
      return `
      <tr>
        <td><input type="checkbox" data-event-select="${escapeHtml(event.id)}" aria-label="Select ${escapeHtml(event.id)}" ${selectedIds.includes(event.id) ? 'checked' : ''} /></td>
        <td>${escapeHtml(event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown')}</td>
        <td><button class="ghost-btn" data-event-open="${escapeHtml(event.id)}">${escapeHtml(event.id || 'Unknown')}</button></td>
        <td>${escapeHtml(event.category || 'Uncategorized')}</td>
        <td>${escapeHtml(event.iocType || 'Unspecified')}</td>
        <td>${escapeHtml(event.sourceType || 'Unspecified')}</td>
        <td class="event-ioc-cell">${escapeHtml(event.ioc || '—')}</td>
        <td><span class="severity-pill ${severityClass(event.severity)}">${escapeHtml(event.severity || 'Unknown')}</span></td>
        <td>${escapeHtml(event.status || 'Open')}</td>
        <td>${escapeHtml(event.analystAction || '—')}</td>
        <td><div class="table-actions"><button class="small-btn" data-event-status="${escapeHtml(event.id)}">${resolved ? 'Reopen' : 'Resolve'}</button><button class="small-btn" data-event-notes="${escapeHtml(event.id)}">Notes${event.notes ? ' •' : ''}</button></div></td>
      </tr>
    `;
    }).join('');

    return `
      <section class="page-header">
        <h2>Security Event Explorer</h2>
        <div class="page-actions"><button class="secondary-btn" id="exportExplorerBtn" ${filtered.length ? '' : 'disabled'}>Export filtered CSV</button></div>
      </section>
      <div class="card">
        <div class="form-grid" style="margin-bottom:1rem;">
          <div class="field">
            <label for="eventSearchInput">Search</label>
            <input id="eventSearchInput" value="${escapeHtml(filters.search || '')}" placeholder="Search all event fields, notes, and indicators" />
          </div>
          <div class="field">
            <label for="eventSeverityFilter">Severity</label>
            <select id="eventSeverityFilter">
              <option value="all">All</option>
              <option value="informational" ${filters.severity === 'informational' ? 'selected' : ''}>Informational</option>
              <option value="low" ${filters.severity === 'low' ? 'selected' : ''}>Low</option>
              <option value="medium" ${filters.severity === 'medium' ? 'selected' : ''}>Medium</option>
              <option value="high" ${filters.severity === 'high' ? 'selected' : ''}>High</option>
              <option value="critical" ${filters.severity === 'critical' ? 'selected' : ''}>Critical</option>
            </select>
          </div>
          <div class="field"><label for="eventTypeFilter">Indicator type</label><select id="eventTypeFilter"><option value="all">All types</option>${types.map((type) => `<option value="${escapeHtml(type)}" ${filters.type === type ? 'selected' : ''}>${escapeHtml(type)}</option>`).join('')}</select></div>
          <div class="field"><label for="eventFromFilter">From</label><input id="eventFromFilter" type="date" value="${escapeHtml(filters.from || '')}" /></div>
          <div class="field"><label for="eventToFilter">To</label><input id="eventToFilter" type="date" value="${escapeHtml(filters.to || '')}" /></div>
        </div>
        <div class="event-bulk-actions">
          <label><input id="selectEventPage" type="checkbox" ${selectedOnPage ? 'checked' : ''} /> Select page</label>
          <span class="muted">${selectedIds.length} selected · ${filtered.length} matching event${filtered.length === 1 ? '' : 's'}</span>
          <button class="secondary-btn" id="markInvestigatedBtn" ${selectedIds.length ? '' : 'disabled'}>Mark selected investigated</button>
        </div>
        <div class="page-actions" style="margin-bottom:1rem;">
          <button class="secondary-btn" id="prevEventPageBtn" ${currentPage <= 1 ? 'disabled' : ''}>Previous</button>
          <span class="muted">Page ${currentPage} of ${totalPages}</span>
          <button class="secondary-btn" id="nextEventPageBtn" ${currentPage >= totalPages ? 'disabled' : ''}>Next</button>
        </div>
        <div class="table-scroll event-log-table-wrap"><table class="list-table">
          <thead>
            <tr>
              <th aria-label="Selection"></th>
              ${sortHeaders.map(([key, label]) => `<th aria-sort="${filters.sortBy === key ? (filters.sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'}"><button class="table-sort" data-sort-event="${key}">${label}${filters.sortBy === key ? (filters.sortDirection === 'asc' ? ' ↑' : ' ↓') : ''}</button></th>`).join('')}
              <th>Analyst Action</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="11">No events match the current filters.</td></tr>'}</tbody>
        </table></div>
      </div>
    `;
  }

  function renderSimulation() {
    const scenarios = SimulationLab.getScenarioCatalog();
    const appState = StorageManager.loadState();
    const cards = scenarios.map((scenario) => {
      const progress = appState.scenarioProgress && appState.scenarioProgress[scenario.id];
      const scoreText = progress && Number.isFinite(progress.score) ? `Score: ${progress.score}%` : 'Not run yet';
      return `
        <div class="simulation-card">
          <div class="card-header">
            <h3 class="card-title">${scenario.title}</h3>
          </div>
          <div class="scenario-badges">
            <span class="badge-pill">SIMULATION MODE</span>
            <span class="badge-pill">${scenario.id}</span>
          </div>
          <p>${scenario.description}</p>
          <div class="muted">${scoreText}</div>
          <button class="primary-btn" data-scenario="${scenario.id}">Run Scenario</button>
        </div>
      `;
    }).join('');

    return `
      <section class="page-header">
        <h2>Attack Simulation Lab</h2>
      </section>
      <div class="card-grid">${cards}</div>
    `;
  }

  function renderSources() {
    const appState = StorageManager.loadState();
    const settings = appState.settings?.threatSources || {};
    const rows = ThreatSources.getSourceCatalog().map((source) => {
      const config = settings[source.key] || {};
      const configured = Boolean(config.enabled && config.apiKey);
      const status = configured ? 'Unavailable' : 'Not configured';
      const detail = configured
        ? 'Credentials are present in local browser settings, but no live integration is implemented.'
        : 'No credentials configured; no lookup has been performed.';
      return `
      <tr>
        <td>${escapeHtml(source.name)}</td>
        <td><span class="status-pill">${status}</span></td>
        <td>Unavailable</td>
        <td>${escapeHtml(detail)}</td>
        <td>Not available</td>
        <td>Not queried</td>
        <td><a href="${escapeHtml(source.docs)}" target="_blank" rel="noopener noreferrer">Documentation</a></td>
      </tr>
    `;
    }).join('');

    return `
      <section class="page-header">
        <h2>Threat Intelligence Sources</h2>
      </section>
      <div class="card">
        <p class="alert-box">Browser-only mode: these providers are catalog entries, not active connections. No live threat intelligence is queried or represented here.</p>
        <table class="list-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Status</th>
              <th>Last successful lookup</th>
              <th>Last error</th>
              <th>Quota</th>
              <th>Result count</th>
              <th>Docs</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  }

  function renderReports() {
    const context = reportContext(StorageManager.loadState());
    const rows = context.events.map((event) => `<tr>
      <td>${escapeHtml(event.id || 'Unknown')}</td><td>${escapeHtml(event.category || 'Uncategorized')}</td>
      <td>${escapeHtml(event.ioc || '—')}</td><td>${escapeHtml(event.severity || 'Unknown')}</td><td>${escapeHtml(event.status || 'Open')}</td>
    </tr>`).join('');
    return `
      <section class="page-header">
        <h2>Investigation Reports</h2>
        <div class="page-actions">
          <button class="primary-btn" id="exportJsonBtn">Export JSON</button>
          <button class="secondary-btn" id="exportCsvBtn">Export CSV</button>
        </div>
      </section>
      <div class="card">
        <p class="muted">Preview and export the same event scope. Select events in Security Event Explorer to report only that selection; otherwise the current explorer filters are used.</p>
        <div class="report-meta">
          <div><strong>Scope:</strong> ${escapeHtml(context.scope)}</div>
          <div><strong>Source:</strong> Browser-local saved records; no live source connection</div>
          <div><strong>Confidence:</strong> Local record confidence only; external intelligence is not queried or independently verified.</div>
        </div>
        <div class="card-header"><h3 class="card-title">Event preview (${context.events.length})</h3></div>
        <div class="table-scroll"><table class="list-table"><thead><tr><th>ID</th><th>Category</th><th>IOC</th><th>Severity</th><th>Status</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No events in the current report scope.</td></tr>'}</tbody></table></div>
        <details class="report-json-preview"><summary>Preview report data</summary><pre>${escapeHtml(JSON.stringify(context, null, 2))}</pre></details>
      </div>
    `;
  }

  function renderWatchlist() {
    const appState = StorageManager.loadState();
    const items = (appState.iocs || []).filter((ioc) => ioc.watchlist);
    const rows = items.map((ioc) => `
      <tr>
        <td>${escapeHtml(ioc.value)}</td>
        <td>${escapeHtml(ioc.type)}</td>
        <td><span class="risk-badge ${riskClass(Number(ioc.riskScore) >= 80 ? 'critical' : Number(ioc.riskScore) >= 60 ? 'high' : Number(ioc.riskScore) >= 40 ? 'suspicious' : 'guarded')}">${escapeHtml(ioc.riskScore)}</span></td>
        <td>${escapeHtml(ioc.classification)}</td>
      </tr>
    `).join('');

    return `
      <section class="page-header">
        <h2>Watchlist</h2>
      </section>
      <div class="card">
        <table class="list-table">
          <thead>
            <tr>
              <th>Indicator</th>
              <th>Type</th>
              <th>Risk</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="4">No watchlisted indicators yet.</td></tr>'}</tbody>
        </table>
      </div>
    `;
  }

  function renderSettings() {
    const appState = StorageManager.loadState();
    return `
      <section class="page-header">
        <h2>Settings and Data Management</h2>
      </section>
      <div class="card-grid">
        <div class="card">
          <div class="card-header"><h3 class="card-title">Theme</h3></div>
          <button class="primary-btn" id="themeToggleSettings">Toggle Theme</button>
        </div>
        <div class="card">
          <div class="card-header"><h3 class="card-title">Storage</h3></div>
          <div class="page-actions">
            <button class="secondary-btn" id="exportDataBtn">Export JSON</button>
            <button class="secondary-btn" id="importDataBtn">Import JSON</button>
            <button class="danger-btn" id="resetDataBtn">Clear All Data</button>
          </div>
          <input id="fileImportInput" type="file" accept="application/json" class="hidden" />
        </div>
      </div>
      <div class="card" style="margin-top:1rem;">
        <div class="card-header"><h3 class="card-title">Analyst Settings</h3></div>
        <div class="field">
          <label for="analystLabelInput">Analyst Label</label>
          <input id="analystLabelInput" value="${appState.analystLabel || 'Analyst-01'}" />
        </div>
      </div>
    `;
  }

  function renderHelp() {
    return `
      <section class="page-header">
        <h2>Help and Analyst Guide</h2>
      </section>
      <div class="card">
        <h3>Analyst guidance</h3>
        <ul>
          <li>Validate URLs and domains before trusting brand signals.</li>
          <li>Use heuristic score as a starting point, not a final verdict.</li>
          <li>Verify external intelligence and avoid exposing secrets in browser-based integrations.</li>
          <li>Label all simulation data clearly to prevent confusion with real telemetry.</li>
        </ul>
      </div>
    `;
  }

  function saveEventField(eventId, update) {
    const appState = StorageManager.loadState();
    const event = (appState.events || []).find((item) => item.id === eventId);
    if (!event) return false;
    update(event);
    StorageManager.saveState(appState);
    return true;
  }

  function showEventDetails(eventId) {
    const event = (StorageManager.loadState().events || []).find((item) => item.id === eventId);
    if (!event) return;
    const modal = document.getElementById('modalRoot');
    const content = document.createElement('div');
    content.className = 'modal-content';
    const title = document.createElement('h3');
    title.textContent = event.id || 'Security event';
    content.appendChild(title);
    [['Description', event.description], ['Category', event.category], ['Indicator type', event.iocType],
      ['IOC', event.ioc], ['Severity', event.severity], ['Status', event.status],
      ['Source label', event.sourceType || 'Unspecified'], ['Analyst action', event.analystAction], ['Notes', event.notes]]
      .forEach(([label, value]) => {
        const paragraph = document.createElement('p');
        const strong = document.createElement('strong');
        strong.textContent = `${label}: `;
        paragraph.append(strong, document.createTextNode(value || 'Not recorded'));
        content.appendChild(paragraph);
      });
    const close = document.createElement('button');
    close.className = 'primary-btn';
    close.textContent = 'Close';
    close.addEventListener('click', () => modal.classList.remove('open'));
    content.appendChild(close);
    modal.replaceChildren(content);
    modal.classList.add('open');
  }

  function editEventNotes(eventId) {
    const event = (StorageManager.loadState().events || []).find((item) => item.id === eventId);
    if (!event) return;
    const modal = document.getElementById('modalRoot');
    const content = document.createElement('div');
    content.className = 'modal-content';
    const title = document.createElement('h3');
    title.textContent = `Analyst notes · ${event.id}`;
    const label = document.createElement('label');
    label.htmlFor = 'eventNotesInput';
    label.textContent = 'Notes (stored in this browser)';
    const textarea = document.createElement('textarea');
    textarea.id = 'eventNotesInput';
    textarea.value = event.notes || '';
    const actions = document.createElement('div');
    actions.className = 'page-actions';
    const save = document.createElement('button');
    save.className = 'primary-btn';
    save.textContent = 'Save notes';
    save.addEventListener('click', () => {
      saveEventField(eventId, (record) => { record.notes = textarea.value; });
      modal.classList.remove('open');
      renderView(state.currentView);
      showToast('Event notes saved locally.', 'success');
    });
    const cancel = document.createElement('button');
    cancel.className = 'secondary-btn';
    cancel.textContent = 'Cancel';
    cancel.addEventListener('click', () => modal.classList.remove('open'));
    actions.append(save, cancel);
    content.append(title, label, textarea, actions);
    modal.replaceChildren(content);
    modal.classList.add('open');
    textarea.focus();
  }

  function navigateToEvent(eventId) {
    const event = (StorageManager.loadState().events || []).find((item) => item.id === eventId);
    if (!event) return;
    window.history.pushState({ view: 'event-log' }, '', '#event-log');
    document.querySelectorAll('.nav-link').forEach((button) => button.classList.toggle('active', button.dataset.view === 'event-log'));
    renderView('event-log');
    showEventDetails(eventId);
  }

  function bindNotifications() {
    const button = document.getElementById('notificationsButton');
    if (!button) return;
    let panel = document.getElementById('notificationPanel');
    if (!panel) {
      panel = document.createElement('section');
      panel.id = 'notificationPanel';
      panel.className = 'notification-panel hidden';
      panel.setAttribute('aria-label', 'Notifications');
      document.querySelector('.topbar-actions')?.appendChild(panel);
      panel.addEventListener('click', (event) => {
        const action = event.target.closest('[data-notification-read], [data-notification-dismiss], [data-notification-open]');
        if (!action) return;
        const eventId = action.dataset.notificationRead || action.dataset.notificationDismiss || action.dataset.notificationOpen;
        if (action.dataset.notificationOpen) {
          const appState = StorageManager.loadState();
          const notificationState = appState.notificationState || { readIds: [], dismissedIds: [] };
          notificationState.readIds = [...new Set([...(notificationState.readIds || []), `event:${eventId}`])];
          appState.notificationState = notificationState;
          StorageManager.saveState(appState);
          panel.classList.add('hidden');
          navigateToEvent(eventId);
          return;
        }
        const appState = StorageManager.loadState();
        const notificationState = appState.notificationState || { readIds: [], dismissedIds: [] };
        const property = action.dataset.notificationRead ? 'readIds' : 'dismissedIds';
        notificationState[property] = [...new Set([...(notificationState[property] || []), `event:${eventId}`])];
        appState.notificationState = notificationState;
        StorageManager.saveState(appState);
        renderNotificationPanel(panel, button);
      });
    }
    if (!button.dataset.notificationsBound) {
      button.addEventListener('click', () => {
        panel.classList.toggle('hidden');
        renderNotificationPanel(panel, button);
      });
      button.dataset.notificationsBound = 'true';
    }
    renderNotificationPanel(panel, button);
  }

  function renderNotificationPanel(panel, button) {
    const appState = StorageManager.loadState();
    const notificationState = appState.notificationState || { readIds: [], dismissedIds: [] };
    const dismissed = notificationState.dismissedIds || [];
    const read = notificationState.readIds || [];
    const records = notificationRecords(appState).filter((record) => !dismissed.includes(record.id));
    const unreadCount = records.filter((record) => !read.includes(record.id)).length;
    const badge = button.querySelector('.badge');
    if (badge) {
      badge.textContent = String(unreadCount);
      badge.hidden = unreadCount === 0;
    }
    button.setAttribute('aria-expanded', String(!panel.classList.contains('hidden')));
    panel.innerHTML = `<div class="notification-header"><strong>Local event alerts</strong><span>${unreadCount} unread</span></div>${records.map((record) => `
      <article class="notification-item ${read.includes(record.id) ? 'is-read' : 'is-unread'}">
        <button class="notification-open" data-notification-open="${escapeHtml(record.eventId)}"><strong>${escapeHtml(record.title)}</strong><span>${escapeHtml(record.detail)}</span><small>${escapeHtml(record.timestamp ? Timeline.formatTimestamp(record.timestamp) : 'Time unavailable')}</small></button>
        <div class="table-actions">${read.includes(record.id) ? '' : `<button class="small-btn" data-notification-read="${escapeHtml(record.eventId)}">Mark read</button>`}<button class="small-btn" data-notification-dismiss="${escapeHtml(record.eventId)}">Dismiss</button></div>
      </article>`).join('') || '<p class="empty-state">No active high-severity alerts in saved local events.</p>'}`;
  }

  function updateEventFilters(namespace, changes, preserveSelection = true) {
    const appState = StorageManager.loadState();
    const filters = appState.filters || {};
    filters[namespace] = { ...(filters[namespace] || {}), ...changes };
    if (Object.keys(changes).some((key) => ['search', 'severity', 'type', 'from', 'to', 'category'].includes(key))) {
      filters[namespace].page = 1;
      if (!preserveSelection) filters[namespace].selectedIds = [];
    }
    appState.filters = filters;
    StorageManager.saveState(appState);
  }

  function rerenderPreservingInput(viewName, inputId) {
    const current = document.getElementById(inputId);
    const start = current?.selectionStart;
    const end = current?.selectionEnd;
    renderView(viewName);
    const replacement = document.getElementById(inputId);
    if (replacement) {
      replacement.focus();
      if (start !== null && start !== undefined && replacement.setSelectionRange) replacement.setSelectionRange(start, end);
    }
  }

  function renderView(viewName) {
    state.currentView = viewName;
    const map = {
      overview: renderOverview,
      inspector: renderUrlInspector,
      'ioc-analyzer': renderIocAnalyzer,
      timeline: renderTimeline,
      'event-log': renderEventLog,
      simulation: renderSimulation,
      sources: renderSources,
      reports: renderReports,
      watchlist: renderWatchlist,
      settings: renderSettings,
      help: renderHelp
    };

    const container = document.getElementById('viewContainer');
    const renderFn = map[viewName] || renderOverview;
    container.innerHTML = renderFn();
    bindViewEvents();
  }

  function bindViewEvents() {
    const analyze = document.getElementById('analyzeRiskBtn');
    if (analyze) {
      analyze.addEventListener('click', async () => {
        const value = document.getElementById('riskUrlInput').value;
        const config = StorageManager.loadState().settings || {};
        const result = await UrlInspector.analyzeUrlInput(value, config.threatSources || {});
        const container = document.getElementById('riskAnalysisResult');
        const findings = document.getElementById('riskFindings');
        const guidance = getRiskGuidance(result);

        container.innerHTML = `
          <div><strong>Normalized host:</strong> ${result.hostname || 'N/A'}</div>
          <div><strong>Verdict:</strong> <span class="risk-badge ${result.risk.className}">${result.risk.verdict || 'Unknown'}</span></div>
          <div><strong>Score:</strong> ${result.risk.score}/100</div>
          <div><strong>Recommendation:</strong> ${guidance.title}</div>
          <div><strong>Fix / action:</strong> ${guidance.detail}</div>
          <div><strong>Evidence:</strong> ${result.messages.join(', ') || 'No evidence captured.'}</div>
        `;

        findings.innerHTML = result.risk.factors.length
          ? result.risk.factors.map((factor) => `<div class="info-box">${factor.label} (+${factor.points})</div>`).join('')
          : '<div class="empty-state">No heuristic findings available.</div>';

        const saveBtn = document.getElementById('saveInvestigationBtn');
        if (saveBtn) {
          saveBtn.dataset.pending = JSON.stringify({ value, verdict: result.risk.verdict, score: result.risk.score, host: result.hostname, evidence: result.messages });
        }
      });
    }

    const saveInvestigationBtn = document.getElementById('saveInvestigationBtn');
    if (saveInvestigationBtn) {
      saveInvestigationBtn.addEventListener('click', () => {
        const pending = saveInvestigationBtn.dataset.pending ? JSON.parse(saveInvestigationBtn.dataset.pending) : null;
        if (!pending || !pending.value) {
          showToast('Inspect a URL first before saving.', 'error');
          return;
        }
        const appState = StorageManager.loadState();
        const record = {
          id: `INV-${Date.now()}`,
          title: pending.host || pending.value,
          type: 'URL',
          value: pending.value,
          riskScore: pending.score || 0,
          verdict: pending.verdict || 'Unknown',
          createdAt: new Date().toISOString()
        };
        appState.investigations = [record, ...(appState.investigations || [])];
        StorageManager.saveState(appState);
        showToast('Investigation saved to local history.', 'success');
      });
    }

    const exportJsonBtn = document.getElementById('exportJsonBtn');
    if (exportJsonBtn) {
      exportJsonBtn.addEventListener('click', () => {
        const appState = StorageManager.loadState();
        ReportExport.exportJsonReport(reportContext(appState));
        showToast('JSON report downloaded.', 'success');
      });
    }

    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
      exportCsvBtn.addEventListener('click', () => {
        const context = reportContext(StorageManager.loadState());
        ReportExport.exportCsvReport(eventCsvRows(context.events), 'threatscope-investigation-events');
        showToast('CSV export downloaded.', 'success');
      });
    }

    const exportTimelineBtn = document.getElementById('exportTimelineBtn');
    if (exportTimelineBtn) {
      exportTimelineBtn.addEventListener('click', () => {
        ReportExport.exportCsvReport(eventCsvRows(getTimelineEvents(StorageManager.loadState())), 'threatscope-timeline');
        showToast('Filtered timeline CSV downloaded.', 'success');
      });
    }

    const exportExplorerBtn = document.getElementById('exportExplorerBtn');
    if (exportExplorerBtn) {
      exportExplorerBtn.addEventListener('click', () => {
        ReportExport.exportCsvReport(eventCsvRows(getExplorerEvents(StorageManager.loadState())), 'threatscope-event-explorer');
        showToast('Filtered event CSV downloaded.', 'success');
      });
    }

    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        const nextTheme = state.theme === 'dark' ? 'light' : 'dark';
        setTheme(nextTheme);
      });
    }

    const themeToggleSettings = document.getElementById('themeToggleSettings');
    if (themeToggleSettings) {
      themeToggleSettings.addEventListener('click', () => {
        const nextTheme = state.theme === 'dark' ? 'light' : 'dark';
        setTheme(nextTheme);
      });
    }

    const exportDataBtn = document.getElementById('exportDataBtn');
    if (exportDataBtn) {
      exportDataBtn.addEventListener('click', () => {
        const data = StorageManager.exportData();
        const blob = new Blob([data], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'threatscope-storage-export.json';
        link.click();
        URL.revokeObjectURL(link.href);
      });
    }

    const importDataBtn = document.getElementById('importDataBtn');
    if (importDataBtn) {
      importDataBtn.addEventListener('click', () => {
        const input = document.getElementById('fileImportInput');
        if (input) input.click();
      });
    }

    const importFileInput = document.getElementById('fileImportInput');
    if (importFileInput) {
      importFileInput.addEventListener('change', async (event) => {
        const [file] = event.target.files || [];
        if (!file) return;
        try {
          const text = await file.text();
          const nextState = StorageManager.importData(text);
          StorageManager.saveState(nextState);
          renderView(state.currentView);
          showToast('Data imported and validated.', 'success');
        } catch (error) {
          showToast('Import failed: invalid JSON or schema.', 'error');
        } finally {
          importFileInput.value = '';
        }
      });
    }

    const analystLabelInput = document.getElementById('analystLabelInput');
    if (analystLabelInput) {
      analystLabelInput.addEventListener('change', () => {
        const appState = StorageManager.loadState();
        appState.analystLabel = analystLabelInput.value || 'Analyst-01';
        StorageManager.saveState(appState);
      });
    }

    const resetDataBtn = document.getElementById('resetDataBtn');
    if (resetDataBtn) {
      resetDataBtn.addEventListener('click', () => {
        const confirmed = confirm('Clear all locally stored ThreatScope data?');
        if (!confirmed) return;
        StorageManager.resetState();
        renderView(state.currentView);
        showToast('Stored data cleared.', 'success');
      });
    }

    const addIocBtn = document.getElementById('addIocBtn');
    if (addIocBtn) {
      addIocBtn.addEventListener('click', () => {
        const value = prompt('Enter an IOC value to add to the analyzer:', '');
        if (!value) return;
        const stateData = StorageManager.loadState();
        const record = IocAnalyzer.buildNewRecord(value, 'Added manually');
        stateData.iocs = [record, ...(stateData.iocs || [])];
        StorageManager.saveState(stateData);
        renderView('ioc-analyzer');
        showToast('IOC record added.', 'success');
      });
    }

    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle) {
      sidebarToggle.addEventListener('click', () => {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar) sidebar.classList.toggle('collapsed');
      });
    }

    document.querySelectorAll('[data-scenario]').forEach((button) => {
      button.addEventListener('click', () => {
        const scenarioId = button.dataset.scenario;
        const scenario = SimulationLab.scenarios[scenarioId];
        if (!scenario) return;

        const selectionHtml = scenario.answers.map((answer, index) => `
          <label class="scenario-option" style="display:block; margin:0.4rem 0;">
            <input type="checkbox" name="scenario-answer" value="${answer}" />
            <span>${answer}</span>
          </label>
        `).join('');

        const detail = `
          <div class="card">
            <h3>${scenario.title}</h3>
            <p><strong>Objective:</strong> ${scenario.objective}</p>
            <p><strong>Description:</strong> ${scenario.description}</p>
            <p><strong>Learning objective:</strong> ${scenario.learning.join(', ')}</p>
            <p><strong>Incident indicators:</strong> ${scenario.tasks.join(' • ')}</p>
            <div class="field" style="margin-top:1rem;">
              <label>Choose the findings that match the scenario</label>
              <div>${selectionHtml}</div>
            </div>
            <div class="page-actions" style="margin-top:1rem;">
              <button class="primary-btn" id="submitScenarioBtn">Submit Answers</button>
              <button class="secondary-btn" id="closeModalBtn">Close</button>
            </div>
          </div>
        `;

        const modal = document.getElementById('modalRoot');
        modal.innerHTML = `<div class="modal-content">${detail}</div>`;
        modal.classList.add('open');

        document.getElementById('closeModalBtn').addEventListener('click', () => modal.classList.remove('open'));
        document.getElementById('submitScenarioBtn').addEventListener('click', () => {
          const selected = Array.from(modal.querySelectorAll('input[name="scenario-answer"]:checked')).map((input) => input.value);
          const result = SimulationLab.computeScenarioScore(selected, scenario.id);
          const appState = StorageManager.loadState();
          const completed = {
            complete: true,
            score: result.score,
            total: result.total,
            selected,
            correct: result.correct
          };
          appState.scenarioProgress = { ...(appState.scenarioProgress || {}), [scenario.id]: completed };
          StorageManager.saveState(appState);

          const correctList = result.correct.length ? result.correct.join(', ') : 'No correct matches selected.';
          const html = `
            <div class="card">
              <h3>${scenario.title}</h3>
              <p><strong>Result:</strong> ${result.score}% correct (${result.correct.length}/${result.total})</p>
              <p><strong>Correct findings:</strong> ${correctList}</p>
              <p><strong>Analysis:</strong> ${scenario.detail}</p>
              <div class="page-actions" style="margin-top:1rem;">
                <button class="primary-btn" id="closeModalBtn">Close</button>
              </div>
            </div>
          `;
          modal.innerHTML = `<div class="modal-content">${html}</div>`;
          modal.querySelector('#closeModalBtn').addEventListener('click', () => modal.classList.remove('open'));
          renderView(state.currentView);
          showToast(`${scenario.title} graded at ${result.score}%.`, 'success');
        });
      });
    });

    const eventSearchInput = document.getElementById('eventSearchInput');
    if (eventSearchInput) eventSearchInput.addEventListener('input', (event) => {
      updateEventFilters('eventExplorer', { search: event.target.value });
      rerenderPreservingInput('event-log', 'eventSearchInput');
    });
    const eventSeverityFilter = document.getElementById('eventSeverityFilter');
    if (eventSeverityFilter) eventSeverityFilter.addEventListener('change', (event) => {
      updateEventFilters('eventExplorer', { severity: event.target.value });
      renderView('event-log');
    });
    const eventTypeFilter = document.getElementById('eventTypeFilter');
    if (eventTypeFilter) eventTypeFilter.addEventListener('change', (event) => {
      updateEventFilters('eventExplorer', { type: event.target.value });
      renderView('event-log');
    });
    [['eventFromFilter', 'from'], ['eventToFilter', 'to']].forEach(([id, key]) => {
      const input = document.getElementById(id);
      if (input) input.addEventListener('change', (event) => {
        updateEventFilters('eventExplorer', { [key]: event.target.value });
        renderView('event-log');
      });
    });
    document.querySelectorAll('[data-sort-event]').forEach((button) => button.addEventListener('click', () => {
      const appState = StorageManager.loadState();
      const filters = appState.filters?.eventExplorer || {};
      const sortBy = button.dataset.sortEvent;
      const sortDirection = filters.sortBy === sortBy && filters.sortDirection !== 'asc' ? 'asc' : 'desc';
      updateEventFilters('eventExplorer', { sortBy, sortDirection }, true);
      renderView('event-log');
    }));

    const selectEventPage = document.getElementById('selectEventPage');
    if (selectEventPage) selectEventPage.addEventListener('change', () => {
      const appState = StorageManager.loadState();
      const filters = appState.filters?.eventExplorer || {};
      const visibleIds = getExplorerEvents(appState).slice(((filters.page || 1) - 1) * 8, (filters.page || 1) * 8).map((event) => event.id);
      const selected = new Set(filters.selectedIds || []);
      visibleIds.forEach((id) => selectEventPage.checked ? selected.add(id) : selected.delete(id));
      updateEventFilters('eventExplorer', { selectedIds: [...selected] }, true);
      renderView('event-log');
    });
    document.querySelectorAll('[data-event-select]').forEach((checkbox) => checkbox.addEventListener('change', () => {
      const appState = StorageManager.loadState();
      const filters = appState.filters?.eventExplorer || {};
      const selected = new Set(filters.selectedIds || []);
      if (checkbox.checked) selected.add(checkbox.dataset.eventSelect);
      else selected.delete(checkbox.dataset.eventSelect);
      updateEventFilters('eventExplorer', { selectedIds: [...selected] }, true);
      renderView('event-log');
    }));

    const markInvestigatedBtn = document.getElementById('markInvestigatedBtn');
    if (markInvestigatedBtn) markInvestigatedBtn.addEventListener('click', () => {
      const appState = StorageManager.loadState();
      const selected = new Set(appState.filters?.eventExplorer?.selectedIds || []);
      appState.events = (appState.events || []).map((event) => selected.has(event.id)
        ? { ...event, status: 'Investigating', analystAction: 'Marked investigated locally' }
        : event);
      appState.filters.eventExplorer.selectedIds = [];
      StorageManager.saveState(appState);
      renderView('event-log');
      showToast('Selected events marked as investigated.', 'success');
    });

    const prevEventPageBtn = document.getElementById('prevEventPageBtn');
    if (prevEventPageBtn) prevEventPageBtn.addEventListener('click', () => {
      const appState = StorageManager.loadState();
      const filters = appState.filters?.eventExplorer || {};
      updateEventFilters('eventExplorer', { page: Math.max(1, Number(filters.page || 1) - 1) }, true);
      renderView('event-log');
    });
    const nextEventPageBtn = document.getElementById('nextEventPageBtn');
    if (nextEventPageBtn) nextEventPageBtn.addEventListener('click', () => {
      const appState = StorageManager.loadState();
      const filters = appState.filters?.eventExplorer || {};
      updateEventFilters('eventExplorer', { page: Number(filters.page || 1) + 1 }, true);
      renderView('event-log');
    });

    const timelineSearch = document.getElementById('timelineSearch');
    if (timelineSearch) timelineSearch.addEventListener('input', (event) => {
      updateEventFilters('timeline', { search: event.target.value });
      rerenderPreservingInput('timeline', 'timelineSearch');
    });
    [['timelineType', 'type'], ['timelineSeverity', 'severity'], ['timelineCategory', 'category'],
      ['timelineFrom', 'from'], ['timelineTo', 'to']].forEach(([id, key]) => {
      const input = document.getElementById(id);
      if (input) input.addEventListener('change', (event) => {
        updateEventFilters('timeline', { [key]: event.target.value });
        renderView('timeline');
      });
    });

    document.querySelectorAll('[data-event-open]').forEach((button) => button.addEventListener('click', () => {
      showEventDetails(button.dataset.eventOpen);
    }));
    document.querySelectorAll('[data-event-notes]').forEach((button) => button.addEventListener('click', () => {
      editEventNotes(button.dataset.eventNotes);
    }));
    document.querySelectorAll('[data-event-status]').forEach((button) => button.addEventListener('click', () => {
      saveEventField(button.dataset.eventStatus, (event) => {
        const resolved = ['resolved', 'closed'].includes(String(event.status || '').toLowerCase());
        event.status = resolved ? 'Open' : 'Resolved';
        event.analystAction = resolved ? 'Reopened locally' : 'Resolved locally';
      });
      renderView('event-log');
      showToast('Event status saved locally.', 'success');
    }));
    bindNotifications();
  }

  function init() {
    const storedTheme = localStorage.getItem('threatscope-theme') || 'dark';
    setTheme(storedTheme);
    const initial = window.location.hash.slice(1) || 'overview';
    renderView(initial || 'overview');
    document.getElementById('globalSearch').addEventListener('input', (event) => {
      const query = event.target.value;
      const appState = StorageManager.loadState();
      appState.filters.search = query;
      StorageManager.saveState(appState);
    });
    window.addEventListener('popstate', (event) => {
      const nextView = (event.state && event.state.view) || 'overview';
      renderView(nextView);
    });
  }

  window.UI = {
    init,
    setTheme,
    renderView,
    showToast,
    bindViewEvents
  };
})();
