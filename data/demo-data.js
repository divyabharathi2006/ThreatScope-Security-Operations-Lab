window.demoData = {
  schemaVersion: 1,
  theme: 'dark',
  filters: {
    severity: 'all',
    dateRange: '7d',
    search: ''
  },
  settings: {
    analystLabel: 'Analyst-01',
    threatSources: {
      virustotal: { enabled: false, apiKey: '', lastLookup: 'Unavailable', lastError: 'API key not configured', quota: 'Not configured' },
      google: { enabled: false, apiKey: '', lastLookup: 'Unavailable', lastError: 'API key not configured', quota: 'Not configured' },
      abuseipdb: { enabled: false, apiKey: '', lastLookup: 'Unavailable', lastError: 'API key not configured', quota: 'Not configured' }
    }
  },
  dashboard: {
    totalInvestigated: 184,
    highRiskIndicators: 19,
    criticalIndicators: 4,
    openAlerts: 23,
    totalEvents: 428,
    recentActivity: [
      { label: 'URL inspected', value: 'securebank-login.example', time: '5 min ago' },
      { label: 'IOC triaged', value: 'sha256:b15d...', time: '8 min ago' },
      { label: 'Attack event reviewed', value: 'brute-force cluster', time: '12 min ago' }
    ],
    severityDistribution: [
      { label: 'Low', value: 28 },
      { label: 'Medium', value: 42 },
      { label: 'High', value: 19 },
      { label: 'Critical', value: 7 }
    ],
    categoryDistribution: [
      { label: 'Phishing', value: 26 },
      { label: 'Malware', value: 22 },
      { label: 'DNS Abuse', value: 18 },
      { label: 'Credential Abuse', value: 21 },
      { label: 'Exfiltration', value: 13 }
    ]
  },
  suspiciousUrls: [
    { url: 'http://104.16.71.14/login?redirect=https://secure.example', risk: 'High', source: 'Synthetic', status: 'Investigating' },
    { url: 'https://tinyurl.com/y7kq4m', risk: 'Critical', source: 'Threat feed', status:'Flagged' },
    { url: 'https://login-verify.securebank.net/portal', risk: 'Suspicious', source: 'Local', status:'Reviewed' },
    { url: 'https://cloud-storage-update.example', risk: 'Medium', source: 'Synthetic', status:'Observed' }
  ],
  events: [
    {
      id: 'EVT-1001',
      timestamp: '2026-10-09T08:33:00Z',
      category: 'Phishing',
      severity: 'High',
      ioc: 'https://securebank-login.example',
      iocType: 'URL',
      description: 'Credential harvesting landing page distributed through a spoofed email campaign.',
      status: 'Open',
      sourceType: 'simulated',
      analystAction: 'Queued for review'
    },
    {
      id: 'EVT-1002',
      timestamp: '2026-10-09T09:10:00Z',
      category: 'Malware',
      severity: 'Critical',
      ioc: 'sha256:9ab5d2c31f...',
      iocType: 'SHA-256',
      description: 'Suspicious loader hash matched a known malware indicator in synthetic telemetry.',
      status: 'Investigating',
      sourceType: 'simulated',
      analystAction: 'IOC enriched'
    },
    {
      id: 'EVT-1003',
      timestamp: '2026-10-09T09:44:00Z',
      category: 'Credential Abuse',
      severity: 'Medium',
      ioc: '203.0.113.48',
      iocType: 'IPv4',
      description: 'Repeated failed authentication attempts against privileged accounts.',
      status: 'Contained',
      sourceType: 'local',
      analystAction: 'Rate-limit applied'
    },
    {
      id: 'EVT-1004',
      timestamp: '2026-10-09T10:32:00Z',
      category: 'DNS Abuse',
      severity: 'High',
      ioc: 'suspicious-domain.example',
      iocType: 'Domain',
      description: 'Short-lived DNS lookups and high entropy subdomains suggest malicious infrastructure.',
      status: 'Open',
      sourceType: 'external API',
      analystAction: 'Blocked in egress rule'
    },
    {
      id: 'EVT-1005',
      timestamp: '2026-10-09T11:07:00Z',
      category: 'Exfiltration',
      severity: 'Critical',
      ioc: '10.45.18.24',
      iocType: 'IPv4',
      description: 'Outbound transfer spike aligned with archive staging of sensitive documents.',
      status: 'Escalated',
      sourceType: 'simulated',
      analystAction: 'Validation requested'
    }
  ],
  iocs: [
    {
      id: 'IOC-1001',
      type: 'URL',
      value: 'https://securebank-login.example/verify?id=1234',
      classification: 'Suspicious',
      riskScore: 72,
      createdAt: '2026-10-09T07:30:00Z',
      lastChecked: '2026-10-09T09:20:00Z',
      notes: 'Phishing lure replicates login flow.',
      tags: ['phishing', 'credential-harvest'],
      watchlist: true,
      history: ['Investigation opened', 'Heuristic score assigned', 'Potential phishing indicators identified'],
      related: ['IOC-1002', 'EVT-1001']
    },
    {
      id: 'IOC-1002',
      type: 'Domain',
      value: 'securebank-login.example',
      classification: 'Malicious',
      riskScore: 88,
      createdAt: '2026-10-09T07:32:00Z',
      lastChecked: '2026-10-09T09:22:00Z',
      notes: 'Impersonates legitimate banking domain.',
      tags: ['spoofed', 'fraud'],
      watchlist: true,
      history: ['Domain normalized', 'Brand impersonation flagged'],
      related: ['IOC-1001']
    },
    {
      id: 'IOC-1003',
      type: 'SHA-256',
      value: '9ab5d2c31f2b8b39d6ba42b1fe9a6d5a4bf0f0061e5efc9c1acdba53f570fbc',
      classification: 'Unknown',
      riskScore: 61,
      createdAt: '2026-10-09T05:00:00Z',
      lastChecked: '2026-10-09T09:52:00Z',
      notes: 'Loader hash in malware simulation scenario.',
      tags: ['malware', 'loader'],
      watchlist: false,
      history: ['Synthetic event observed', 'IOC linked to malicious execution path'],
      related: ['EVT-1002']
    }
  ],
  watchlist: ['IOC-1001', 'IOC-1002'],
  intelligenceSources: [
    {
      name: 'VirusTotal',
      status: 'Not configured',
      lastSuccessfulLookup: 'Unavailable',
      lastError: 'No API key configured',
      quota: 'Not configured',
      resultCount: 0,
      documentation: 'https://developers.virustotal.com/'
    },
    {
      name: 'Google Safe Browsing',
      status: 'Not configured',
      lastSuccessfulLookup: 'Unavailable',
      lastError: 'No API key configured',
      quota: 'Not configured',
      resultCount: 0,
      documentation: 'https://developers.google.com/safe-browsing'
    },
    {
      name: 'AbuseIPDB',
      status: 'Not configured',
      lastSuccessfulLookup: 'Unavailable',
      lastError: 'No API key configured',
      quota: 'Not configured',
      resultCount: 0,
      documentation: 'https://www.abuseipdb.com/'
    }
  ],
  scenarioProgress: {
    'phishing': { complete: false, score: 0 },
    'bruteforce': { complete: false, score: 0 },
    'malware': { complete: false, score: 0 },
    'dns': { complete: false, score: 0 },
    'exfiltration': { complete: false, score: 0 }
  },
  investigations: [
    {
      id: 'INV-1001',
      title: 'Suspicious banking lure',
      type: 'URL',
      value: 'https://securebank-login.example/verify?id=1234',
      riskScore: 72,
      verdict: 'High Risk',
      createdAt: '2026-10-09T07:35:00Z'
    }
  ]
};
