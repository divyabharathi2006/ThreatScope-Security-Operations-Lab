(function () {
  const catalog = {
    virustotal: {
      name: 'VirusTotal',
      docs: 'https://developers.virustotal.com/',
      endpoint: 'https://www.virustotal.com/api/v3/search?query='
    },
    google: {
      name: 'Google Safe Browsing',
      docs: 'https://developers.google.com/safe-browsing',
      endpoint: 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='
    },
    abuseipdb: {
      name: 'AbuseIPDB',
      docs: 'https://www.abuseipdb.com/',
      endpoint: 'https://api.abuseipdb.com/api/v2/check'
    }
  };

  function getSourceCatalog() {
    return Object.entries(catalog).map(([key, value]) => ({ key, ...value }));
  }

  async function lookupSource(sourceKey, value, settings = {}) {
    const config = settings[sourceKey] || {};
    const definition = catalog[sourceKey];
    if (!definition) {
      return { status: 'unavailable', name: sourceKey, source: sourceKey, result: 'Unsupported source.' };
    }

    if (!config.enabled || !config.apiKey) {
      return {
        status: 'not_configured',
        source: definition.name,
        name: definition.name,
        timestamp: new Date().toISOString(),
        result: 'Not configured',
        message: 'No secret key is configured. Direct browser integration is unsafe and should use a backend proxy in production.'
      };
    }

    return {
      status: 'unavailable',
      source: definition.name,
      name: definition.name,
      timestamp: new Date().toISOString(),
      result: 'Unavailable',
      message: 'No live provider integration is implemented. Credentials in browser storage are not used or transmitted.'
    };
  }

  async function fetchSourceResults(value, settings = {}) {
    const keys = Object.keys(catalog);
    const promises = keys.map((key) => lookupSource(key, value, settings));
    return Promise.all(promises);
  }

  window.ThreatSources = {
    catalog,
    getSourceCatalog,
    lookupSource,
    fetchSourceResults
  };
})();
