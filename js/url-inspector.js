(function () {
  async function analyzeUrlInput(value, settings = {}) {
    const validation = Validation.validateUrlInput(value);
    const userInput = Validation.sanitizeText(value);
    const hostname = validation.host || Validation.normalizeHost(userInput);
    const findings = [];

    if (!validation.isValid) {
      return {
        input: userInput,
        normalized: validation.normalized,
        hostname,
        risk: { score: 30, verdict: 'Unknown', className: 'unknown', factors: [{ label: 'Malformed input', points: 30 }], evidence: ['Malformed input.'] },
        sourceResults: [],
        status: 'invalid',
        messages: [validation.error]
      };
    }

    if (hostname && /^\d+(?:\.\d+){3}$/.test(hostname)) {
      findings.push({ label: 'IP address used as hostname', points: 20 });
    }

    if (/^(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd)/i.test(hostname)) {
      findings.push({ label: 'URL shortener service', points: 18 });
    }

    const port = validation.port;
    if (port && !['80', '443'].includes(String(port))) {
      findings.push({ label: 'Unusual port detected', points: 12 });
    }

    if (/%[0-9a-f]{2}/i.test(userInput) || /%2f|%3d|%3a/i.test(userInput)) {
      findings.push({ label: 'Suspicious URL encoding or redirect obfuscation', points: 14 });
    }

    if (/(?:redirect=|next=|return=|url=|destination=|target=)/i.test(userInput)) {
      findings.push({ label: 'Redirection parameter detected', points: 12 });
    }

    if (hostname && hostname.split('.').length > 4) {
      findings.push({ label: 'Excessive subdomains', points: 10 });
    }

    if (/(?:login|verify|secure|update|confirm|account|billing)/i.test(hostname)) {
      findings.push({ label: 'Misleading hostname patterns', points: 10 });
    }

    const sourceResults = await ThreatSources.fetchSourceResults(userInput, settings);
    const risk = RiskEngine.calculateRiskScore(userInput, findings, sourceResults.filter((source) => source.status === 'malicious'));

    return {
      input: userInput,
      normalized: validation.normalized,
      hostname,
      risk,
      sourceResults,
      status: 'ok',
      messages: risk.evidence
    };
  }

  window.UrlInspector = {
    analyzeUrlInput
  };
})();
