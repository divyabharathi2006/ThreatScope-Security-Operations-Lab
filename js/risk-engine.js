(function () {
  function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
  }

  function riskVerdictFromScore(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High Risk';
    if (score >= 40) return 'Suspicious';
    if (score >= 20) return 'Guarded';
    if (score > 0) return 'Low Risk';
    return 'Unknown';
  }

  function scoreClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'suspicious';
    if (score >= 20) return 'guarded';
    if (score > 0) return 'low';
    return 'unknown';
  }

  function calculateRiskScore(input, findings = [], sources = []) {
    const cleaned = typeof input === 'string' ? input.trim() : '';
    const factors = [];
    let score = 0;

    if (!cleaned) {
      factors.push({ label: 'Empty or invalid input', points: 25 });
      score += 25;
      return {
        score: 25,
        verdict: 'Unknown',
        className: 'unknown',
        factors,
        evidence: ['No indicator value was supplied.']
      };
    }

    const shouldValidateUrl = /^https?:\/\//i.test(cleaned) || cleaned.includes('.') || /\//.test(cleaned);
    if (shouldValidateUrl) {
      try {
        const parsed = new URL(/^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`);
        const host = parsed.hostname.toLowerCase();
        const path = `${parsed.pathname} ${parsed.search}`.toLowerCase();

        if (/^\d+(?:\.\d+){3}$/.test(host)) {
          factors.push({ label: 'IP address used as hostname', points: 22 });
          score += 22;
        }

        if (parsed.protocol === 'http:' && !host.includes('localhost')) {
          factors.push({ label: 'Insecure HTTP connection', points: 16 });
          score += 16;
        }

        if (parsed.port && !['80', '443'].includes(parsed.port)) {
          factors.push({ label: 'Unusual port detected', points: 12 });
          score += 12;
        }

        if (/(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly|rebrand\.ly)/i.test(host)) {
          factors.push({ label: 'URL shortener service', points: 18 });
          score += 18;
        }

        if (/(?:login|verify|secure|update|confirm|account|billing|pay|reset|signin|password)/i.test(host) || /(?:login|verify|secure|update|confirm|billing|payment|signin|password)/i.test(path)) {
          factors.push({ label: 'Misleading hostname patterns', points: 10 });
          score += 10;
        }

        if (/(?:redirect=|next=|return=|destination=|url=|target=)/i.test(cleaned) || /(?:redirect|next|return|destination|target).*?(?:login|verify|secure|account)/i.test(path)) {
          factors.push({ label: 'Redirection parameter detected', points: 12 });
          score += 12;
        }

        const encodedMatches = cleaned.match(/%[0-9a-f]{2}|%2f|%3d|%3a/gi);
        if (encodedMatches && encodedMatches.length >= 2) {
          factors.push({ label: 'Suspicious URL encoding or redirect obfuscation', points: 14 });
          score += 14;
        }

        const subdomainCount = host.split('.').length;
        if (subdomainCount >= 5) {
          factors.push({ label: 'Excessive subdomains', points: 10 });
          score += 10;
        }

        if (/(?:\.tk|\.ml|\.ga|\.cf|\.top|\.xyz|\.loan|\.bid|\.club|\.icu)$/i.test(host) || /(?:secure|login|update|verify|confirm|account|bank|cloud|drive|support|service).*\.(?:tk|ml|ga|cf|top|xyz|loan|bid|club|icu)/i.test(host)) {
          factors.push({ label: 'Potentially deceptive domain pattern', points: 20 });
          score += 20;
        }
      } catch (error) {
        factors.push({ label: 'Malformed URL or unsupported input', points: 28 });
        score += 28;
      }
    }

    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(cleaned)) {
      factors.push({ label: 'IPv4 indicator without a trusted context', points: 16 });
      score += 16;
    }

    if (Array.isArray(findings)) {
      findings.forEach((finding) => {
        const points = Number(finding.points || 0);
        if (points > 0 && !factors.some((factor) => factor.label === finding.label)) {
          factors.push({ label: finding.label, points });
          score += points;
        }
      });
    }

    if (Array.isArray(sources)) {
      sources.forEach((source) => {
        if (source && source.status === 'malicious') {
          factors.push({ label: `${source.name} reputation match`, points: 25 });
          score += 25;
        }
      });
    }

    if (!factors.length && shouldValidateUrl) {
      factors.push({ label: 'No obvious malicious indicators detected', points: 6 });
      score = 6;
    }

    const uniqueFactors = [];
    const seen = new Set();
    factors.forEach((entry) => {
      const key = entry.label.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        uniqueFactors.push(entry);
      }
    });

    const finalScore = clamp(uniqueFactors.reduce((total, factor) => total + factor.points, 0), 0, 100);
    const verdict = finalScore === 0 ? 'Unknown' : riskVerdictFromScore(finalScore);
    return {
      score: finalScore,
      verdict,
      className: scoreClass(finalScore),
      factors: uniqueFactors,
      evidence: uniqueFactors.map((factor) => `${factor.label} (+${factor.points})`)
    };
  }

  window.RiskEngine = {
    calculateRiskScore,
    riskVerdictFromScore,
    scoreClass
  };
})();
