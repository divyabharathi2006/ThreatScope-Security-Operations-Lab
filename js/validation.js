(function () {
  const HASH_RE = {
    sha256: /^[a-f0-9]{64}$/i,
    sha1: /^[a-f0-9]{40}$/i,
    md5: /^[a-f0-9]{32}$/i
  };

  function sanitizeText(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/\s+/g, ' ').trim();
  }

  function escapeHtml(value) {
    return sanitizeText(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function normalizeHost(host) {
    if (!host) return '';
    return host.replace(/^https?:\/\//i, '').replace(/^www\./i, '').replace(/\/+.*$/, '').split(':')[0].toLowerCase();
  }

  function detectIocType(value) {
    const normalized = sanitizeText(value).toLowerCase();
    if (!normalized) return 'unknown';
    if (/^https?:\/\//i.test(normalized) || /^www\./i.test(normalized) || /\.[a-z]{2,}\//i.test(normalized)) return 'URL';
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(normalized)) return 'IPv4';
    if (HASH_RE.sha256.test(normalized)) return 'SHA-256';
    if (HASH_RE.sha1.test(normalized)) return 'SHA-1';
    if (HASH_RE.md5.test(normalized)) return 'MD5';
    if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(normalized)) return 'Domain';
    if (/^[a-z0-9._-]+$/i.test(normalized) && normalized.includes('.')) return 'Domain';
    return 'unknown';
  }

  function validateUrlInput(value) {
    const cleaned = sanitizeText(value);
    if (!cleaned) {
      return { isValid: false, normalized: '', host: '', error: 'Input is empty.' };
    }

    let candidate = cleaned;
    if (!/^https?:\/\//i.test(candidate) && !candidate.startsWith('www.')) {
      candidate = 'https://' + candidate;
    }

    try {
      const parsed = new URL(candidate);
      const host = normalizeHost(parsed.host);
      return {
        isValid: Boolean(host),
        normalized: parsed.toString(),
        host,
        protocol: parsed.protocol,
        port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
        pathname: parsed.pathname,
        error: Boolean(host) ? '' : 'Unable to determine hostname.'
      };
    } catch (error) {
      return {
        isValid: false,
        normalized: cleaned,
        host: '',
        protocol: '',
        port: '',
        pathname: '',
        error: 'Malformed URL or unsupported input.'
      };
    }
  }

  function formatDateValue(value) {
    if (!value) return 'N/A';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toISOString();
  }

  function csvEscape(value) {
    const text = value == null ? '' : String(value);
    if (/[",\n]/.test(text)) {
      return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
  }

  window.Validation = {
    sanitizeText,
    escapeHtml,
    normalizeHost,
    detectIocType,
    validateUrlInput,
    formatDateValue,
    csvEscape
  };
})();
