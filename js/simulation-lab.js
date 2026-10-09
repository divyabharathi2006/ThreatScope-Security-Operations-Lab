(function () {
  const simulations = {
    phishing: {
      id: 'phishing',
      title: 'Scenario A: Phishing Investigation',
      objective: 'Identify suspicious phishing patterns in a simulated email lure.',
      description: 'An employee received a fake billing notice. Determine which indicators suggest phishing before opening the link.',
      learning: ['Check the sender domain', 'Look for urgency and deceptive branding', 'Inspect the landing page URL for suspicious patterns'],
      tasks: [
        'The sender address appears to be "billing@finance-secure.net".',
        'The email pushes the user to verify their account within 15 minutes.',
        'The URL includes redirect=, login, and securebank patterns.',
        'The sender uses a visual logo and links to a fake portal.'
      ],
      answers: ['Urgent action demand', 'Brand impersonation', 'Suspicious redirect URL', 'Fake portal or login page'],
      detail: 'Phishing attacks often create urgency and impersonation to push users to click a malicious URL.'
    },
    bruteforce: {
      id: 'bruteforce',
      title: 'Scenario B: Brute-Force Alert',
      objective: 'Recognize a suspicious authentication spike.',
      description: 'An unusual sequence of failed logins from a single source is occurring against an administrator account.',
      learning: ['High repetition over a short interval', 'Distribution of login attempts', 'Possible account takeover sequence'],
      tasks: [
        'There were 38 failed logins in 4 minutes.',
        'Attempts targeted privileged accounts after normal business hours.',
        'The source IP changed location after first credential failures.',
        'The event triggered a rate-limit response.'
      ],
      answers: ['Repeated failed logins', 'Privileged account targeting', 'Abnormal activity timing', 'Rate-limit response'],
      detail: 'Credential attacks often show a rapid burst of failures against a small set of accounts.'
    },
    malware: {
      id: 'malware',
      title: 'Scenario C: Malware IOC Investigation',
      objective: 'Review a suspicious file hash and preserve evidence.',
      description: 'A suspicious executable hash appears in endpoint telemetry. The analyst must determine whether it is a likely malware sample.',
      learning: ['Check file hash across multiple detections', 'Review spawn chain or loader behavior', 'Determine if the event is enabling malicious execution'],
      tasks: [
        'The hash is associated with an execution chain on a workstation.',
        'A child process was spawned after the file execution.',
        'The sample matches a loader pattern used in similar synthetic incidents.'
      ],
      answers: ['Loader artifact', 'Execution chain', 'Malicious process spawn'],
      detail: 'Malware analysis focuses on the behavior of the file after it is executed, not the filename alone.'
    },
    dns: {
      id: 'dns',
      title: 'Scenario D: Suspicious DNS Activity',
      objective: 'Find malicious DNS patterns in repeated lookups.',
      description: 'A workstation generated several unusual DNS lookups to random subdomains with long names.',
      learning: ['High entropy domains', 'Fast-flux or short-lived subdomains', 'Unexpected external lookups'],
      tasks: [
        'The domain has several random-looking labels.',
        'The queries returned short TTL values and no business context.',
        'The host was not part of the user’s known software inventory.'
      ],
      answers: ['Random subdomain labels', 'Short-lived DNS records', 'Unexpected software behavior'],
      detail: 'DNS abuse often uses long, randomly generated hostnames and short lifetimes to hide infrastructure.'
    },
    exfiltration: {
      id: 'exfiltration',
      title: 'Scenario E: Possible Data Exfiltration',
      objective: 'Identify unusual data transfer behavior.',
      description: 'Outbound network activity suggests a large upload to an external host during off-hours.',
      learning: ['Assess volume and timing', 'Check destination reputation', 'Compare with baseline business patterns'],
      tasks: [
        'Large compressed archive files left the network after normal working hours.',
        'The destination IP is not a known approved hosting endpoint.',
        'The pattern matches a potential staging process before data theft.'
      ],
      answers: ['Off-hours transfer', 'Unapproved external host', 'Archive staging pattern'],
      detail: 'Exfiltration often occurs during off-hours and uses encrypted or compressed archives that stand out from baseline traffic.'
    }
  };

  function getScenarioCatalog() {
    return Object.values(simulations);
  }

  function normalizeAnswer(value) {
    return String(value || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ' ')
      .trim();
  }

  function computeScenarioScore(answers, key) {
    const scenario = simulations[key];
    if (!scenario) return { score: 0, total: 0, correct: [] };

    const normalizedSelected = (answers || []).map(normalizeAnswer);
    const total = scenario.answers.length;
    const correct = scenario.answers.filter((answer) => {
      const normalizedAnswer = normalizeAnswer(answer);
      return normalizedSelected.some((selected) => {
        if (!selected || !normalizedAnswer) return false;
        return selected === normalizedAnswer || selected.includes(normalizedAnswer) || normalizedAnswer.includes(selected);
      });
    });
    const score = total ? Math.round((correct.length / total) * 100) : 0;
    return { score, total, correct };
  }

  window.SimulationLab = {
    getScenarioCatalog,
    computeScenarioScore,
    scenarios: simulations
  };
})();
