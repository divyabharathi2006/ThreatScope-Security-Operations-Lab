# ThreatScope

ThreatScope is a browser-based SOC lab for investigating suspicious URLs, domains, IOCs, alerts, and attack scenarios. It runs entirely in the browser using HTML, CSS, and vanilla JavaScript, with localStorage persistence and no backend requirement.

## Features

- Overview dashboard with KPI cards, charts, and recent activity
- URL and domain risk inspection with heuristic scoring
- IOC analysis and watchlist management
- Security event timeline and explorer
- Simulated phishing, brute-force, malware, DNS, and exfiltration scenarios
- Threat intelligence source configuration panel
- JSON and CSV reporting exports
- Local persistence for investigations, notes, and preferences

## Local setup

1. Open the project folder in VS Code.
2. Start a local web server from the project root:

   - Python: `python -m http.server 8000`
   - Or use the VS Code Live Server extension if installed.

3. Open the app in a browser at:
   - `http://localhost:8000`

## Files

- `index.html` – application shell
- `css/style.css` – visual design
- `css/responsive.css` – responsive layout rules
- `js/*.js` – application modules for routing, validation, scoring, insight generation, and exports
- `data/demo-data.js` – simulated cybersecurity dataset for local testing

## API configuration notes

- The app does not embed any private keys.
- Direct browser-based API calls to services such as VirusTotal or Google Safe Browsing are discouraged without a secure backend proxy.
- If credentials are supplied in settings, the app will attempt a browser-safe lookup pattern, but network policies, CORS, quotas, or rate limits may prevent successful access.
- The app handles unavailable, unconfigured, or failed integrations gracefully.

## Data privacy and security

- No API secrets are stored in localStorage.
- Sensitive secrets should never be placed into browser settings or exported files.
- localStorage is browser-specific and not encrypted or server-backed.

## Testing checklist

- [ ] Dashboard loads and KPI cards display values.
- [ ] URL inspector validates malformed input and calculates risk score.
- [ ] IOC analyzer detects IOC type and supports notes, tags, and watchlist actions.
- [ ] Event explorer can filter and paginate records.
- [ ] Timeline events open the correct detail view.
- [ ] Simulation scenarios can run, reset, and score.
- [ ] JSON and CSV exports generate valid files.
- [ ] Data persists after refresh.
- [ ] Theme switching works.
- [ ] Settings can be imported/exported without breaking the schema.

## Limitations

This project is intentionally built as a frontend-only demonstration. It does not inspect real network traffic, collect live external detections without explicit configuration, or claim to be a production SOC system.
