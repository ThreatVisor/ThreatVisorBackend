# ThreatVisorBackend – Developer Overview

## Purpose

ThreatVisorBackend provides a unified microservice architecture for security scanning, vulnerability management, and AI-driven analysis. Its goal is to orchestrate multiple security scanners (such as OWASP ZAP, reNgine, Wapiti, Nikto, w3af), correlate findings, assess risk, and produce actionable insights enriched by AI models. It is intended for use in continuous security assessment pipelines, enterprise environments, and compliance-driven projects.

---

## Technology Stack

- **JavaScript (Node.js/Express)**: Microservice core, API, scanner orchestration (87.5% of codebase)
- **Shell scripts**: Automation, environment setup, Docker build steps (9.1%)
- **Python**: Used by some scanners and integration code (3.2%)
- **Dockerfile**: Containerization, custom scanner builds (0.2%)
- **External Services**: OpenAI (for AI-driven analysis), Supabase (for cloud storage/query support)

---

## Architecture

### Overview

- **Express.js microservice**: Listens on configurable port (default: 4000), exposes REST endpoints for scanning, status and summary retrieval.
- **Multi-scanner orchestration**: Supports launching, controlling, and aggregating results from multiple security-scanner Docker containers.
- **Directory structure management**: Automatic creation/management of `reports` and `scripts` directories for output and execution.
- **AI Integration**: Uses OpenAI API for vulnerability analysis, impact assessment, remediation advice, and compliance notes.
- **Process management**: Configurable via `ecosystem.config.cjs` (PM2) and shell scripts for start/stop/status/health.

### Key Directories

- `/reports`: Stores scan output files
- `/scripts`: Contains utility and environment setup scripts
- `/scanner-images`: Build workspace for Docker images

---

## Supported Scanners

Defined in the `SCANNERS` JavaScript object. Example scanners:
- **OWASP ZAP**: Dynamic application scanner
- **reNgine**: Custom build of reNgine via Docker
- **Wapiti**: Python-based web application vulnerability scanner
- **Nikto**: Dockerized vulnerability scanner for web servers
- **w3af**: Python security assessment tool

New scanners may be integrated in future versions.

### Example Scanner Configuration Snippet

```js
const SCANNERS = {
  zap: {
    name: 'OWASP ZAP',
    containerName: 'zaproxy/zap-stable',
    reportFile: 'zap_report.json',
    reportFormat: 'json',
    containerWorkDir: '/zap/wrk'
  },
  rengine: {
    name: 'reNgine',
    containerName: 'custom-rengine',
    reportFile: 'rengine_report.json',
    reportFormat: 'json',
    containerWorkDir: '/app/reports'
  },
  // ... More scanners
};
```

---

## Setup & Installation

### Automated Local Reproduction

See `azure_scanner_repro.sh` for step-by-step repro and automation:
- Installs required system packages & Docker images
- Clones/builds reNgine, creates helper scripts for w3af, etc.
- Produces working installation and verification logs in `~/scanner-reports/azure_scanner_status.md`

### Docker-Based Install

Example Dockerfile for building custom Wapiti image:

```dockerfile
FROM python:3.9-slim
RUN apt-get update && apt-get install -y git libxml2-dev libxslt1-dev zlib1g-dev python3-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt && python setup.py install
ENTRYPOINT ["wapiti"]
```

### Service Control

Use `manage-service.sh` to:
- Start, stop, restart, check status, view health and logs of the microservice
- Relies on PM2 and configuration in `ecosystem.config.cjs`

---

## API Overview

### Main Endpoints

- `/scan` (POST): Initiate a new scan (details depend on payload)
- `/scan/:scanId/ai-summary` (GET): Get OpenAI-powered summary for a specific scan
- `/health` (GET): Basic health check
- `/debug` (GET): Returns config, capabilities, directory existence, etc.

### Scan Output

- All scan results are consolidated and validated.
- Output contains raw scanner results plus AI analysis, risk ratings, business & technical impacts, remediation steps, attack scenarios, compliance notes, and reference links.

---

## Processing Logic

#### Vulnerability Deduplication & Correlation
- Identifies unique vulnerabilities across scanners
- Performs intelligent deduplication and correlates evidence by endpoint, vector, and impact

#### AI Analysis & Content Generation
- *Functions*: Generate technical impact, business impact, remediation steps, attack scenarios, compliance impact
- *Sample*: Output preview includes title, description, analysis, impact, remediation, scenarios, and references

#### Risk Assessment

```js
function assessOverallRisk(severityCounts) {
    if (severityCounts.critical > 0) return 'Critical - Immediate attention required';
    if (severityCounts.high > 2) return 'High - Urgent remediation needed';
    if (severityCounts.medium > 5) return 'Medium - Regular security improvements needed';
    return 'Low - Maintain current security practices';
}
```

#### Compliance Notes
- Maps vulnerabilities to OWASP Top 10, PCI DSS, GDPR, SOX, HIPAA, etc.
- Highlights required documentation, audit trail, and reporting in case of severe findings

---

## Example Remediation Steps

```js
// For Content Security Policy vulnerabilities:
[
    "Deploy CSP in report-only mode using 'Content-Security-Policy-Report-Only' header to collect violation reports",
    "Analyze CSP violation reports for 1-2 weeks, refine policy to allow legitimate resources while blocking unsafe practices",
    "Switch to enforcing CSP policy using 'Content-Security-Policy' header after thorough testing and violation analysis"
]
```

---

## Prevention Practices

```js
[
  "Implement comprehensive security scanning using multiple tools",
  "Establish mandatory security reviews for all changes",
  "Deploy automated security testing in CI/CD pipeline",
  "Conduct regular security training for teams"
]
```

---

## Attack Scenarios

```js
[
  "CDN compromise attack: Attacker gains access to external CDN hosting JavaScript libraries → Injects malicious code → Authentication tokens and session data stolen.",
  "Supply chain attack: Malicious modification of trusted external resources leads to sensitive data exfiltration."
]
```

---

## Compliance Assessment Example

```js
return `Compliance impact assessment indicates this ${vuln.severity} vulnerability may result in violations ... Regulatory reporting requirements may be triggered if this vulnerability leads to data exposure...`
```

---

## Logging & Monitoring

- Extensive logging throughout scanning and analysis steps
- Logging includes scanner details, risk scores, output validation, and process status
- All logs accessible via PM2 and service management scripts

---

## Environment Configuration

- Main config in `ecosystem.config.cjs` (example variables: `NODE_ENV`, `PORT`, `OPENAI_API_KEY`, `OPENAI_MODEL`)
- API keys and model selection for OpenAI are supported via environment
- File and directory permissions managed by service

---

## Extending & Customizing

- To add a new scanner, extend the `SCANNERS` config, provide Docker image/build/prerequisites
- New analysis and reporting functions can be added modularly in JS core
- All logic is meant to be modular for easy integration with new tools or reporting platforms

---

## References

- See individual scanner documentation for usage specifics
- Use included shell scripts and Dockerfiles for reproducible environment setup
- Output markdown reports found in `~/scanner-reports/azure_scanner_status.md` or `/reports` directory

---

## Getting Started

1. **Clone the repository**
2. **Run setup scripts or Docker builds for required scanners**
3. **Configure the environment via .env, ecosystem.config.cjs, or direct shell variables**
4. **Start the microservice using `manage-service.sh start` or PM2**
5. **Use the API to run and review security scans; reference logs and reports for deep analysis**

---

## Contact & Support

For further details, consult source code (`index.mjs`, shell scripts) and reach out to the ThreatVisor team if documentation gaps are encountered.
