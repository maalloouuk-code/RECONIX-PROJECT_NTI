# RECONIX — Security Control System

NTI NEXUS is a web-based security assessment toolkit that performs automated, unauthenticated, surface-level security analysis of a target HTTP/HTTPS website.

The project combines multiple security and reconnaissance capabilities into one unified assessment workflow:

- **Security Behavior Profiling Engine**
- **Combined HTTP Security Scanner**
- **OSINT Lookup Layer**
- **User Discovery**
- **robots.txt Analyzer**

The backend exposes a Flask API, while the included frontend provides a security-control-system style dashboard for running scans, reviewing findings, comparing scan history, and viewing the generated assessment.

---

## Project Structure

```text
Final Project/
├── app.py
├── master_link.py
├── security_behavior_engine.py
├── http_scanner.py
├── osint.py
├── osint_api.py
├── user_discovery.py
├── robots_analyzer.py
├── index.html
├── script.js
└── style.css
```

### Backend Components

| File | Responsibility |
|---|---|
| `app.py` | Flask application entry point and API registration |
| `master_link.py` | Integrates the three security analysis modules and produces the unified assessment |
| `security_behavior_engine.py` | Behavioral security profiling, anomaly detection, correlation analysis, scoring, and recommendations |
| `http_scanner.py` | HTTP response, security-header, cookie/configuration, HTTP-method, and redirect analysis |
| `osint.py` / `osint_api.py` | Public-information lookup and OSINT enrichment for the target assessment |
| `user_discovery.py` | User-related discovery and exposed-indicator analysis |
| `robots_analyzer.py` | `robots.txt` retrieval, parsing, interesting-path detection, and report generation |

### Frontend Components

| File | Responsibility |
|---|---|
| `index.html` | NTI NEXUS dashboard interface |
| `script.js` | Frontend state management, API communication, scan rendering, findings, history, and dashboard updates |
| `style.css` | Dashboard layout, responsive styling, visual effects, colors, typography, and UI components |

---

## Core Architecture

```text
                         ┌─────────────────────┐
                         │      Frontend       │
                         │   NTI NEXUS UI      │
                         └──────────┬──────────┘
                                    │
                                    │ HTTP/JSON
                                    ▼
                         ┌─────────────────────┐
                         │      Flask API      │
                         │       app.py        │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   master_link.py    │
                         │  Master Scan Layer  │
                         └──────┬──────┬───────┘
                                │      │
                 ┌──────────────┘      └──────────────┐
                 ▼                                     ▼
     ┌────────────────────────┐           ┌────────────────────────┐
     │ Security Behavior      │           │ Combined HTTP Scanner  │
     │ Profiling Engine       │           │                        │
     └────────────┬───────────┘           └────────────┬───────────┘
                  │                                    │
                  └────────────────┬───────────────────┘
                                   │
                                   ▼
                         ┌─────────────────────┐
                         │  robots.txt        │
                         │     Analyzer        │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Unified Assessment  │
                         │ Score + Findings    │
                         └─────────────────────┘
```

---

## Security Behavior Profiling Engine

The behavioral engine analyzes the target across six security domains:

1. **Transport Security**
2. **Redirect Behavior**
3. **Cookie Behavior**
4. **CORS Behavior**
5. **HTTP Method Behavior**
6. **Information Disclosure**

It builds structured security profiles, observations, anomalies, correlated risks, domain scores, an overall score, and recommendations.

### Transport Security

The engine compares HTTP and HTTPS behavior and evaluates:

- HTTP accessibility
- HTTPS accessibility
- HTTPS enforcement
- HSTS presence
- cleartext exposure
- transport consistency

### Redirect Behavior

The redirect profiler evaluates:

- redirect chains
- number of hops
- protocol transitions
- HTTP → HTTPS upgrades
- HTTPS → HTTP downgrades
- same-domain versus cross-domain behavior
- excessive redirect chains
- circular redirect behavior
- final transport protocol

### Cookie Behavior

The cookie analyzer evaluates observed cookies and their security properties, including:

- `Secure`
- `HttpOnly`
- `SameSite`
- sensitive/session-cookie identification
- persistent cookies
- CSRF-token patterns
- cookie consistency
- security prefixes

Sensitive cookie names are identified using configured patterns such as:

```text
session
sess
jwt
token
auth
sid
phpsessid
jsessionid
asp.net_sessionid
remember
account
user
logged_in
sso
```

### CORS Behavior

The engine analyzes CORS-related behavior including:

- `Access-Control-Allow-Origin`
- origin reflection
- `null` origin trust
- `Access-Control-Allow-Credentials`
- cross-origin security boundaries

A reflected or trusted origin combined with credentialed CORS can generate a high-severity correlated risk.

### HTTP Method Behavior

The behavioral engine probes HTTP method behavior, including:

- `OPTIONS`
- `TRACE`

The engine can identify an active TRACE method and classify it as a high-risk behavior when the response confirms the method is enabled.

### Information Disclosure

The engine checks response information that can expose infrastructure details, including:

- software/version disclosure
- server information
- debug-related headers
- detailed version exposure

---

## Behavioral Anomaly Detection

The engine detects behavioral anomalies when independent observations indicate an inconsistent or risky security posture.

Examples implemented in the project include:

- Inconsistent HTTPS Enforcement Anomaly
- HTTPS Enforced Without HSTS Policy Memory
- Protocol Downgrade Anomaly in Redirect Routing
- Cyclic Routing Anomaly
- Cookie Security Flag Inconsistency
- Session State Issued Without Cryptographic Binding
- Cross-Origin Security Boundary Collapse
- Legacy Debugging Verb Exposed in Active Profile
- Verbose Infrastructure Fingerprinting & Debug Leak

Anomalies contain structured evidence, severity, classification, affected domains, and descriptive context.

---

## Correlated Risk Analysis

The project does not rely only on isolated findings.

`CorrelationEngine` combines evidence from multiple security domains to identify compound risks.

Implemented correlation logic includes scenarios such as:

### Transport & Session Security Breakdown

Combines:

- cleartext HTTP accessibility
- lack of mandatory HTTPS enforcement
- sensitive cookies without `Secure`

### Permissive Origin Credential Exposure

Combines:

- reflected or trusted `null` CORS origin
- credentialed cross-origin requests

The correlation engine assigns severity, confidence, trigger observations, evidence, impact, and remediation guidance to correlated risks.

---

## Security Behavior Scoring

The behavioral engine uses six weighted domains:

| Domain | Weight |
|---|---:|
| Transport Security | 22% |
| Redirect Behavior | 16% |
| Cookie Behavior | 20% |
| CORS Behavior | 16% |
| HTTP Method Behavior | 14% |
| Information Disclosure | 12% |

The base score is calculated as:

```text
Base Score = Σ(domain score × domain weight)
```

A controlled contextual penalty is then applied for anomalies and correlated risks.

The implementation intentionally limits the compound-risk penalty so that the same underlying weakness is not excessively counted multiple times.

### Risk Classification

| Score | Risk Level |
|---:|---|
| 90–100 | LOW |
| 75–89 | LOW/MEDIUM |
| 50–74 | MEDIUM |
| 25–49 | HIGH |
| 0–24 | CRITICAL |

The engine also classifies behavioral consistency as:

- `HIGH`
- `MODERATE`
- `LOW`
- `CRITICAL INCONSISTENCY`

---

## Combined HTTP Security Scanner

`http_scanner.py` provides a separate transparent scoring layer.

### Base HTTP Scan

The scanner records:

- requested URL
- final URL
- HTTP status code
- response time
- response headers
- cookies
- redirect status
- redirect count
- redirect chain

### Security Headers

The scanner checks:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Missing headers are reported as security findings according to their configured default severity.

### Cookies & Configuration

The scanner checks observed cookies for:

- `Secure`
- `HttpOnly`
- `SameSite`

It also reports informational server-header disclosure such as:

- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-AspNetMvc-Version`

### HTTP Methods

The scanner sends an `OPTIONS` request and evaluates the `Allow` header.

The following methods are considered risky by the scanner:

```text
PUT
DELETE
TRACE
CONNECT
```

Advertised risky methods are classified as **Suspected**, not automatically confirmed vulnerabilities.

### Redirect Security

The scanner records the redirect chain and checks whether an insecure HTTP redirect path is observed.

---

## Combined Scanner Scoring

The HTTP scanner starts from a score of `100`.

Only findings that satisfy both conditions affect the score:

```text
finding_type == "Security Finding"
confidence == "Confirmed"
```

Configured penalties are:

| Severity | Penalty |
|---|---:|
| High | 25 points |
| Medium | 15 points |
| Low | 5 points |
| Info | 0 points |

Suspected findings, unverified findings, and informational findings do not reduce the scanner score.

---

## Reconnaissance & Intelligence Layers

The platform extends its technical security checks with reconnaissance capabilities that provide additional context before and alongside the security assessment.

### OSINT Lookup Layer

The OSINT layer gathers relevant publicly available information to enrich the target profile and support the assessment with additional context. It is intended to complement technical findings rather than replace direct security validation.

### User Discovery

The user-discovery component identifies potential user-related information and exposed indicators as part of the reconnaissance workflow. Discovered information is treated as reconnaissance evidence and should be validated before being considered a confirmed security finding.

---

## robots.txt Analyzer

`robots_analyzer.py` retrieves and parses:

```text
/robots.txt
```

It extracts:

- User-Agents
- Disallowed paths
- Allowed paths
- Sitemaps

It also detects potentially interesting disallowed paths using configured keywords.

Examples include:

```text
admin
administrator
backup
backups
api
private
login
dashboard
config
uploads
upload
test
dev
debug
```

Detected paths are categorized and assigned a severity based on the matching keyword.

The analyzer can generate both JSON and HTML reports when used directly.

---

## Unified Master Scan

`master_link.py` is the integration layer.

A complete master scan runs:

```text
1. Security Behavior Profiling Engine
2. Combined HTTP Scanner
3. robots.txt Analyzer
```

The results are returned together with:

- target
- scan timestamp
- execution time
- scan failure state
- failure reason when applicable
- unified assessment
- component scores
- complete module results

---

## Unified Score

The master score combines the behavioral engine and HTTP scanner.

When both components succeed:

```text
Unified Score
= (Behavior Engine Score × 0.60)
+ (Combined Scanner Score × 0.40)
```

The score is then reduced by a robots.txt penalty.

The penalty is based on high-risk interesting paths:

```text
3 points per high-risk path
Maximum robots.txt penalty: 10 points
```

The final score is clamped to a minimum of `0`.

### Unified Rating

| Score | Rating |
|---:|---|
| 90–100 | Excellent |
| 75–89 | Good |
| 50–74 | Fair |
| 25–49 | Poor |
| 0–24 | Critical |

---

## API

The Flask backend exposes the master API under:

```text
/api/v1/master
```

### Health Check

```http
GET /api/v1/master/health
```

Example response:

```json
{
  "module": "Master Security Toolkit (Behavior Engine + Combined Scanner + Robots Analyzer)",
  "status": "operational"
}
```

### Master Scan

```http
POST /api/v1/master/scan
Content-Type: application/json
```

Request body:

```json
{
  "url": "https://example.com"
}
```

An optional timeout can also be supplied:

```json
{
  "url": "https://example.com",
  "timeout": 10
}
```

The endpoint returns the unified master result containing the three analysis modules and the unified assessment.

### Root Endpoint

```http
GET /
```

Returns basic backend service information and the available master endpoints.

---

## Direct Security Behavior API

`security_behavior_engine.py` also contains a Flask Blueprint factory for direct integration:

```text
create_security_behavior_blueprint()
```

The blueprint provides:

```http
POST /profile
POST /profile/mock
GET  /health
```

When mounted with:

```python
app.register_blueprint(
    create_security_behavior_blueprint(),
    url_prefix="/api/v1/behavior"
)
```

the resulting endpoints are:

```text
POST /api/v1/behavior/profile
POST /api/v1/behavior/profile/mock
GET  /api/v1/behavior/health
```

The mock profile endpoint is designed for pre-recorded scenarios and performs no network requests.

---

## Frontend Dashboard

The included frontend is a static HTML/CSS/JavaScript interface named:

```text
NTI NEXUS — Security Control System
```

The interface contains the following application sections:

- Dashboard
- Scan
- Findings
- History
- Report

The dashboard consumes the master API endpoints:

```text
GET  /api/v1/master/health
POST /api/v1/master/scan
```

The frontend displays data derived from the actual backend scan response rather than generating random scan statistics.

The interface includes:

- target URL input
- scan controls
- API base configuration
- connection/health status
- scan progress
- unified security score
- severity counters
- asset and finding statistics
- risk assessment
- module status
- threat information
- findings table
- finding detail modal
- scan history
- comparison information
- system clock and uptime
- response/latency information
- visual security dashboard components

---

## Requirements

The backend requires Python packages used by the project:

```text
Flask
flask-cors
requests
colorama
```

Python standard-library modules are used extensively throughout the backend and do not require separate installation.

---

## Installation

### 1. Open the project directory

```bash
cd "Final Project"
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
```

Linux/macOS:

```bash
python3 -m venv .venv
```

### 3. Activate the virtual environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Windows CMD:

```cmd
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install flask flask-cors requests colorama
```

---

## Running the Backend

From the project directory:

```bash
python app.py
```

The Flask server starts on:

```text
http://127.0.0.1:5000
```

The application binds to:

```text
0.0.0.0:5000
```

for the Flask development server.

Verify the API:

```text
GET http://127.0.0.1:5000/api/v1/master/health
```

---

## Running the Frontend

`index.html`, `script.js`, and `style.css` form a static frontend.

The frontend is not served by `app.py` itself.

Use a static web server such as VS Code Live Server or another local HTTP server to open `index.html`.

The frontend API base should point to:

```text
http://127.0.0.1:5000
```

The dashboard performs a health check against:

```text
/api/v1/master/health
```

and sends scans to:

```text
/api/v1/master/scan
```

---

## Running a Master Scan from the Command Line

`master_link.py` can also be executed directly.

```bash
python master_link.py --url https://example.com
```

The program prints the master security report to the terminal.

A JSON report can be saved using:

```bash
python master_link.py --url https://example.com --output report.json
```

If no URL is supplied, the program prompts for one interactively.

---

## Running the Individual Modules

### HTTP Scanner

```bash
python http_scanner.py
```

The scanner prompts for the target URL and prints the full HTTP security scan result.

### Reconnaissance & Intelligence Layers

The platform extends its technical security checks with reconnaissance capabilities that provide additional context before and alongside the security assessment.

### OSINT Lookup Layer

The OSINT layer gathers relevant publicly available information to enrich the target profile and support the assessment with additional context. It is intended to complement technical findings rather than replace direct security validation.

### User Discovery

The user-discovery component identifies potential user-related information and exposed indicators as part of the reconnaissance workflow. Discovered information is treated as reconnaissance evidence and should be validated before being considered a confirmed security finding.

---

## robots.txt Analyzer

The analyzer contains command-line functionality for retrieving, analyzing, and exporting `robots.txt` information.

### Security Behavior Profiling Engine

The main behavior engine can be integrated through its `SecurityBehaviorProfiler` class or Flask blueprint.

The engine also contains internal command-line/reporting helpers.

---

## Output Model

The master scan returns three primary result objects:

```text
security_behavior_engine
combined_scanner
robots_txt_analysis
```

and a unified assessment:

```text
unified_assessment
```

The unified assessment contains:

```text
unified_score_percent
rating
components
```

The behavioral engine report contains:

```text
feature
target
scan_timestamp
execution_time_ms
profile
observations
anomalies
correlated_risks
overall
recommendations
```

---

## Finding Confidence Model

The project distinguishes between confirmed evidence and observations that require further validation.

### Confirmed

The condition was directly observed and verified by the automated check.

### Suspected

The scanner observed a signal that may indicate a security issue, but the evidence is not sufficient to classify it as a confirmed vulnerability.

### Needs Manual Verification

The automated check could not establish the security state conclusively.

This distinction is especially important for HTTP methods advertised through the `OPTIONS` `Allow` header.

---

## Security Scope

This project is designed for defensive security assessment and surface-level behavioral profiling of authorized targets.

It does not perform exploitation, credential attacks, brute force, authenticated testing, or a complete penetration test.

Only scan systems for which you have explicit authorization.

---

## Scan Limitations

The automated HTTP scanner has the following limitations:

1. It inspects raw HTTP responses using Python `requests`.
2. It does not execute JavaScript.
3. Cookies or headers created dynamically by client-side JavaScript may not be detected.
4. The scan is unauthenticated.
5. Authenticated pages and controls that appear only after login are not assessed.
6. HTTP methods are inferred from the `OPTIONS` `Allow` header and are not automatically considered exploitable.
7. A successful HTTP response does not imply that the target is secure.
8. The project performs an automated surface-level assessment and is not a replacement for a complete penetration test or security audit.

---

## Important Scoring Notes

The project intentionally separates:

```text
Confirmed Security Findings
Suspected Findings
Needs Manual Verification
Informational Findings
```

Only confirmed findings contribute to the dedicated HTTP scanner score.

The behavioral engine uses domain scores as its primary signal and applies limited contextual penalties for anomalies and correlated risks.

The master layer then combines the behavioral and scanner scores and applies the configured robots.txt high-risk-path penalty.

Therefore, the displayed score should be interpreted as an automated security assessment score, not as a universal measure of real-world security.

---

## Technology Stack

### Backend

- Python
- Flask
- Flask-CORS
- Requests
- Colorama
- Python standard library

### Frontend

- HTML5
- CSS3
- Vanilla JavaScript
- SVG-based interface elements

### Security Analysis

- HTTP/HTTPS transport analysis
- Security-header analysis
- Cookie security analysis
- Redirect analysis
- CORS analysis
- HTTP method analysis
- Information-disclosure analysis
- Behavioral anomaly detection
- Cross-domain risk correlation
- robots.txt analysis
- Unified security scoring

---

## Project Purpose

NTI NEXUS provides a unified interface for analyzing observable web-security behavior instead of relying on a single isolated scanner.

The architecture separates collection, analysis, correlation, scoring, integration, and presentation so that the individual security modules can operate independently while also contributing to one master assessment.

---

## Team Contributions

| Team Member | Main Contribution |
|---|---|
| **Malak Mahmoud Abdullah** | Security Behavior Profiling Engine and behavioral security analysis |
| **Jana Muhammad Ali** | Backend & Frontend Development, HTTP Scanner, and User Discovery |
| **Mahmoud Basem Ibrahim Ismail** | OSINT Lookup Layer |
| **Ahmed Fouad** | `robots.txt` Analyzer |

The components are integrated through the master layer so that each contribution can provide evidence to the overall security assessment.
