# demo-vulnerable-app

An intentionally insecure Flask application used to demo the **Security Agent**
JetBrains plugin during the BEST UC3M hackathon.

> **Do not deploy.** This project exists only as a scanning fixture and demo
> target. Every module contains curated vulnerabilities that should be picked up
> by the plugin.

## Structure

The app is split into multiple files so the plugin can demonstrate scanning a
small but more realistic Python codebase:

- `app.py`: Flask entry point, blueprint registration, hardcoded secret, debug mode
- `auth_routes.py`: authentication flows with SQL injection, hardcoded secrets, weak crypto
- `data_routes.py`: import/export flows with insecure deserialization and path traversal
- `network_routes.py`: command execution and outbound fetches from untrusted input
- `ui_routes.py`: unsafe server-side templating

## Vulnerability map

| File                | Route / Area         | CWE       | OWASP | Notes                                      |
| ------------------- | -------------------- | --------- | ----- | ------------------------------------------ |
| `app.py`            | app config           | CWE-798   | A07   | Hardcoded Flask secret                     |
| `app.py`            | `app.run(...)`       | CWE-489   | A05   | Debug mode enabled                         |
| `app.py`            | `app.run(...)`       | CWE-668   | A05   | `host="0.0.0.0"` exposure                  |
| `auth_routes.py`    | module config        | CWE-798   | A07   | Hardcoded DB URL and JWT signing key       |
| `auth_routes.py`    | `POST /login`        | CWE-89    | A03   | SQL injection via f-string                 |
| `auth_routes.py`    | `POST /register`     | CWE-327   | A02   | MD5 password hashing                       |
| `data_routes.py`    | `POST /restore`      | CWE-502   | A08   | `pickle.loads` on user-controlled bytes    |
| `data_routes.py`    | `POST /config`       | CWE-502   | A08   | `yaml.load` without `SafeLoader`           |
| `data_routes.py`    | `GET /download`      | CWE-22    | A01   | Path traversal in `send_file`              |
| `network_routes.py` | `GET /ping`          | CWE-78    | A03   | OS command injection with `shell=True`     |
| `network_routes.py` | `GET /fetch`         | CWE-918   | A10   | SSRF via `requests.get(url)`               |
| `ui_routes.py`      | `GET /hello`         | CWE-79    | A03   | Server-side XSS via `render_template_string` |

## Smoke-test the SAST baseline

From the repo root, with `semgrep` on `PATH`:

```bash
semgrep scan --json --config p/security-audit demo-vulnerable-app/ > findings-semgrep.json
```

Semgrep should now find issues across multiple files, which makes the plugin
demo feel much closer to a real project scan.
