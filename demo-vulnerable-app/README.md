# demo-vulnerable-app

A small intentionally insecure Flask app used to demo the **Security Agent**
JetBrains plugin during the BEST UC3M hackathon.

> **Do not deploy.** Every route here is a curated vulnerability used to
> trigger the plugin's detection, explanation, and one-click fix flow.

## Vulnerability map

| Route                | CWE       | OWASP Top 10 (2021) | Notes                              |
| -------------------- | --------- | ------------------- | ---------------------------------- |
| (module level)       | CWE-798   | A07                 | Hardcoded credentials & API keys   |
| `POST /login`        | CWE-89    | A03                 | SQL injection via f-string         |
| `GET /ping`          | CWE-78    | A03                 | OS command injection (`shell=True`)|
| `POST /restore`      | CWE-502   | A08                 | `pickle.loads` on untrusted bytes  |
| `POST /config`       | CWE-502   | A08                 | `yaml.load` without `SafeLoader`   |
| `GET /download`      | CWE-22    | A01                 | Path traversal in `send_file`      |
| `GET /fetch`         | CWE-918   | A10                 | SSRF via `requests.get(url)`       |
| `POST /register`     | CWE-327   | A02                 | MD5 password hashing               |
| `GET /hello`         | CWE-79    | A03                 | Server-side XSS via template str.  |

## Smoke-test the SAST baseline

From the repo root, with `semgrep` and `bandit` on `PATH`:

```bash
semgrep scan --json --config p/security-audit demo-vulnerable-app/ > findings-semgrep.json
bandit -r demo-vulnerable-app/ -f json -o findings-bandit.json
```

Both tools should find at least 8 issues across the file. The plugin's
`SemgrepRunner` and `BanditRunner` are validated against this fixture.
