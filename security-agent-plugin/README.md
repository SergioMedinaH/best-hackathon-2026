# Security Agent

<!-- Plugin description -->
**Security Agent** is an IntelliJ/PyCharm plugin built for the BEST UC3M "Help the Developer" hackathon. It combines Semgrep grounding with agentic reasoning to help developers detect, understand, and fix security vulnerabilities without leaving the IDE.

The Phase 1 milestone focuses on the foundation:
- a real plugin identity instead of the JetBrains template scaffold
- a `Scan Project for Security Issues` action registered in the IDE
- a Kotlin `SemgrepRunner` that invokes Semgrep and parses SARIF output into a typed `Finding` model
- structured scan logs that print severity, file, line, CWE, and message for each result

Phase 2 and Phase 3 extend that base with:
- a `Security Agent` tool window that groups findings by severity and navigates to source on double click
- an application settings page for the OpenAI API key, chat model, and base URL
- secure API key storage through IntelliJ Password Safe
- a reusable `OpenAIClient` with plain chat, strict JSON-schema responses, streaming helpers, and a `Ping OpenAI` action
<!-- Plugin description end -->

## Current workflow

1. Open the vulnerable demo project in the IDE sandbox.
2. Trigger `Tools | Scan Project for Security Issues`.
3. The plugin scans the project root with Semgrep and prints findings to the run log in a structured format.
4. Open `Settings | Tools | Security Agent` to configure the OpenAI API key.
5. Trigger `Tools | Ping OpenAI` to validate the stored credentials with a real API request.

## Local verification

```bash
./gradlew test
./gradlew buildPlugin
```

## Notes

- The plugin currently expects `semgrep` to be available on `PATH`.
- `pluginRepositoryUrl` is a placeholder and should be replaced with the team repository once the final repo is decided.
