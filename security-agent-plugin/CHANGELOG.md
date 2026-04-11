<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Security Agent Changelog

## [Unreleased]

### Added

- Rebrand the JetBrains plugin template into the Security Agent plugin.
- Add a Phase 1 `Scan Project for Security Issues` action wired into the IDE Tools menu.
- Add a Semgrep SARIF pipeline with a typed `Finding` model, severity mapping, and structured logging.
- Add a parser test fixture for Semgrep SARIF output.
- Add a Phase 2 tool window with severity-grouped findings, detail view, navigation, and rescan support.
- Add a Phase 3 settings page backed by Password Safe plus a reusable OpenAI client and `Ping OpenAI` action.
