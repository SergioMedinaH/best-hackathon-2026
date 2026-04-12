package com.hackathon.securityagent.report

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.services.SecurityScanState
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class SecurityReportGenerator(
    private val projectName: String,
    private val projectBasePath: Path?,
) {
    fun generate(
        state: SecurityScanState,
        narrative: SecurityReportNarrative? = null,
    ): SecurityReportDocument {
        val reportableFindings = state.findings
            .filter { it.validationStatus != ValidationStatus.DISMISSED }
            .sortedWith(compareByDescending<Finding> { it.severity.priority }.thenByDescending { it.confidence ?: 0 })
        val findings = reportableFindings.ifEmpty { state.findings }
        val score = SecurityScoreCalculator.calculate(findings)
        val reportNarrative = narrative ?: fallbackNarrative(findings, score)
        return SecurityReportDocument(
            score = score,
            markdown = buildMarkdown(state, findings, score, reportNarrative),
            html = buildHtml(state, findings, score, reportNarrative),
        )
    }

    fun exportToProjectRoot(document: SecurityReportDocument): ExportedSecurityReport {
        val projectRoot = projectBasePath ?: error("The project must be saved to disk before exporting reports.")
        Files.createDirectories(projectRoot)

        val markdownPath = projectRoot.resolve(MARKDOWN_FILENAME)
        val htmlPath = projectRoot.resolve(HTML_FILENAME)

        Files.writeString(markdownPath, document.markdown, StandardCharsets.UTF_8)
        Files.writeString(htmlPath, document.html, StandardCharsets.UTF_8)

        return ExportedSecurityReport(
            markdownPath = markdownPath,
            htmlPath = htmlPath,
        )
    }

    private fun buildMarkdown(
        state: SecurityScanState,
        findings: List<Finding>,
        score: Int,
        narrative: SecurityReportNarrative,
    ): String =
        buildString {
            appendLine("# Security Report")
            appendLine()
            appendLine("- Project: $projectName")
            appendLine("- Generated: ${formatGeneratedAt(state)}")
            projectBasePath?.let { appendLine("- Project root: $it") }
            appendLine("- Security score: $score / 100")
            appendLine("- Findings in report: ${findings.size}")
            appendLine()
            appendLine("## Executive Summary")
            appendLine()
            appendLine(narrative.executiveSummary)
            appendLine()
            appendLine("## Overall Risk")
            appendLine()
            appendLine("- Risk level: ${narrative.overallRisk}")
            appendLine("- Severity breakdown: ${severityBreakdown(findings)}")
            state.lastScanDurationMs?.let { appendLine("- Scan duration: ${it} ms") }
            if (state.lastCommand.isNotEmpty()) {
                appendLine("- Scan command: `${state.lastCommand.joinToString(" ")}`")
            }
            appendLine()
            appendLine("## Immediate Priorities")
            appendLine()
            val priorities = narrative.topPriorities.ifEmpty { fallbackPriorities(findings) }
            priorities.forEachIndexed { index, item ->
                appendLine("${index + 1}. $item")
            }
            appendLine()
            appendLine("## Remediation Plan")
            appendLine()
            val remediationPlan = narrative.remediationPlan.ifEmpty { fallbackRemediationPlan(findings) }
            remediationPlan.forEach { item ->
                appendLine("- $item")
            }
            appendLine()
            appendLine("## Findings by Severity")
            appendLine()

            findings
                .groupBy { it.severity }
                .toList()
                .sortedByDescending { it.first.priority }
                .forEach { (severity, groupedFindings) ->
                    appendLine("### ${severity.displayName} (${groupedFindings.size})")
                    appendLine()
                    groupedFindings.forEach { finding ->
                        appendLine("#### ${finding.ruleId}")
                        appendLine()
                        appendLine("- Location: ${finding.locationDisplay}")
                        appendLine("- Validation: ${finding.validationStatus.displayName}")
                        appendLine("- Confidence: ${finding.confidence?.let { "$it%" } ?: "Unknown"}")
                        appendLine("- CWE: ${finding.cweIds.joinToString().ifBlank { "Not provided" }}")
                        appendLine("- OWASP: ${finding.owaspCategory ?: "Not mapped"}")
                        appendLine("- Message: ${finding.message}")
                        appendLine()

                        finding.validationRationale?.takeIf { it.isNotBlank() }?.let {
                            appendLine("**Validator rationale**")
                            appendLine()
                            appendLine(it)
                            appendLine()
                        }
                        finding.narrativeExplanation?.takeIf { it.isNotBlank() }?.let {
                            appendLine("**Narrative explanation**")
                            appendLine()
                            appendLine(it)
                            appendLine()
                        }
                        finding.exploitChain?.takeIf { it.isNotBlank() }?.let {
                            appendLine("**Exploit chain**")
                            appendLine()
                            appendLine(it)
                            appendLine()
                        }
                        finding.fixSummary?.takeIf { it.isNotBlank() }?.let {
                            appendLine("**Proposed fix**")
                            appendLine()
                            appendLine(it)
                            appendLine()
                        }
                        finding.safeCodeExample?.takeIf { it.isNotBlank() }?.let {
                            appendLine("**Safe code example**")
                            appendLine()
                            appendLine("```python")
                            appendLine(it.trim())
                            appendLine("```")
                            appendLine()
                        }
                    }
                }
        }

    private fun buildHtml(
        state: SecurityScanState,
        findings: List<Finding>,
        score: Int,
        narrative: SecurityReportNarrative,
    ): String {
        val allFindings = state.findings.ifEmpty { findings }
        val priorities = narrative.topPriorities.ifEmpty { fallbackPriorities(findings) }
        val remediationPlan = narrative.remediationPlan.ifEmpty { fallbackRemediationPlan(findings) }
        val severityData = severityChartData(findings)
        val validationData = validationChartData(allFindings)
        val cweData = topCweData(findings)
        val fileData = topFileData(findings)
        val confidenceData = confidenceDistribution(findings)
        val findingsWithFix = findings.count { it.hasApplicableFix }
        val reviewedFindings = findings.count { it.validationStatus != ValidationStatus.PENDING || it.hasAgentDetails }
        val projectedFindings = findings.filterNot { it.hasApplicableFix }
        val projectedScore = SecurityScoreCalculator.calculate(projectedFindings)
        val projectedDelta = projectedScore - score
        val topRisks = findings
            .sortedWith(compareByDescending<Finding> { it.severity.priority }.thenByDescending { it.confidence ?: 0 })
            .take(5)
        val severityCards = findings
            .groupBy { it.severity }
            .toList()
            .sortedByDescending { it.first.priority }
            .joinToString(separator = "") { (severity, groupedFindings) ->
                """
                <section class="severity-section">
                  <h2>${escapeHtml(severity.displayName)} (${groupedFindings.size})</h2>
                  ${groupedFindings.joinToString(separator = "") { finding -> findingToHtml(finding) }}
                </section>
                """.trimIndent()
            }
        val scoreAngle = (score.coerceIn(0, 100) * 3.6).toInt()

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Security Report - ${escapeHtml(projectName)}</title>
          <style>
            body { font-family: "Segoe UI", sans-serif; margin: 0; padding: 28px; background: linear-gradient(180deg, #f8fbff 0%, #eef3f8 100%); color: #1f2933; }
            .page { max-width: 1220px; margin: 0 auto; }
            .hero { background: linear-gradient(135deg, #0f172a, #1d4ed8); color: white; border-radius: 24px; padding: 28px; box-shadow: 0 18px 45px rgba(15, 23, 42, 0.18); }
            .hero-grid { display: grid; grid-template-columns: minmax(220px, 280px) 1fr; gap: 24px; align-items: center; }
            .hero h1 { margin: 0 0 8px 0; font-size: 34px; }
            .hero-meta { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px; font-size: 14px; opacity: 0.95; }
            .hero-meta span { padding: 8px 12px; border-radius: 999px; background: rgba(255,255,255,0.12); }
            .score-gauge { width: 210px; height: 210px; margin: 0 auto; border-radius: 50%; display: grid; place-items: center; background: radial-gradient(circle, #0f172a 0 58%, transparent 59%), conic-gradient(#38bdf8 0deg ${scoreAngle}deg, rgba(255,255,255,0.16) ${scoreAngle}deg 360deg); }
            .score-gauge-inner { text-align: center; }
            .score-gauge-value { font-size: 54px; font-weight: 800; line-height: 1; }
            .score-gauge-label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.9; margin-top: 8px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 22px 0; }
            .dual-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin: 22px 0; }
            .card, .finding { background: white; border-radius: 18px; padding: 20px; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08); border: 1px solid rgba(15, 23, 42, 0.06); }
            .card h2, .severity-section h2 { margin-top: 0; }
            .kpi { font-size: 40px; font-weight: 800; line-height: 1.05; color: #0f172a; }
            .muted { color: #5b6b7f; line-height: 1.55; }
            .badge { display: inline-block; border-radius: 999px; padding: 6px 12px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
            .badge-critical { background: #7f1d1d; color: white; }
            .badge-high { background: #c2410c; color: white; }
            .badge-medium { background: #facc15; color: #1f2933; }
            .badge-low { background: #15803d; color: white; }
            .badge-info { background: #0284c7; color: white; }
            .badge-unknown { background: #64748b; color: white; }
            .badge-confirmed { background: #dcfce7; color: #166534; }
            .badge-needs-review { background: #fef3c7; color: #92400e; }
            .badge-pending { background: #dbeafe; color: #1d4ed8; }
            .badge-error { background: #fee2e2; color: #b91c1c; }
            .badge-dismissed { background: #e2e8f0; color: #475569; }
            .section-head { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; margin-bottom: 14px; }
            .section-head p { margin: 0; color: #5b6b7f; font-size: 14px; }
            .donut-wrap { display: grid; grid-template-columns: 170px 1fr; gap: 18px; align-items: center; }
            .donut { width: 160px; height: 160px; margin: 0 auto; border-radius: 50%; display: grid; place-items: center; background: var(--donut-gradient); position: relative; }
            .donut::after { content: ""; position: absolute; inset: 22px; border-radius: 50%; background: white; }
            .donut-center { position: relative; z-index: 1; text-align: center; }
            .donut-center strong { display: block; font-size: 34px; line-height: 1; }
            .donut-center span { font-size: 12px; color: #5b6b7f; text-transform: uppercase; letter-spacing: 0.08em; }
            .legend { display: grid; gap: 10px; }
            .legend-row { display: grid; grid-template-columns: auto 1fr auto auto; gap: 10px; align-items: center; font-size: 14px; }
            .legend-dot { width: 12px; height: 12px; border-radius: 999px; }
            .bar-list { display: grid; gap: 12px; }
            .bar-row { display: grid; gap: 8px; }
            .bar-meta { display: flex; justify-content: space-between; gap: 12px; font-size: 14px; }
            .bar-track { height: 10px; background: #e2e8f0; border-radius: 999px; overflow: hidden; }
            .bar-fill { height: 100%; width: var(--bar-width); background: var(--bar-color); border-radius: 999px; }
            .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
            .metric { padding: 16px; border-radius: 16px; background: #f8fbff; border: 1px solid rgba(29, 78, 216, 0.08); }
            .metric strong { display: block; font-size: 28px; line-height: 1; margin-bottom: 6px; }
            .compare-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
            .compare-card { padding: 18px; border-radius: 16px; background: #f8fbff; border: 1px solid rgba(15, 23, 42, 0.06); }
            .compare-card strong { display: block; font-size: 32px; line-height: 1.05; margin-top: 6px; }
            .pill { display: inline-block; margin-top: 12px; padding: 6px 10px; border-radius: 999px; background: #dcfce7; color: #166534; font-size: 13px; font-weight: 700; }
            .risk-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 14px; }
            .risk-card { padding: 18px; border-radius: 18px; background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%); border: 1px solid rgba(15, 23, 42, 0.08); }
            .risk-card h3 { margin: 12px 0 10px 0; font-size: 18px; line-height: 1.35; }
            .risk-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
            .severity-section { margin-top: 28px; }
            .finding { margin-top: 16px; border-left: 6px solid var(--finding-border, #cbd5e1); }
            .finding h3 { margin-top: 0; }
            .meta { display: grid; grid-template-columns: 140px 1fr; gap: 8px 12px; font-size: 14px; margin: 16px 0; }
            .meta-label { font-weight: 700; color: #475569; }
            pre { background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 12px; overflow-x: auto; white-space: pre-wrap; }
            ul, ol { margin-top: 8px; }
            p { line-height: 1.6; }
            .empty { color: #5b6b7f; padding: 16px; border-radius: 14px; background: #f8fafc; border: 1px dashed rgba(100, 116, 139, 0.35); }
            @media (max-width: 860px) { body { padding: 18px; } .hero-grid, .donut-wrap { grid-template-columns: 1fr; } }
          </style>
        </head>
        <body>
          <div class="page">
            <section class="hero">
              <div class="hero-grid">
                <div class="score-gauge">
                  <div class="score-gauge-inner">
                    <div class="score-gauge-value">$score</div>
                    <div class="score-gauge-label">Security Score</div>
                  </div>
                </div>
                <div>
                  <h1>Security Report</h1>
                  <p>${escapeHtml(narrative.executiveSummary)}</p>
                  <div class="hero-meta">
                    <span>Project: ${escapeHtml(projectName)}</span>
                    <span>Generated: ${escapeHtml(formatGeneratedAt(state))}</span>
                    <span>Risk: ${escapeHtml(narrative.overallRisk)}</span>
                    <span>Findings: ${findings.size}</span>
                    <span>Scanned files: ${state.pythonFileCount}</span>
                  </div>
                </div>
              </div>
            </section>

            <section class="grid">
              <div class="card">
                <h2>Findings</h2>
                <div class="kpi">${findings.size}</div>
                <p class="muted">Active findings included in this report.</p>
              </div>
              <div class="card">
                <h2>Critical + High</h2>
                <div class="kpi">${findings.count { it.severity.priority >= Severity.HIGH.priority }}</div>
                <p class="muted">Issues with the highest potential impact.</p>
              </div>
              <div class="card">
                <h2>Agent Reviewed</h2>
                <div class="kpi">$reviewedFindings</div>
                <p class="muted">Findings already enriched with validation or narrative context.</p>
              </div>
              <div class="card">
                <h2>Executable Fixes</h2>
                <div class="kpi">$findingsWithFix</div>
                <p class="muted">Findings with a patch preview that can be applied from the IDE.</p>
              </div>
            </section>

            <section class="dual-grid">
              <section class="card">
                <div class="section-head">
                  <h2>Severity Distribution</h2>
                  <p>Potential impact across active findings.</p>
                </div>
                ${buildDonutSection(severityData, "Active Findings")}
              </section>
              <section class="card">
                <div class="section-head">
                  <h2>Validation Distribution</h2>
                  <p>Current agent verdicts over the scanned findings.</p>
                </div>
                ${buildBarSection(validationData, "Validation data")}
              </section>
            </section>

            <section class="dual-grid">
              <section class="card">
                <div class="section-head">
                  <h2>Top CWE</h2>
                  <p>Most repeated weakness classes.</p>
                </div>
                ${buildBarSection(cweData, "Top CWE data")}
              </section>
              <section class="card">
                <div class="section-head">
                  <h2>Findings by File</h2>
                  <p>Files concentrating the highest amount of risk.</p>
                </div>
                ${buildBarSection(fileData, "Findings by file")}
              </section>
            </section>

            <section class="dual-grid">
              <section class="card">
                <div class="section-head">
                  <h2>Coverage Overview</h2>
                  <p>Operational summary of the scan and enrichment pipeline.</p>
                </div>
                <div class="metric-grid">
                  <div class="metric"><strong>${state.pythonFileCount}</strong><span>Python files scanned</span></div>
                  <div class="metric"><strong>${findings.size}</strong><span>Active findings</span></div>
                  <div class="metric"><strong>$reviewedFindings</strong><span>Agent-reviewed findings</span></div>
                  <div class="metric"><strong>$findingsWithFix</strong><span>Fixes available</span></div>
                </div>
                <p class="muted">${escapeHtml(severityBreakdown(findings))}${state.lastScanDurationMs?.let { " Scan duration: ${it} ms." }.orEmpty()}</p>
              </section>
              <section class="card">
                <div class="section-head">
                  <h2>Confidence Distribution</h2>
                  <p>Confidence bands attached to the current findings.</p>
                </div>
                ${buildBarSection(confidenceData, "Confidence data")}
              </section>
            </section>

            <section class="dual-grid">
              <section class="card">
                <div class="section-head">
                  <h2>Projected Remediation Outcome</h2>
                  <p>Projection based on findings with an executable fix.</p>
                </div>
                <div class="compare-grid">
                  <div class="compare-card">
                    <span class="muted">Current state</span>
                    <strong>$score / 100</strong>
                    <p>${findings.size} active findings are currently included in the report.</p>
                  </div>
                  <div class="compare-card">
                    <span class="muted">Projected after suggested fixes</span>
                    <strong>$projectedScore / 100</strong>
                    <p>${projectedFindings.size} findings would remain if each executable fix fully resolved its mapped issue.</p>
                    <span class="pill">${if (projectedDelta >= 0) "+" else ""}$projectedDelta score delta</span>
                  </div>
                </div>
                <p class="muted">This is a projection, not a guaranteed post-rescan result.</p>
              </section>
              <section class="card">
                <div class="section-head">
                  <h2>Immediate Priorities</h2>
                  <p>Suggested order of execution.</p>
                </div>
                <ol>${priorities.joinToString(separator = "") { "<li>${escapeHtml(it)}</li>" }}</ol>
                <h2 style="margin-top: 18px;">Remediation Plan</h2>
                <ul>${remediationPlan.joinToString(separator = "") { "<li>${escapeHtml(it)}</li>" }}</ul>
              </section>
            </section>

            <section class="card">
              <div class="section-head">
                <h2>Top Risks</h2>
                <p>Highest-priority findings ordered by severity and confidence.</p>
              </div>
              <div class="risk-grid">
                ${topRisks.joinToString(separator = "") { topRiskCard(it) }}
              </div>
            </section>

            $severityCards
          </div>
        </body>
        </html>
        """.trimIndent()
    }

    private fun findingToHtml(finding: Finding): String {
        val safeExample = finding.safeCodeExample?.takeIf { it.isNotBlank() }?.let {
            "<h4>Safe Code Example</h4><pre>${escapeHtml(it.trim())}</pre>"
        }.orEmpty()

        val rationale = finding.validationRationale?.takeIf { it.isNotBlank() }?.let {
            "<h4>Validator Rationale</h4><p>${escapeHtmlPreservingNewlines(it)}</p>"
        }.orEmpty()

        val explanation = finding.narrativeExplanation?.takeIf { it.isNotBlank() }?.let {
            "<h4>Narrative Explanation</h4><p>${escapeHtmlPreservingNewlines(it)}</p>"
        }.orEmpty()

        val exploit = finding.exploitChain?.takeIf { it.isNotBlank() }?.let {
            "<h4>Exploit Chain</h4><p>${escapeHtmlPreservingNewlines(it)}</p>"
        }.orEmpty()

        val fix = finding.fixSummary?.takeIf { it.isNotBlank() }?.let {
            "<h4>Proposed Fix</h4><p>${escapeHtmlPreservingNewlines(it)}</p>"
        }.orEmpty()

        return """
        <article class="finding" style="--finding-border: ${severityColor(finding.severity)};">
          <span class="badge ${severityBadgeClass(finding.severity)}">${escapeHtml(finding.severity.displayName)}</span>
          <h3>${escapeHtml(finding.ruleId)}</h3>
          <div class="meta">
            <div class="meta-label">Location</div><div>${escapeHtml(finding.locationDisplay)}</div>
            <div class="meta-label">Validation</div><div>${escapeHtml(finding.validationStatus.displayName)}</div>
            <div class="meta-label">Confidence</div><div>${escapeHtml(finding.confidence?.let { "$it%" } ?: "Unknown")}</div>
            <div class="meta-label">CWE</div><div>${escapeHtml(finding.cweIds.joinToString().ifBlank { "Not provided" })}</div>
            <div class="meta-label">OWASP</div><div>${escapeHtml(finding.owaspCategory ?: "Not mapped")}</div>
          </div>
          <h4>Semgrep Message</h4>
          <p>${escapeHtmlPreservingNewlines(finding.message)}</p>
          $rationale
          $explanation
          $exploit
          $fix
          $safeExample
        </article>
        """.trimIndent()
    }

    private fun buildDonutSection(
        data: List<ChartDatum>,
        label: String,
    ): String {
        if (data.isEmpty()) {
            return """<div class="empty">$label is not available for this scan.</div>"""
        }

        val total = data.sumOf { it.count }.coerceAtLeast(1)

        return """
        <div class="donut-wrap">
          <div class="donut" style="--donut-gradient: conic-gradient(${buildConicGradient(data)});">
            <div class="donut-center">
              <strong>$total</strong>
              <span>${escapeHtml(label)}</span>
            </div>
          </div>
          <div class="legend">
            ${data.joinToString(separator = "") { datum ->
                """
                <div class="legend-row">
                  <span class="legend-dot" style="background: ${datum.color};"></span>
                  <span>${escapeHtml(datum.label)}</span>
                  <strong>${datum.count}</strong>
                  <span class="muted">${percentage(datum.count, total)}%</span>
                </div>
                """.trimIndent()
            }}
          </div>
        </div>
        """.trimIndent()
    }

    private fun buildBarSection(
        data: List<ChartDatum>,
        label: String,
    ): String {
        if (data.isEmpty()) {
            return """<div class="empty">$label is not available for this scan.</div>"""
        }

        val maxCount = data.maxOf { it.count }.coerceAtLeast(1)

        return """
        <div class="bar-list">
          ${data.joinToString(separator = "") { datum ->
                """
                <div class="bar-row">
                  <div class="bar-meta">
                    <span>${escapeHtml(datum.label)}</span>
                    <strong>${datum.count}</strong>
                  </div>
                  <div class="bar-track">
                    <div class="bar-fill" style="--bar-width: ${percentage(datum.count, maxCount)}%; --bar-color: ${datum.color};"></div>
                  </div>
                </div>
                """.trimIndent()
            }}
        </div>
        """.trimIndent()
    }

    private fun topRiskCard(finding: Finding): String {
        val confidenceText = finding.confidence?.let { "$it%" } ?: "Unknown"
        val validationBadgeClass = when (finding.validationStatus) {
            ValidationStatus.CONFIRMED -> "badge-confirmed"
            ValidationStatus.NEEDS_REVIEW -> "badge-needs-review"
            ValidationStatus.PENDING -> "badge-pending"
            ValidationStatus.ERROR -> "badge-error"
            ValidationStatus.DISMISSED -> "badge-dismissed"
        }

        return """
        <article class="risk-card">
          <span class="badge ${severityBadgeClass(finding.severity)}">${escapeHtml(finding.severity.displayName)}</span>
          <h3>${escapeHtml(finding.ruleId)}</h3>
          <div class="risk-meta">
            <span class="badge $validationBadgeClass">${escapeHtml(finding.validationStatus.displayName)}</span>
            <span class="badge badge-unknown">Confidence $confidenceText</span>
          </div>
          <p><strong>${escapeHtml(finding.locationDisplay)}</strong></p>
          <p>${escapeHtml(finding.message)}</p>
          ${finding.fixSummary?.takeIf { it.isNotBlank() }?.let { "<p><strong>Suggested fix:</strong> ${escapeHtml(it)}</p>" }.orEmpty()}
        </article>
        """.trimIndent()
    }

    private fun severityChartData(findings: List<Finding>): List<ChartDatum> =
        Severity.entries
            .filter { severity -> findings.any { it.severity == severity } }
            .map { severity ->
                ChartDatum(
                    label = severity.displayName,
                    count = findings.count { it.severity == severity },
                    color = severityColor(severity),
                )
            }

    private fun validationChartData(findings: List<Finding>): List<ChartDatum> =
        ValidationStatus.entries
            .filter { status -> findings.any { it.validationStatus == status } }
            .map { status ->
                ChartDatum(
                    label = status.displayName,
                    count = findings.count { it.validationStatus == status },
                    color = validationColor(status),
                )
            }

    private fun topCweData(findings: List<Finding>): List<ChartDatum> =
        findings
            .flatMap { it.cweIds.ifEmpty { listOf("Not provided") } }
            .groupingBy { it }
            .eachCount()
            .entries
            .sortedByDescending { it.value }
            .take(6)
            .map { (label, count) -> ChartDatum(label = label, count = count, color = "#1d4ed8") }

    private fun topFileData(findings: List<Finding>): List<ChartDatum> =
        findings
            .groupingBy { it.relativePath }
            .eachCount()
            .entries
            .sortedByDescending { it.value }
            .take(6)
            .map { (label, count) -> ChartDatum(label = label, count = count, color = "#0f766e") }

    private fun confidenceDistribution(findings: List<Finding>): List<ChartDatum> {
        val confidenceValues = findings.mapNotNull { it.confidence }
        if (confidenceValues.isEmpty()) {
            return emptyList()
        }

        return listOf(
            ChartDatum("0-24", confidenceValues.count { it in 0..24 }, "#fecaca"),
            ChartDatum("25-49", confidenceValues.count { it in 25..49 }, "#fdba74"),
            ChartDatum("50-74", confidenceValues.count { it in 50..74 }, "#fde68a"),
            ChartDatum("75-89", confidenceValues.count { it in 75..89 }, "#86efac"),
            ChartDatum("90-100", confidenceValues.count { it in 90..100 }, "#38bdf8"),
        ).filter { it.count > 0 }
    }

    private fun buildConicGradient(data: List<ChartDatum>): String {
        val total = data.sumOf { it.count }.coerceAtLeast(1)
        var start = 0.0

        return buildString {
            data.forEachIndexed { index, datum ->
                val sweep = datum.count.toDouble() / total.toDouble() * 360.0
                val end = if (index == data.lastIndex) 360.0 else start + sweep
                if (isNotEmpty()) {
                    append(", ")
                }
                append("${datum.color} ${formatNumber(start)}deg ${formatNumber(end)}deg")
                start = end
            }
        }
    }

    private fun percentage(
        value: Int,
        total: Int,
    ): Int =
        if (total <= 0) {
            0
        } else {
            (value.toDouble() / total.toDouble() * 100.0).toInt()
        }

    private fun formatNumber(value: Double): String = "%.2f".format(java.util.Locale.US, value)

    private fun severityColor(severity: Severity): String =
        when (severity) {
            Severity.CRITICAL -> "#b91c1c"
            Severity.HIGH -> "#c2410c"
            Severity.MEDIUM -> "#d97706"
            Severity.LOW -> "#15803d"
            Severity.INFO -> "#0284c7"
            Severity.UNKNOWN -> "#64748b"
        }

    private fun validationColor(status: ValidationStatus): String =
        when (status) {
            ValidationStatus.CONFIRMED -> "#15803d"
            ValidationStatus.NEEDS_REVIEW -> "#d97706"
            ValidationStatus.PENDING -> "#2563eb"
            ValidationStatus.ERROR -> "#b91c1c"
            ValidationStatus.DISMISSED -> "#64748b"
        }

    private fun fallbackNarrative(
        findings: List<Finding>,
        score: Int,
    ): SecurityReportNarrative {
        val highestSeverity = findings.maxByOrNull { it.severity.priority }?.severity?.displayName ?: "Unknown"
        val confirmedCount = findings.count { it.validationStatus == ValidationStatus.CONFIRMED }
        val needsReviewCount = findings.count { it.validationStatus == ValidationStatus.NEEDS_REVIEW }

        return SecurityReportNarrative(
            executiveSummary =
                "Security Agent identified ${findings.size} findings in $projectName. " +
                    "$confirmedCount findings are currently confirmed and $needsReviewCount require follow-up. " +
                    "The overall score is $score/100, with the highest active severity at $highestSeverity.",
            overallRisk = when {
                score <= 35 -> "Critical"
                score <= 60 -> "High"
                score <= 80 -> "Medium"
                else -> "Low"
            },
            topPriorities = fallbackPriorities(findings),
            remediationPlan = fallbackRemediationPlan(findings),
        )
    }

    private fun fallbackPriorities(findings: List<Finding>): List<String> =
        findings
            .sortedWith(compareByDescending<Finding> { it.severity.priority }.thenByDescending { it.confidence ?: 0 })
            .take(3)
            .map { finding ->
                "Address ${finding.ruleId} at ${finding.locationDisplay} (${finding.severity.displayName}) and verify the proposed remediation."
            }
            .ifEmpty { listOf("Run a fresh scan before exporting a report.") }

    private fun fallbackRemediationPlan(findings: List<Finding>): List<String> =
        buildList {
            if (findings.any { it.severity.priority >= Severity.HIGH.priority }) {
                add("Fix critical and high-severity code execution or injection paths before broad refactors.")
            }
            if (findings.any { it.validationStatus == ValidationStatus.NEEDS_REVIEW || it.validationStatus == ValidationStatus.PENDING }) {
                add("Review medium-confidence findings with the affected developer before merging remediations.")
            }
            add("Rescan the project after applying fixes and regenerate this report to confirm the score improves.")
        }

    private fun severityBreakdown(findings: List<Finding>): String =
        Severity.entries
            .filter { severity -> findings.any { it.severity == severity } }
            .joinToString(separator = " | ") { severity ->
                "${severity.displayName}: ${findings.count { it.severity == severity }}"
            }
            .ifBlank { "No findings in report." }

    private fun formatGeneratedAt(state: SecurityScanState): String =
        state.lastScanFinishedAt
            ?.atZone(ZoneId.systemDefault())
            ?.format(TIMESTAMP_FORMATTER)
            ?: "Not available"

    private fun severityBadgeClass(severity: Severity): String =
        when (severity) {
            Severity.CRITICAL -> "badge-critical"
            Severity.HIGH -> "badge-high"
            Severity.MEDIUM -> "badge-medium"
            Severity.LOW -> "badge-low"
            Severity.INFO -> "badge-info"
            Severity.UNKNOWN -> "badge-unknown"
        }

    private fun escapeHtmlPreservingNewlines(value: String): String =
        escapeHtml(value).replace("\n", "<br/>")

    private fun escapeHtml(value: String): String =
        buildString(value.length) {
            value.forEach { ch ->
                when (ch) {
                    '&' -> append("&amp;")
                    '<' -> append("&lt;")
                    '>' -> append("&gt;")
                    '"' -> append("&quot;")
                    '\'' -> append("&#39;")
                    else -> append(ch)
                }
            }
        }

    private companion object {
        private const val MARKDOWN_FILENAME = "security-report.md"
        private const val HTML_FILENAME = "security-report.html"
        private val TIMESTAMP_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    }

    private data class ChartDatum(
        val label: String,
        val count: Int,
        val color: String,
    )
}
