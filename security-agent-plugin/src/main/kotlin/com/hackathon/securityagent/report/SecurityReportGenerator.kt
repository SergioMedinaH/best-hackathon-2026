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

        val priorities = narrative.topPriorities.ifEmpty { fallbackPriorities(findings) }
        val remediationPlan = narrative.remediationPlan.ifEmpty { fallbackRemediationPlan(findings) }

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Security Report - ${escapeHtml(projectName)}</title>
          <style>
            body { font-family: "Segoe UI", sans-serif; margin: 0; padding: 32px; background: #f4f7fb; color: #1f2933; }
            .page { max-width: 1080px; margin: 0 auto; }
            .hero { background: linear-gradient(135deg, #0f172a, #1d4ed8); color: white; border-radius: 18px; padding: 28px 32px; box-shadow: 0 18px 45px rgba(15, 23, 42, 0.18); }
            .hero h1 { margin: 0 0 8px 0; font-size: 32px; }
            .hero-meta { display: flex; flex-wrap: wrap; gap: 18px; margin-top: 16px; font-size: 14px; opacity: 0.92; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 24px 0; }
            .card, .finding { background: white; border-radius: 16px; padding: 20px; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08); }
            .card h2, .severity-section h2 { margin-top: 0; }
            .score { font-size: 38px; font-weight: 700; color: #0f172a; }
            .badge { display: inline-block; border-radius: 999px; padding: 6px 12px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
            .badge-critical { background: #7f1d1d; color: white; }
            .badge-high { background: #c2410c; color: white; }
            .badge-medium { background: #facc15; color: #1f2933; }
            .badge-low { background: #15803d; color: white; }
            .badge-info { background: #0284c7; color: white; }
            .badge-unknown { background: #64748b; color: white; }
            .severity-section { margin-top: 28px; }
            .finding { margin-top: 16px; border-left: 6px solid #cbd5e1; }
            .finding h3 { margin-top: 0; }
            .meta { display: grid; grid-template-columns: 140px 1fr; gap: 8px 12px; font-size: 14px; margin: 16px 0; }
            .meta-label { font-weight: 700; color: #475569; }
            pre { background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 12px; overflow-x: auto; white-space: pre-wrap; }
            ul, ol { margin-top: 8px; }
            p { line-height: 1.6; }
          </style>
        </head>
        <body>
          <div class="page">
            <section class="hero">
              <h1>Security Report</h1>
              <p>${escapeHtml(narrative.executiveSummary)}</p>
              <div class="hero-meta">
                <span>Project: ${escapeHtml(projectName)}</span>
                <span>Generated: ${escapeHtml(formatGeneratedAt(state))}</span>
                <span>Risk: ${escapeHtml(narrative.overallRisk)}</span>
                <span>Findings: ${findings.size}</span>
              </div>
            </section>

            <section class="grid">
              <div class="card">
                <h2>Security Score</h2>
                <div class="score">$score / 100</div>
                <p>${escapeHtml(severityBreakdown(findings))}</p>
              </div>
              <div class="card">
                <h2>Immediate Priorities</h2>
                <ol>${priorities.joinToString(separator = "") { "<li>${escapeHtml(it)}</li>" }}</ol>
              </div>
              <div class="card">
                <h2>Remediation Plan</h2>
                <ul>${remediationPlan.joinToString(separator = "") { "<li>${escapeHtml(it)}</li>" }}</ul>
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
        <article class="finding">
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
}
