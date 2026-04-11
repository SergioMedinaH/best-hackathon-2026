package com.hackathon.securityagent.report

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.services.SecurityScanState
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Path
import java.time.Instant

class SecurityReportGeneratorTest {
    @Test
    fun `generates markdown and html report with executive sections`() {
        val findings = listOf(
            sampleFinding(
                ruleId = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                severity = Severity.HIGH,
                line = 61,
                message = "shell=True allows command injection.",
            ),
            sampleFinding(
                ruleId = "python.flask.security.insecure-deserialization.insecure-deserialization",
                severity = Severity.HIGH,
                line = 72,
                message = "pickle.loads on request data can lead to RCE.",
            ),
        )

        val report = SecurityReportGenerator(
            projectName = "demo-vulnerable-app",
            projectBasePath = Path.of("C:/Users/sergi/Documents/Uni/Hackathon/demo-vulnerable-app"),
        ).generate(
            state = SecurityScanState(
                findings = findings,
                pythonFileCount = 1,
                lastScanDurationMs = 1200,
                lastScanFinishedAt = Instant.parse("2026-04-11T16:40:00Z"),
                lastCommand = listOf("semgrep", "scan", "--config", "p/security-audit"),
            ),
            narrative = SecurityReportNarrative(
                executiveSummary = "The project contains multiple high-severity findings affecting code execution paths.",
                overallRisk = "High",
                topPriorities = listOf("Remove shell=True from subprocess usage."),
                remediationPlan = listOf("Replace dangerous primitives with safe standard-library alternatives."),
            ),
        )

        assertTrue(report.markdown.contains("# Security Report"))
        assertTrue(report.markdown.contains("## Executive Summary"))
        assertTrue(report.markdown.contains("## Findings by Severity"))
        assertTrue(report.markdown.contains("python.flask.security.insecure-deserialization.insecure-deserialization"))

        assertTrue(report.html.contains("<title>Security Report - demo-vulnerable-app</title>"))
        assertTrue(report.html.contains("Immediate Priorities"))
        assertTrue(report.html.contains("shell=True allows command injection."))
    }

    @Test
    fun `security score drops when confirmed high severity findings exist`() {
        val score = SecurityScoreCalculator.calculate(
            listOf(
                sampleFinding(severity = Severity.HIGH, line = 61),
                sampleFinding(severity = Severity.MEDIUM, line = 132),
            ),
        )

        assertTrue(score < 100)
        assertTrue(score >= 0)
    }

    private fun sampleFinding(
        ruleId: String = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        severity: Severity,
        line: Int,
        message: String = "A security issue was detected.",
    ) = Finding(
        ruleId = ruleId,
        severity = severity,
        message = message,
        cweIds = listOf("CWE-78"),
        relativePath = "app.py",
        absolutePath = Path.of("C:/Users/sergi/Documents/Uni/Hackathon/demo-vulnerable-app/app.py"),
        line = line,
        column = 1,
        validationStatus = ValidationStatus.CONFIRMED,
        confidence = 95,
        owaspCategory = "A03:2021 - Injection",
        validationRationale = "The validator confirmed this is exploitable with attacker-controlled input.",
        narrativeExplanation = "The route uses untrusted data in a dangerous sink.",
        exploitChain = "Attacker input reaches the sink without sanitization.",
        fixSummary = "Use a safer API and remove the dangerous shell invocation.",
        safeCodeExample = "subprocess.check_output([\"ping\", \"-n\", \"1\", host], shell=False)",
    )
}
