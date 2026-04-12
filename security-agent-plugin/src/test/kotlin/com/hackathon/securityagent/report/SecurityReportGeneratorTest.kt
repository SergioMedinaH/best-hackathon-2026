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
                severity = Severity.CRITICAL,
                line = 61,
                relativePath = "app.py",
                message = "shell=True allows command injection.",
                validationStatus = ValidationStatus.CONFIRMED,
                confidence = 95,
                cweIds = listOf("CWE-78"),
            ),
            sampleFinding(
                ruleId = "python.flask.security.insecure-deserialization.insecure-deserialization",
                severity = Severity.HIGH,
                line = 72,
                relativePath = "auth/session.py",
                message = "pickle.loads on request data can lead to RCE.",
                validationStatus = ValidationStatus.NEEDS_REVIEW,
                confidence = 84,
                cweIds = listOf("CWE-502"),
            ),
            sampleFinding(
                ruleId = "python.lang.security.audit.md5-used",
                severity = Severity.LOW,
                line = 115,
                relativePath = "crypto.py",
                message = "MD5 should not be used for password hashing.",
                validationStatus = ValidationStatus.PENDING,
                confidence = 41,
                cweIds = listOf("CWE-327"),
                fixSummary = "",
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
        assertTrue(report.html.contains("Severity Distribution"))
        assertTrue(report.html.contains("Validation Distribution"))
        assertTrue(report.html.contains("Top CWE"))
        assertTrue(report.html.contains("Findings by File"))
        assertTrue(report.html.contains("Coverage Overview"))
        assertTrue(report.html.contains("Confidence Distribution"))
        assertTrue(report.html.contains("Projected Remediation Outcome"))
        assertTrue(report.html.contains("Top Risks"))
        assertTrue(report.html.contains("conic-gradient("))
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
        relativePath: String = "app.py",
        validationStatus: ValidationStatus = ValidationStatus.CONFIRMED,
        confidence: Int = 95,
        cweIds: List<String> = listOf("CWE-78"),
        fixSummary: String = "Use a safer API and remove the dangerous shell invocation.",
    ) = Finding(
        ruleId = ruleId,
        severity = severity,
        message = message,
        cweIds = cweIds,
        relativePath = relativePath,
        absolutePath = Path.of("C:/Users/sergi/Documents/Uni/Hackathon/demo-vulnerable-app/$relativePath"),
        line = line,
        column = 1,
        validationStatus = validationStatus,
        confidence = confidence,
        owaspCategory = "A03:2021 - Injection",
        validationRationale = "The validator confirmed this is exploitable with attacker-controlled input.",
        narrativeExplanation = "The route uses untrusted data in a dangerous sink.",
        exploitChain = "Attacker input reaches the sink without sanitization.",
        fixSummary = fixSummary,
        safeCodeExample = "subprocess.check_output([\"ping\", \"-n\", \"1\", host], shell=False)",
    )
}
