package com.hackathon.securityagent.report

import java.nio.file.Path

data class SecurityReportNarrative(
    val executiveSummary: String,
    val overallRisk: String,
    val topPriorities: List<String>,
    val remediationPlan: List<String>,
)

data class SecurityReportDocument(
    val score: Int,
    val markdown: String,
    val html: String,
)

data class ExportedSecurityReport(
    val markdownPath: Path,
    val htmlPath: Path,
)
