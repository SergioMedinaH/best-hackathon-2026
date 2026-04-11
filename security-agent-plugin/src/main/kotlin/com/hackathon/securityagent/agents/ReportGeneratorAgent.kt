package com.hackathon.securityagent.agents

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.report.SecurityReportNarrative

class ReportGeneratorAgent(
    private val runner: KoogAgentRunner,
) {
    fun generateNarrative(
        projectName: String,
        score: Int,
        findings: List<Finding>,
    ): SecurityReportNarrative {
        val reportableFindings = findings
            .filter { it.validationStatus != ValidationStatus.DISMISSED }
            .sortedWith(compareByDescending<Finding> { it.severity.priority }.thenByDescending { it.confidence ?: 0 })
            .take(MAX_FINDINGS_IN_PROMPT)

        val prompt = buildString {
            appendLine("Create an executive security report summary for the following developer-facing scan.")
            appendLine("Return JSON only.")
            appendLine()
            appendLine("Project: $projectName")
            appendLine("Security score: $score / 100")
            appendLine("Findings in prompt: ${reportableFindings.size}")
            appendLine()
            appendLine("Findings:")
            reportableFindings.forEachIndexed { index, finding ->
                appendLine("${index + 1}. [${finding.severity.displayName}] ${finding.ruleId}")
                appendLine("   Location: ${finding.locationDisplay}")
                appendLine("   Validation: ${finding.validationStatus.displayName}")
                appendLine("   Confidence: ${finding.confidence?.let { "$it%" } ?: "Unknown"}")
                appendLine("   CWE: ${finding.cweIds.joinToString().ifBlank { "Not provided" }}")
                appendLine("   OWASP: ${finding.owaspCategory ?: "Not mapped"}")
                appendLine("   Message: ${finding.message}")
                finding.narrativeExplanation?.takeIf { it.isNotBlank() }?.let {
                    appendLine("   Explanation: $it")
                }
                finding.exploitChain?.takeIf { it.isNotBlank() }?.let {
                    appendLine("   Exploit: $it")
                }
                finding.fixSummary?.takeIf { it.isNotBlank() }?.let {
                    appendLine("   Fix: $it")
                }
                appendLine()
            }
        }

        val response: ReportGenerationResponse = StructuredJsonParser.parse(runner.run(PROMPT_PATH, prompt))
        return SecurityReportNarrative(
            executiveSummary = response.executiveSummary.trim(),
            overallRisk = response.overallRisk.trim(),
            topPriorities = response.topPriorities.map(String::trim).filter(String::isNotBlank),
            remediationPlan = response.remediationPlan.map(String::trim).filter(String::isNotBlank),
        )
    }

    private companion object {
        private const val PROMPT_PATH = "prompts/reporter.md"
        private const val MAX_FINDINGS_IN_PROMPT = 12
    }
}
