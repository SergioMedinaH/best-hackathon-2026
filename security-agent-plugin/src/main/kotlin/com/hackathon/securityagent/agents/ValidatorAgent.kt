package com.hackathon.securityagent.agents

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.psi.CodeContext

class ValidatorAgent(
    private val runner: KoogAgentRunner,
    private val groundingRepository: GroundingRepository,
) {
    fun validate(
        finding: Finding,
        context: CodeContext,
        triage: TriageResponse,
    ): ValidationResponse {
        val prompt = buildString {
            appendLine("Validate whether the finding is a real vulnerability in this code path.")
            appendLine("Prioritize grounded reasoning over general security advice. Return JSON only.")
            appendLine()
            append(FindingPromptFormatter.baseContext(finding, context))
            appendLine()
            appendLine("Triager rationale:")
            appendLine(triage.rationale)
            appendLine()
            appendLine("Relevant CWE grounding:")
            appendLine(groundingRepository.formatCweContext(finding.cweIds))
            appendLine()
            appendLine("OWASP Top 10 grounding:")
            appendLine(groundingRepository.formatOwaspContext())
        }

        return StructuredJsonParser.parse(runner.run(PROMPT_PATH, prompt))
    }

    private companion object {
        private const val PROMPT_PATH = "prompts/validator.md"
    }
}
