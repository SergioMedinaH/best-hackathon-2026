package com.hackathon.securityagent.agents

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.psi.CodeContext

class ExplainerAgent(
    private val runner: KoogAgentRunner,
) {
    fun explain(
        finding: Finding,
        context: CodeContext,
        validation: ValidationResponse,
    ): ExplanationResponse {
        val prompt = buildString {
            appendLine("Explain the validated finding for a developer inside an IDE tool window.")
            appendLine("Focus on the exploit path and why the specific code is risky. Return JSON only.")
            appendLine()
            append(FindingPromptFormatter.baseContext(finding, context))
            appendLine()
            appendLine("Validated status: ${validation.status}")
            appendLine("Confidence: ${validation.confidence}")
            appendLine("Validation rationale: ${validation.rationale}")
            validation.owaspCategory?.let {
                appendLine("OWASP mapping: $it")
            }
        }

        return StructuredJsonParser.parse(runner.run(PROMPT_PATH, prompt))
    }

    private companion object {
        private const val PROMPT_PATH = "prompts/explainer.md"
    }
}
