package com.hackathon.securityagent.agents

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.psi.CodeContext

class TriagerAgent(
    private val runner: KoogAgentRunner,
) {
    fun triage(
        finding: Finding,
        context: CodeContext,
    ): TriageResponse {
        val prompt = buildString {
            appendLine("Review the following static analysis finding.")
            appendLine("Decide whether it is worth keeping for the developer-facing report or whether it looks like noise.")
            appendLine("Return JSON only.")
            appendLine()
            append(FindingPromptFormatter.baseContext(finding, context))
        }

        return StructuredJsonParser.parse(runner.run(PROMPT_PATH, prompt))
    }

    private companion object {
        private const val PROMPT_PATH = "prompts/triager.md"
    }
}
