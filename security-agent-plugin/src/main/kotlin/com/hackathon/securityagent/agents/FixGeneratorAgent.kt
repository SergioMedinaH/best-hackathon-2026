package com.hackathon.securityagent.agents

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.psi.CodeContext

class FixGeneratorAgent(
    private val runner: KoogAgentRunner,
) {
    fun generateFix(
        finding: Finding,
        context: CodeContext,
        validation: ValidationResponse,
        explanation: ExplanationResponse,
    ): FixGenerationResponse {
        val prompt = buildString {
            appendLine("Generate a safe remediation for the validated finding.")
            appendLine("Keep the response practical for an IDE user. Return JSON only.")
            appendLine()
            append(FindingPromptFormatter.baseContext(finding, context))
            appendLine()
            appendLine("Patch constraints:")
            appendLine("- Keep the patch minimal and contiguous.")
            appendLine("- patchStartLine and patchEndLine must use absolute file line numbers.")
            appendLine("- Prefer changing only lines within the focused snippet range (${context.lineWindow.first}-${context.lineWindow.last}).")
            appendLine("- replacementCode must be the exact replacement text for that line range, with no markdown fences.")
            appendLine()
            appendLine("Validated status: ${validation.status}")
            appendLine("Validation rationale: ${validation.rationale}")
            appendLine("Narrative explanation: ${explanation.narrativeExplanation}")
            appendLine("Exploit chain: ${explanation.exploitChain}")
        }

        return StructuredJsonParser.parse(runner.run(PROMPT_PATH, prompt))
    }

    private companion object {
        private const val PROMPT_PATH = "prompts/fixer.md"
    }
}
