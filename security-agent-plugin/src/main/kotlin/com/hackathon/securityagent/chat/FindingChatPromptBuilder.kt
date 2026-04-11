package com.hackathon.securityagent.chat

import com.hackathon.securityagent.agents.PromptResourceLoader
import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.openai.ChatMessage
import com.hackathon.securityagent.psi.CodeContextExtractor

class FindingChatPromptBuilder(
    private val promptLoader: PromptResourceLoader = PromptResourceLoader(),
    private val contextExtractor: CodeContextExtractor = CodeContextExtractor(),
) {
    fun buildMessages(
        finding: Finding,
        history: List<FindingChatMessage>,
    ): List<ChatMessage> {
        val context = contextExtractor.extract(finding)
        val bootstrapMessage = buildString {
            appendLine("Selected finding context:")
            appendLine("- Rule: ${finding.ruleId}")
            appendLine("- Severity: ${finding.severity.displayName}")
            appendLine("- Location: ${finding.locationDisplay}")
            appendLine("- CWE: ${finding.cweIds.joinToString().ifBlank { "Not provided" }}")
            appendLine("- OWASP: ${finding.owaspCategory ?: "Not mapped"}")
            appendLine("- Validation: ${finding.validationStatus.displayName}")
            appendLine("- Confidence: ${finding.confidence?.let { "$it%" } ?: "Unknown"}")
            appendLine("- Semgrep message: ${finding.message}")
            appendLine()
            appendLine("Reasoning gathered so far:")
            appendLine(finding.validationRationale ?: "No validator rationale available yet.")
            appendLine()
            appendLine("Narrative explanation:")
            appendLine(finding.narrativeExplanation ?: "No narrative explanation available yet.")
            appendLine()
            appendLine("Exploit chain:")
            appendLine(finding.exploitChain ?: "No exploit chain available yet.")
            appendLine()
            appendLine("Suggested remediation:")
            appendLine(finding.fixSummary ?: "No remediation summary available yet.")
            appendLine()
            appendLine("Safe code example:")
            appendLine(finding.safeCodeExample ?: "No safe code example available yet.")
            appendLine()
            appendLine("Relevant code context:")
            appendLine("- Path: ${context.relativePath}")
            appendLine("- Focus line: ${context.focusLine}")
            appendLine("- Enclosing symbol: ${context.enclosingSymbol ?: "Not detected"}")
            appendLine("- Imports: ${context.imports.joinToString().ifBlank { "None captured" }}")
            appendLine("- Line window: ${context.lineWindow.first}..${context.lineWindow.last}")
            appendLine()
            appendLine(context.snippet)
        }

        return buildList {
            add(ChatMessage("system", promptLoader.load(PROMPT_PATH)))
            add(ChatMessage("user", bootstrapMessage))
            history
                .filter { it.content.isNotBlank() }
                .forEach { message ->
                    add(ChatMessage(message.role.openAIRole, message.content))
                }
        }
    }

    private companion object {
        private const val PROMPT_PATH = "prompts/follow-up-chat.md"
    }
}
