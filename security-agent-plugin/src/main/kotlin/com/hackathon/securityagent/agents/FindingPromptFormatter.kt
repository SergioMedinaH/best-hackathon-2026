package com.hackathon.securityagent.agents

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.psi.CodeContext

object FindingPromptFormatter {
    fun baseContext(
        finding: Finding,
        context: CodeContext,
    ): String =
        buildString {
            appendLine("Finding metadata:")
            appendLine("- Rule: ${finding.ruleId}")
            appendLine("- Severity: ${finding.severity.displayName}")
            appendLine("- Message: ${finding.message}")
            appendLine("- Location: ${finding.locationDisplay}")
            appendLine("- CWE IDs: ${finding.cweIds.ifEmpty { listOf("None") }.joinToString()}")
            appendLine("- Enclosing symbol: ${context.enclosingSymbol ?: "Not identified"}")
            appendLine("- Snippet range: ${context.lineWindow.first}-${context.lineWindow.last}")
            appendLine()
            appendLine("Imports:")
            appendLine(context.imports.ifEmpty { listOf("No imports detected in the first lines of the file.") }.joinToString(separator = "\n"))
            appendLine()
            appendLine("Focused code snippet:")
            appendLine(context.snippet)
        }
}
