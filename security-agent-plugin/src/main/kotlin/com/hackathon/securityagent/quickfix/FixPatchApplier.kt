package com.hackathon.securityagent.quickfix

import com.hackathon.securityagent.model.FixPatch

data class PatchApplicationResult(
    val updatedText: String,
    val currentSnippet: String,
    val replacementSnippet: String,
)

class FixPatchConflictException(
    message: String,
) : RuntimeException(message)

object FixPatchApplier {
    fun apply(
        currentText: String,
        patch: FixPatch,
    ): PatchApplicationResult {
        val lineSeparator = detectLineSeparator(currentText)
        val hadTrailingNewline = currentText.endsWith("\n") || currentText.endsWith("\r")
        val lines = splitLines(currentText)

        if (patch.endLine > lines.size || patch.startLine > lines.size || patch.startLine <= 0) {
            throw FixPatchConflictException("The file changed and the stored patch line range is no longer valid. Rescan the project.")
        }

        val startIndex = patch.startLine - 1
        val endExclusive = patch.endLine
        val currentSnippet = lines.subList(startIndex, endExclusive).joinToString(separator = "\n")
        if (normalize(currentSnippet) != normalize(patch.originalCode)) {
            throw FixPatchConflictException("The file changed since the scan. Rescan the project to regenerate this fix.")
        }

        val replacementLines = splitSnippet(patch.replacementCode)
        val updatedLines = lines.toMutableList().apply {
            subList(startIndex, endExclusive).clear()
            addAll(startIndex, replacementLines)
        }
        val updatedText = updatedLines.joinToString(separator = lineSeparator).let { joined ->
            if (hadTrailingNewline && joined.isNotEmpty()) {
                joined + lineSeparator
            } else {
                joined
            }
        }

        return PatchApplicationResult(
            updatedText = updatedText,
            currentSnippet = currentSnippet,
            replacementSnippet = replacementLines.joinToString(separator = "\n"),
        )
    }

    private fun splitLines(text: String): List<String> =
        if (text.isEmpty()) {
            emptyList()
        } else {
            LINE_BREAK_REGEX.split(text)
        }

    private fun splitSnippet(snippet: String): List<String> =
        if (snippet.isEmpty()) {
            emptyList()
        } else {
            LINE_BREAK_REGEX.split(snippet.trimEnd('\n', '\r'))
        }

    private fun detectLineSeparator(text: String): String =
        when {
            text.contains("\r\n") -> "\r\n"
            text.contains('\n') -> "\n"
            text.contains('\r') -> "\r"
            else -> "\n"
        }

    private fun normalize(text: String): String = text.replace("\r\n", "\n").replace('\r', '\n')

    private val LINE_BREAK_REGEX = Regex("\r\n|\n|\r")
}
