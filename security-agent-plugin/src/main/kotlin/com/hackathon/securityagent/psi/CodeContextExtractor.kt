package com.hackathon.securityagent.psi

import com.hackathon.securityagent.model.Finding
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

data class CodeContext(
    val relativePath: String,
    val focusLine: Int,
    val lineWindow: IntRange,
    val imports: List<String>,
    val enclosingSymbol: String?,
    val snippet: String,
)

class CodeContextExtractor {
    fun extract(
        finding: Finding,
        radius: Int = DEFAULT_RADIUS,
    ): CodeContext {
        val sourcePath = finding.absolutePath
        if (!Files.exists(sourcePath)) {
            return CodeContext(
                relativePath = finding.relativePath,
                focusLine = finding.line,
                lineWindow = finding.line..finding.line,
                imports = emptyList(),
                enclosingSymbol = null,
                snippet = "Source file is no longer available on disk.",
            )
        }

        val lines = Files.readAllLines(sourcePath, StandardCharsets.UTF_8)
        if (lines.isEmpty()) {
            return CodeContext(
                relativePath = finding.relativePath,
                focusLine = finding.line,
                lineWindow = finding.line..finding.line,
                imports = emptyList(),
                enclosingSymbol = null,
                snippet = "The source file is empty.",
            )
        }

        val focusIndex = (finding.line - 1).coerceIn(0, lines.lastIndex)
        val startIndex = (focusIndex - radius).coerceAtLeast(0)
        val endIndex = (focusIndex + radius).coerceAtMost(lines.lastIndex)

        val imports = lines
            .take(IMPORT_SCAN_LIMIT)
            .map { it.trim() }
            .filter { it.startsWith("import ") || it.startsWith("from ") }
            .distinct()

        val enclosingSymbol = findNearestSymbol(lines, focusIndex)
        val snippet = (startIndex..endIndex).joinToString(separator = "\n") { index ->
            val marker = if (index == focusIndex) ">>" else "  "
            val lineNumber = (index + 1).toString().padStart(4)
            "$marker $lineNumber | ${lines[index]}"
        }

        return CodeContext(
            relativePath = finding.relativePath,
            focusLine = finding.line,
            lineWindow = (startIndex + 1)..(endIndex + 1),
            imports = imports,
            enclosingSymbol = enclosingSymbol,
            snippet = snippet,
        )
    }

    private fun findNearestSymbol(
        lines: List<String>,
        focusIndex: Int,
    ): String? {
        for (index in focusIndex downTo 0) {
            val match = SYMBOL_PATTERN.find(lines[index]) ?: continue
            val kind = match.groupValues[1]
            val name = match.groupValues[2]
            return "$kind $name"
        }
        return null
    }

    fun readLineRange(
        path: Path,
        startLine: Int,
        endLine: Int,
    ): String? {
        if (startLine <= 0 || endLine < startLine || !Files.exists(path)) {
            return null
        }

        val lines = Files.readAllLines(path, StandardCharsets.UTF_8)
        if (lines.isEmpty() || endLine > lines.size) {
            return null
        }

        return lines.subList(startLine - 1, endLine).joinToString(separator = "\n")
    }

    private companion object {
        private const val DEFAULT_RADIUS = 20
        private const val IMPORT_SCAN_LIMIT = 80
        private val SYMBOL_PATTERN = Regex("""^\s*(def|class)\s+([A-Za-z_][A-Za-z0-9_]*)""")
    }
}
