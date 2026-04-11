package com.hackathon.securityagent.model

import java.nio.file.Path

data class Finding(
    val ruleId: String,
    val severity: Severity,
    val message: String,
    val cweIds: List<String>,
    val relativePath: String,
    val absolutePath: Path,
    val line: Int,
    val column: Int? = null,
    val validationStatus: ValidationStatus = ValidationStatus.PENDING,
    val confidence: Int? = null,
    val owaspCategory: String? = null,
    val validationRationale: String? = null,
    val narrativeExplanation: String? = null,
    val exploitChain: String? = null,
    val fixSummary: String? = null,
    val safeCodeExample: String? = null,
    val fixPatch: FixPatch? = null,
    val enrichmentError: String? = null,
) {
    val id: String
        get() = "${absolutePath.normalize()}|$line|${column ?: 0}|$ruleId"

    val locationDisplay: String
        get() = buildString {
            append(relativePath)
            append(':')
            append(line)
            column?.let {
                append(':')
                append(it)
            }
        }

    val hasAgentDetails: Boolean
        get() =
            narrativeExplanation != null ||
                exploitChain != null ||
                fixSummary != null ||
                safeCodeExample != null ||
                fixPatch != null ||
                validationRationale != null ||
                enrichmentError != null

    val hasApplicableFix: Boolean
        get() = fixPatch != null
}
