package com.hackathon.securityagent.model

enum class Severity(
    val displayName: String,
    val priority: Int,
) {
    CRITICAL("Critical", 4),
    HIGH("High", 3),
    MEDIUM("Medium", 2),
    LOW("Low", 1),
    INFO("Info", 0),
    UNKNOWN("Unknown", -1),
    ;

    companion object {
        fun fromSarifLevel(
            level: String?,
            ruleId: String? = null,
            cweIds: List<String> = emptyList(),
        ): Severity {
            val normalizedRuleId = ruleId?.lowercase().orEmpty()
            val normalizedCwes = cweIds.map { it.lowercase() }

            return when {
                normalizedCwes.any { it.startsWith("cwe-78") || it.startsWith("cwe-502") } ||
                    normalizedRuleId.contains("command-injection") ||
                    normalizedRuleId.contains("insecure-deserialization") ->
                    CRITICAL

                normalizedCwes.any { it.startsWith("cwe-327") || it.startsWith("cwe-798") || it.startsWith("cwe-489") } ||
                    normalizedRuleId.contains("md5") ||
                    normalizedRuleId.contains("hardcoded") ||
                    normalizedRuleId.contains("debug") ->
                    LOW

                else ->
                    when (level?.lowercase()) {
                        "error" -> HIGH
                        "warning" -> MEDIUM
                        "note" -> LOW
                        "none" -> INFO
                        null -> UNKNOWN
                        else -> UNKNOWN
                    }
            }
        }
    }
}
