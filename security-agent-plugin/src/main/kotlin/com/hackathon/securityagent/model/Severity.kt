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
        fun fromSarifLevel(level: String?): Severity =
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
