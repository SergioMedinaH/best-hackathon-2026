package com.hackathon.securityagent.model

enum class ValidationStatus(
    val displayName: String,
) {
    PENDING("Pending"),
    CONFIRMED("Confirmed"),
    NEEDS_REVIEW("Needs Review"),
    DISMISSED("Dismissed"),
    ERROR("Error"),
    ;

    companion object {
        fun fromAgentValue(raw: String?): ValidationStatus =
            when (raw?.trim()?.uppercase()) {
                "CONFIRMED" -> CONFIRMED
                "NEEDS_REVIEW" -> NEEDS_REVIEW
                "DISMISSED" -> DISMISSED
                "ERROR" -> ERROR
                else -> PENDING
            }
    }
}
