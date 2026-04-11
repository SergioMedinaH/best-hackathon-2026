package com.hackathon.securityagent.agents

import kotlinx.serialization.Serializable

@Serializable
data class TriageResponse(
    val keepFinding: Boolean,
    val rationale: String,
)

@Serializable
data class ValidationResponse(
    val status: String,
    val confidence: Int,
    val owaspCategory: String? = null,
    val rationale: String,
)

@Serializable
data class ExplanationResponse(
    val narrativeExplanation: String,
    val exploitChain: String,
)

@Serializable
data class FixGenerationResponse(
    val fixSummary: String,
    val safeCodeExample: String,
    val patchStartLine: Int? = null,
    val patchEndLine: Int? = null,
    val replacementCode: String? = null,
)

@Serializable
data class ReportGenerationResponse(
    val executiveSummary: String,
    val overallRisk: String,
    val topPriorities: List<String> = emptyList(),
    val remediationPlan: List<String> = emptyList(),
)
