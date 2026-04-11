package com.hackathon.securityagent.report

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import kotlin.math.roundToInt

object SecurityScoreCalculator {
    fun calculate(findings: List<Finding>): Int {
        val totalPenalty = findings.sumOf { penaltyFor(it) }
        return (100 - totalPenalty).coerceIn(0, 100)
    }

    private fun penaltyFor(finding: Finding): Int {
        val severityPenalty = when (finding.severity) {
            Severity.CRITICAL -> 18
            Severity.HIGH -> 12
            Severity.MEDIUM -> 6
            Severity.LOW -> 3
            Severity.INFO -> 1
            Severity.UNKNOWN -> 4
        }
        val multiplier = when (finding.validationStatus) {
            ValidationStatus.CONFIRMED -> 1.0
            ValidationStatus.NEEDS_REVIEW -> 0.75
            ValidationStatus.PENDING -> 0.65
            ValidationStatus.ERROR -> 0.50
            ValidationStatus.DISMISSED -> 0.0
        }
        return (severityPenalty * multiplier).roundToInt()
    }
}
