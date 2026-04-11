package com.hackathon.securityagent.services

import com.hackathon.securityagent.model.Finding
import com.intellij.util.messages.Topic
import java.time.Instant

data class SecurityScanState(
    val findings: List<Finding> = emptyList(),
    val isScanning: Boolean = false,
    val isEnriching: Boolean = false,
    val pythonFileCount: Int = 0,
    val enrichedFindingCount: Int = 0,
    val totalFindingsToEnrich: Int = 0,
    val lastScanDurationMs: Long? = null,
    val lastScanFinishedAt: Instant? = null,
    val lastScanError: String? = null,
    val lastEnrichmentError: String? = null,
    val enrichmentSkippedReason: String? = null,
    val lastCommand: List<String> = emptyList(),
)

sealed interface ScanRequestResult {
    data object Started : ScanRequestResult

    data class Rejected(
        val message: String,
        val isError: Boolean,
    ) : ScanRequestResult
}

fun interface SecurityScanListener {
    fun stateUpdated(state: SecurityScanState)

    companion object {
        val TOPIC: Topic<SecurityScanListener> = Topic.create(
            "Security Agent Scan Updates",
            SecurityScanListener::class.java,
        )
    }
}
