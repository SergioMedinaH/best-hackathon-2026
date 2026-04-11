package com.hackathon.securityagent.ui

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.report.SecurityScoreCalculator
import com.hackathon.securityagent.services.SecurityScanState
import com.intellij.icons.AllIcons
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPanel
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridLayout
import javax.swing.JProgressBar

class SecurityOverviewPanel : JBPanel<SecurityOverviewPanel>(BorderLayout(0, 10)) {
    private val scoreValueLabel = JBLabel("--").apply {
        font = font.deriveFont(Font.BOLD, 26f)
    }
    private val scoreCaptionLabel = JBLabel("Run a scan to calculate project posture.")
    private val findingsValueLabel = createStatValueLabel()
    private val filesValueLabel = createStatValueLabel()
    private val confirmedValueLabel = createStatValueLabel()

    private val progressLabel = JBLabel("No scan running.")
    private val progressBar = JProgressBar(0, 100).apply {
        isStringPainted = true
        isVisible = false
    }

    private val guidanceIconLabel = JBLabel(AllIcons.General.Information)
    private val guidanceLabel = JBLabel()
    private val guidancePanel = JBPanel<JBPanel<*>>(BorderLayout(8, 0)).apply {
        isOpaque = true
        border = JBUI.Borders.compound(
            JBUI.Borders.customLine(JBColor(Color(0xD7DDE5), Color(0x4B5563))),
            JBUI.Borders.empty(10, 12),
        )
        add(guidanceIconLabel, BorderLayout.WEST)
        add(guidanceLabel, BorderLayout.CENTER)
        isVisible = false
    }

    private val severityChipPanel = JBPanel<JBPanel<*>>(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
        isOpaque = false
    }
    private val severityChips = Severity.entries.associateWith { severity ->
        createSeverityChip(severity).also { severityChipPanel.add(it) }
    }

    init {
        border = JBUI.Borders.empty(8, 10, 10, 10)
        add(buildHeroPanel(), BorderLayout.NORTH)
        add(buildProgressPanel(), BorderLayout.CENTER)
        add(guidancePanel, BorderLayout.SOUTH)
    }

    fun updateState(state: SecurityScanState) {
        val activeFindings = reportableFindings(state.findings)
        val score = when {
            state.findings.isEmpty() && state.lastScanFinishedAt == null && !state.isScanning && !state.isEnriching -> null
            else -> SecurityScoreCalculator.calculate(activeFindings)
        }

        scoreValueLabel.text = score?.toString() ?: "--"
        scoreCaptionLabel.text = scoreCaption(state, score)
        findingsValueLabel.text = state.findings.size.toString()
        filesValueLabel.text = state.pythonFileCount.toString()
        confirmedValueLabel.text = state.findings.count { it.validationStatus == ValidationStatus.CONFIRMED }.toString()

        Severity.entries.forEach { severity ->
            severityChips.getValue(severity).text = "${severity.displayName} ${state.findings.count { it.severity == severity }}"
        }

        updateProgress(state)
        updateGuidance(state)
    }

    private fun buildHeroPanel(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(14, 0)).apply {
            background = JBColor(Color(0xEFF6FF), Color(0x202A36))
            isOpaque = true
            border = JBUI.Borders.compound(
                JBUI.Borders.customLine(JBColor(Color(0xBFDBFE), Color(0x334155))),
                JBUI.Borders.empty(14, 16),
            )

            add(
                JBPanel<JBPanel<*>>(BorderLayout()).apply {
                    isOpaque = false
                    add(
                        JBLabel(AllIcons.General.Information).apply {
                            border = JBUI.Borders.emptyRight(8)
                        },
                        BorderLayout.WEST,
                    )
                    add(
                        JBPanel<JBPanel<*>>(BorderLayout(0, 4)).apply {
                            isOpaque = false
                            add(JBLabel("Project Posture").apply { font = font.deriveFont(Font.BOLD, 15f) }, BorderLayout.NORTH)
                            add(scoreCaptionLabel, BorderLayout.CENTER)
                        },
                        BorderLayout.CENTER,
                    )
                },
                BorderLayout.CENTER,
            )

            add(
                JBPanel<JBPanel<*>>(BorderLayout()).apply {
                    isOpaque = false
                    add(scoreValueLabel, BorderLayout.CENTER)
                    add(JBLabel("/ 100").apply { foreground = JBColor.GRAY }, BorderLayout.EAST)
                },
                BorderLayout.EAST,
            )

            add(
                JBPanel<JBPanel<*>>(GridLayout(1, 3, 10, 0)).apply {
                    isOpaque = false
                    add(createStatCard("Findings", findingsValueLabel))
                    add(createStatCard("Python files", filesValueLabel))
                    add(createStatCard("Confirmed", confirmedValueLabel))
                },
                BorderLayout.SOUTH,
            )
        }

    private fun buildProgressPanel(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 8)).apply {
            isOpaque = false
            add(severityChipPanel, BorderLayout.NORTH)
            add(
                JBPanel<JBPanel<*>>(BorderLayout(0, 6)).apply {
                    isOpaque = false
                    add(progressLabel, BorderLayout.NORTH)
                    add(progressBar, BorderLayout.CENTER)
                },
                BorderLayout.CENTER,
            )
        }

    private fun createStatCard(
        title: String,
        valueLabel: JBLabel,
    ): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 4)).apply {
            isOpaque = true
            background = JBColor(Color.WHITE, Color(0x27313D))
            border = JBUI.Borders.compound(
                JBUI.Borders.customLine(JBColor(Color(0xD7DDE5), Color(0x475569))),
                JBUI.Borders.empty(10),
            )
            add(JBLabel(title).apply { foreground = JBColor.GRAY }, BorderLayout.NORTH)
            add(valueLabel, BorderLayout.CENTER)
        }

    private fun createSeverityChip(severity: Severity): JBLabel =
        JBLabel("${severity.displayName} 0").apply {
            isOpaque = true
            border = JBUI.Borders.empty(5, 10)
            background = severityBackground(severity)
            foreground = severityForeground(severity)
            font = font.deriveFont(Font.BOLD, 12f)
        }

    private fun updateProgress(state: SecurityScanState) {
        when {
            state.isScanning -> {
                progressBar.isVisible = true
                progressBar.isIndeterminate = true
                progressBar.string = "Running Semgrep grounding"
                progressLabel.text = "Grounding findings with Semgrep across ${state.pythonFileCount} Python files."
            }

            state.isEnriching -> {
                val total = state.totalFindingsToEnrich.coerceAtLeast(1)
                val completed = state.enrichedFindingCount.coerceIn(0, total)
                val percentage = ((completed.toDouble() / total.toDouble()) * 100).toInt()
                progressBar.isVisible = true
                progressBar.isIndeterminate = false
                progressBar.value = percentage
                progressBar.string = "$completed / $total findings enriched"
                progressLabel.text = "Agent reasoning is validating, explaining, and preparing fixes."
            }

            else -> {
                progressBar.isVisible = false
                progressBar.isIndeterminate = false
                progressBar.value = 0
                progressBar.string = ""
                progressLabel.text = when {
                    state.lastScanFinishedAt != null -> "Ready. Select a finding to inspect details, fixes, or the follow-up chat."
                    else -> "Ready. Run a scan to populate the findings tree."
                }
            }
        }
    }

    private fun updateGuidance(state: SecurityScanState) {
        val guidance = when {
            state.lastScanError != null -> GuidanceMessage(
                icon = AllIcons.General.Error,
                text = state.lastScanError,
            )

            state.lastEnrichmentError != null -> GuidanceMessage(
                icon = AllIcons.General.Warning,
                text = "Some agent enrichment steps failed. Raw findings remain available and you can rescan after checking the API or model settings.",
            )

            state.enrichmentSkippedReason != null -> GuidanceMessage(
                icon = AllIcons.General.Information,
                text = state.enrichmentSkippedReason,
            )

            state.findings.isEmpty() && state.lastScanFinishedAt != null -> GuidanceMessage(
                icon = AllIcons.General.Information,
                text = "The latest scan did not report any Semgrep findings for the current Python sources.",
            )

            else -> null
        }

        if (guidance == null) {
            guidancePanel.isVisible = false
            guidanceLabel.text = ""
            return
        }

        guidancePanel.isVisible = true
        guidanceIconLabel.icon = guidance.icon
        guidanceLabel.text = "<html><body style='width: 620px;'>${guidance.text}</body></html>"
    }

    private fun reportableFindings(findings: List<Finding>): List<Finding> =
        findings.filter { it.validationStatus != ValidationStatus.DISMISSED }.ifEmpty { findings }

    private fun scoreCaption(
        state: SecurityScanState,
        score: Int?,
    ): String =
        when {
            state.isScanning -> "Semgrep grounding is running now."
            state.isEnriching -> "Static findings are being enriched with semantic reasoning."
            state.lastScanError != null -> "Scan needs attention before the score can be trusted."
            score == null -> "Run a scan to calculate project posture."
            score >= 90 -> "Strong posture for the current scan snapshot."
            score >= 75 -> "Mostly healthy posture with some actionable issues."
            score >= 55 -> "Noticeable risk concentration that should be addressed soon."
            else -> "High-risk posture. Prioritize fixes before the next demo run."
        }

    private fun createStatValueLabel(): JBLabel =
        JBLabel("0").apply {
            font = font.deriveFont(Font.BOLD, 18f)
        }

    private fun severityBackground(severity: Severity): JBColor =
        when (severity) {
            Severity.CRITICAL -> JBColor(Color(0xB71C1C), Color(0xB71C1C))
            Severity.HIGH -> JBColor(Color(0xBF360C), Color(0xBF360C))
            Severity.MEDIUM -> JBColor(Color(0xFBC02D), Color(0xFBC02D))
            Severity.LOW -> JBColor(Color(0x2E7D32), Color(0x2E7D32))
            Severity.INFO -> JBColor(Color(0x0288D1), Color(0x0288D1))
            Severity.UNKNOWN -> JBColor(Color(0x607D8B), Color(0x607D8B))
        }

    private fun severityForeground(severity: Severity): JBColor =
        when (severity) {
            Severity.MEDIUM -> JBColor(Color(0x1F1F1F), Color(0x1F1F1F))
            else -> JBColor(Color.WHITE, Color.WHITE)
        }

    private data class GuidanceMessage(
        val icon: javax.swing.Icon,
        val text: String,
    )
}
