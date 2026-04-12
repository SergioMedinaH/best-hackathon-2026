package com.hackathon.securityagent.ui

import com.hackathon.securityagent.chat.FindingChatRequestResult
import com.hackathon.securityagent.chat.FindingChatThreadState
import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.services.SecurityScanState
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPanel
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Color
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BoxLayout
import javax.swing.SwingConstants

class FindingDetailPanel : JBPanel<FindingDetailPanel>(BorderLayout()) {
    private val cardLayout = CardLayout()
    private val contentPanel = JBPanel<JBPanel<*>>(cardLayout)

    private val emptyTitleLabel = JBLabel().apply {
        font = font.deriveFont(Font.BOLD, font.size2D + 2f)
    }
    private val emptyBodyLabel = JBLabel().apply {
        verticalAlignment = SwingConstants.TOP
    }

    private val titleLabel = JBLabel().apply {
        font = font.deriveFont(Font.BOLD, font.size2D + 3f)
    }
    private val severityLabel = JBLabel().apply {
        border = JBUI.Borders.empty(4, 10)
        isOpaque = true
    }
    private val locationValue = JBLabel()
    private val ruleValue = JBLabel()
    private val cweValue = JBLabel()
    private val validationValue = JBLabel()
    private val confidenceValue = JBLabel()
    private val owaspValue = JBLabel()

    private val messageArea = createReadOnlyArea()
    private val rationaleArea = createReadOnlyArea()
    private val explanationArea = createReadOnlyArea()
    private val exploitArea = createReadOnlyArea()
    private val fixArea = createReadOnlyArea()
    private val codeArea = createReadOnlyArea(monospaced = true)
    private val chatPanel = FindingChatPanel()

    var onSendChatMessage: ((Finding, String) -> FindingChatRequestResult)? = null
        set(value) {
            field = value
            chatPanel.onSendMessage = value
        }

    init {
        border = JBUI.Borders.empty(12)
        add(contentPanel, BorderLayout.CENTER)

        contentPanel.add(buildEmptyPanel(), EMPTY_CARD)
        contentPanel.add(buildDetailPanel(), DETAIL_CARD)
    }

    fun showFinding(
        finding: Finding,
        chatThreadState: FindingChatThreadState = FindingChatThreadState(finding.id),
    ) {
        titleLabel.text = finding.ruleId
        applySeverityStyle(finding.severity)
        locationValue.text = finding.locationDisplay
        ruleValue.text = finding.ruleId
        cweValue.text = if (finding.cweIds.isEmpty()) "Not provided" else finding.cweIds.joinToString()
        validationValue.text = finding.validationStatus.displayName
        confidenceValue.text = finding.confidence?.let { "$it%" } ?: "Pending"
        owaspValue.text = finding.owaspCategory ?: "Pending"

        messageArea.text = finding.message
        rationaleArea.text = finding.validationRationale ?: defaultRationale(finding)
        explanationArea.text = finding.narrativeExplanation ?: defaultNarrative(finding)
        exploitArea.text = finding.exploitChain ?: defaultExploitChain(finding)
        fixArea.text = finding.fixSummary ?: defaultFixSummary(finding)
        codeArea.text = finding.safeCodeExample ?: defaultSafeExample(finding)
        chatPanel.showFinding(finding, chatThreadState)

        resetCaretPositions()
        cardLayout.show(contentPanel, DETAIL_CARD)
    }

    fun updateChatThread(threadState: FindingChatThreadState) {
        chatPanel.updateThread(threadState)
    }

    fun showState(state: SecurityScanState) {
        val title: String
        val body: String

        when {
            state.isScanning -> {
                title = "Scanning project..."
                body = "Security Agent is running Semgrep across ${state.pythonFileCount} Python files."
            }

            state.isEnriching -> {
                title = "Agent analysis is enriching findings"
                body = "The tree already contains Semgrep findings. Select one to watch validation, exploit reasoning, and remediation details appear. Progress: ${state.enrichedFindingCount}/${state.totalFindingsToEnrich}."
            }

            state.lastScanError != null -> {
                title = "Last scan failed"
                body = state.lastScanError
            }

            state.findings.isEmpty() && state.lastScanFinishedAt != null -> {
                title = "No findings detected"
                body = "The latest scan finished successfully and did not report any Semgrep findings."
            }

            state.findings.isNotEmpty() -> {
                title = "Select a finding"
                body = buildString {
                    append("Choose a finding in the tree to inspect the file, line, CWE, validation status, exploit chain, and fix guidance.")
                    state.enrichmentSkippedReason?.let {
                        append(" Agent analysis was skipped: ")
                        append(it)
                    }
                }
            }

            else -> {
                title = "No scan yet"
                body = "Run a project scan to populate the findings tree."
            }
        }

        emptyTitleLabel.text = title
        emptyBodyLabel.text = "<html><body style='width: 320px;'>$body</body></html>"
        chatPanel.showNoFinding()
        cardLayout.show(contentPanel, EMPTY_CARD)
    }

    private fun buildEmptyPanel(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 10)).apply {
            add(emptyTitleLabel, BorderLayout.NORTH)
            add(emptyBodyLabel, BorderLayout.CENTER)
        }

    private fun buildDetailPanel(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 12)).apply {
            add(
                JBScrollPane(
                    JBPanel<JBPanel<*>>().apply {
                        layout = BoxLayout(this, BoxLayout.Y_AXIS)
                        add(buildHeaderPanel())
                        add(createSection("Semgrep Message", messageArea))
                        add(createSection("Validator Rationale", rationaleArea))
                        add(createSection("Narrative Explanation", explanationArea))
                        add(createSection("Exploit Chain", exploitArea))
                        add(createSection("Proposed Fix", fixArea))
                        add(createSection("Safe Code Example", codeArea))
                        add(chatPanel)
                    },
                ).apply {
                    border = JBUI.Borders.empty()
                    horizontalScrollBarPolicy = JBScrollPane.HORIZONTAL_SCROLLBAR_NEVER
                },
                BorderLayout.CENTER,
            )
        }

    private fun buildHeaderPanel(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 12)).apply {
            border = JBUI.Borders.emptyBottom(14)
            add(
                JBPanel<JBPanel<*>>(BorderLayout(8, 0)).apply {
                    add(titleLabel, BorderLayout.CENTER)
                    add(severityLabel, BorderLayout.EAST)
                },
                BorderLayout.NORTH,
            )
            add(buildMetadataPanel(), BorderLayout.CENTER)
        }

    private fun buildMetadataPanel(): JBPanel<*> =
        JBPanel<JBPanel<*>>(GridBagLayout()).apply {
            val constraints = GridBagConstraints().apply {
                anchor = GridBagConstraints.NORTHWEST
                insets = Insets(0, 0, 8, 12)
            }

            addMetadataRow(this, constraints, 0, "Location", locationValue)
            addMetadataRow(this, constraints, 1, "Rule", ruleValue)
            addMetadataRow(this, constraints, 2, "CWE", cweValue)
            addMetadataRow(this, constraints, 3, "Validation", validationValue)
            addMetadataRow(this, constraints, 4, "Confidence", confidenceValue)
            addMetadataRow(this, constraints, 5, "OWASP", owaspValue)
        }

    private fun createSection(
        title: String,
        textArea: JBTextArea,
    ): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 6)).apply {
            border = JBUI.Borders.emptyBottom(14)
            add(
                JBLabel(title).apply {
                    font = font.deriveFont(Font.BOLD)
                },
                BorderLayout.NORTH,
            )
            add(textArea, BorderLayout.CENTER)
        }

    private fun addMetadataRow(
        panel: JBPanel<*>,
        baseConstraints: GridBagConstraints,
        row: Int,
        label: String,
        value: JBLabel,
    ) {
        val labelConstraints = baseConstraints.clone() as GridBagConstraints
        labelConstraints.gridx = 0
        labelConstraints.gridy = row
        labelConstraints.weightx = 0.0
        panel.add(JBLabel("$label:"), labelConstraints)

        val valueConstraints = baseConstraints.clone() as GridBagConstraints
        valueConstraints.gridx = 1
        valueConstraints.gridy = row
        valueConstraints.weightx = 1.0
        valueConstraints.fill = GridBagConstraints.HORIZONTAL
        panel.add(value, valueConstraints)
    }

    private fun applySeverityStyle(severity: Severity) {
        severityLabel.text = severity.displayName
        severityLabel.background = UIColors.severityBackground(severity)
        severityLabel.foreground = UIColors.severityForeground(severity)
    }

    private fun resetCaretPositions() {
        listOf(messageArea, rationaleArea, explanationArea, exploitArea, fixArea, codeArea).forEach {
            it.caretPosition = 0
        }
    }

    private fun defaultRationale(finding: Finding): String =
        when (finding.validationStatus) {
            ValidationStatus.PENDING -> "Waiting for agent validation."
            ValidationStatus.ERROR -> finding.enrichmentError ?: "The agent pipeline failed before validation completed."
            ValidationStatus.DISMISSED -> "The triage pipeline marked this as likely noise."
            else -> "Validator rationale not available."
        }

    private fun defaultNarrative(finding: Finding): String =
        when (finding.validationStatus) {
            ValidationStatus.PENDING -> "Waiting for the agent to explain why this code path matters."
            ValidationStatus.DISMISSED -> "No narrative explanation because the finding was dismissed."
            ValidationStatus.ERROR -> "No explanation available because the agent pipeline failed."
            else -> "Narrative explanation not available."
        }

    private fun defaultExploitChain(finding: Finding): String =
        when (finding.validationStatus) {
            ValidationStatus.PENDING -> "Exploit chain will appear once the explainer agent finishes."
            ValidationStatus.DISMISSED -> "No exploit chain because the finding was dismissed."
            ValidationStatus.ERROR -> "No exploit chain available because the agent pipeline failed."
            else -> "Exploit chain not available."
        }

    private fun defaultFixSummary(finding: Finding): String =
        when (finding.validationStatus) {
            ValidationStatus.PENDING -> "Fix guidance will appear after validation and explanation complete."
            ValidationStatus.DISMISSED -> "No fix was generated because the finding was dismissed."
            ValidationStatus.ERROR -> "No fix available because the agent pipeline failed."
            else -> "Fix guidance not available."
        }

    private fun defaultSafeExample(finding: Finding): String =
        when (finding.validationStatus) {
            ValidationStatus.PENDING -> "Waiting for the fix generator."
            ValidationStatus.DISMISSED -> "No code example was generated because the finding was dismissed."
            ValidationStatus.ERROR -> "No code example available because the agent pipeline failed."
            else -> "No code example provided."
        }

    private companion object {
        private const val DETAIL_CARD = "detail"
        private const val EMPTY_CARD = "empty"

        private fun createReadOnlyArea(monospaced: Boolean = false): JBTextArea =
            JBTextArea().apply {
                isEditable = false
                lineWrap = !monospaced
                wrapStyleWord = !monospaced
                border = JBUI.Borders.compound(
                    JBUI.Borders.customLine(Color(0xD7DDE5)),
                    JBUI.Borders.empty(8),
                )
                background = UIColors.sectionBackground
                if (monospaced) {
                    font = Font(Font.MONOSPACED, Font.PLAIN, font.size)
                }
            }
    }
}

private object UIColors {
    val sectionBackground: JBColor = JBColor(Color(0xF7F9FC), Color(0x313335))

    fun severityBackground(severity: Severity): JBColor =
        when (severity) {
            Severity.CRITICAL -> JBColor(ColorPalette.CRITICAL_DARK, ColorPalette.CRITICAL)
            Severity.HIGH -> JBColor(ColorPalette.HIGH_DARK, ColorPalette.HIGH)
            Severity.MEDIUM -> JBColor(ColorPalette.MEDIUM_DARK, ColorPalette.MEDIUM)
            Severity.LOW -> JBColor(ColorPalette.LOW_DARK, ColorPalette.LOW)
            Severity.INFO -> JBColor(ColorPalette.INFO_DARK, ColorPalette.INFO)
            Severity.UNKNOWN -> JBColor(ColorPalette.UNKNOWN_DARK, ColorPalette.UNKNOWN)
        }

    fun severityForeground(severity: Severity): JBColor =
        when (severity) {
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
            -> JBColor(ColorPalette.DARK_TEXT, ColorPalette.DARK_TEXT)

            else -> JBColor(ColorPalette.LIGHT_TEXT, ColorPalette.LIGHT_TEXT)
        }
}

private object ColorPalette {
    val CRITICAL = Color(0xE53935)
    val CRITICAL_DARK = Color(0xB71C1C)
    val HIGH = Color(0xF4511E)
    val HIGH_DARK = Color(0xBF360C)
    val MEDIUM = Color(0xFDD835)
    val MEDIUM_DARK = Color(0xFBC02D)
    val LOW = Color(0x43A047)
    val LOW_DARK = Color(0x2E7D32)
    val INFO = Color(0x29B6F6)
    val INFO_DARK = Color(0x0288D1)
    val UNKNOWN = Color(0x90A4AE)
    val UNKNOWN_DARK = Color(0x607D8B)
    val LIGHT_TEXT = Color.WHITE
    val DARK_TEXT = Color(0x1F1F1F)
}
