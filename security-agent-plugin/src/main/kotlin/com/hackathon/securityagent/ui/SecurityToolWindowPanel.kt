package com.hackathon.securityagent.ui

import com.hackathon.securityagent.agents.KoogAgentRunner
import com.hackathon.securityagent.agents.ReportGeneratorAgent
import com.hackathon.securityagent.chat.FindingChatListener
import com.hackathon.securityagent.chat.FindingChatService
import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.report.SecurityReportGenerator
import com.hackathon.securityagent.services.ScanRequestResult
import com.hackathon.securityagent.services.SecurityScanListener
import com.hackathon.securityagent.services.SecurityScanService
import com.hackathon.securityagent.services.SecurityScanState
import com.hackathon.securityagent.settings.SecurityAgentSettings
import com.intellij.icons.AllIcons
import com.intellij.openapi.Disposable
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.ui.SimpleToolWindowPanel
import com.intellij.ui.JBColor
import com.intellij.ui.JBSplitter
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPanel
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.Icon
import javax.swing.JButton

class SecurityToolWindowPanel(
    private val project: Project,
) : SimpleToolWindowPanel(true, true), Disposable {
    private val scanService = project.service<SecurityScanService>()
    private val chatService = project.service<FindingChatService>()
    private val findingsTreePanel = FindingsTreePanel(project)
    private val detailPanel = FindingDetailPanel()
    private val chatPanel = FindingChatPanel()
    private val overviewPanel = SecurityOverviewPanel()
    private val statusLabel = JBLabel()
    private val scanButton = createToolbarButton(
        text = "Scan",
        icon = AllIcons.Actions.Refresh,
        background = JBColor(Color(0xDBEAFE), Color(0x1E3A5F)),
        foreground = JBColor(Color(0x1D4ED8), Color(0xBFDBFE)),
        hoverBackground = JBColor(Color(0xBFDBFE), Color(0x2563EB)),
    )
    private val reportButton = createToolbarButton(
        text = "Create Report",
        icon = AllIcons.Actions.MenuSaveall,
        background = JBColor(Color(0xDCFCE7), Color(0x1F5132)),
        foreground = JBColor(Color(0x166534), Color(0xBBF7D0)),
        hoverBackground = JBColor(Color(0xBBF7D0), Color(0x166534)),
    )
    private val chatToggleButton = createToolbarButton(
        text = "Open Chat",
        icon = AllIcons.General.Balloon,
        background = JBColor(Color(0xEDE9FE), Color(0x3B2B63)),
        foreground = JBColor(Color(0x6D28D9), Color(0xDDD6FE)),
        hoverBackground = JBColor(Color(0xDDD6FE), Color(0x4C1D95)),
    ).apply {
        isEnabled = false
    }
    private val chatDrawer = JBPanel<JBPanel<*>>(BorderLayout()).apply {
        isVisible = false
        preferredSize = Dimension(360, 0)
        minimumSize = Dimension(300, 0)
        border = JBUI.Borders.compound(
            JBUI.Borders.customLineLeft(JBColor(Color(0xD7DDE5), Color(0x4B5563))),
            JBUI.Borders.empty(10, 12, 10, 12),
        )
        add(chatPanel, BorderLayout.CENTER)
    }
    private var isChatOpen = false

    private var selectedFinding: Finding? = null

    init {
        border = JBUI.Borders.empty()
        setToolbar(buildToolbar())
        setContent(buildContent())

        scanButton.addActionListener {
            when (val result = scanService.requestProjectScan()) {
                ScanRequestResult.Started -> Unit
                is ScanRequestResult.Rejected -> showRejectedScanMessage(result)
            }
        }
        reportButton.addActionListener {
            exportReport()
        }
        chatToggleButton.addActionListener {
            toggleChatDrawer()
        }
        chatPanel.onSendMessage = { finding, prompt ->
            chatService.sendMessage(finding, prompt)
        }

        findingsTreePanel.onFindingSelected = { finding ->
            selectedFinding = finding
            if (finding != null) {
                detailPanel.showFinding(finding)
                chatPanel.showFinding(finding, chatService.threadFor(finding.id))
                chatToggleButton.isEnabled = true
            } else {
                detailPanel.showState(scanService.currentState())
                chatPanel.showNoFinding()
                chatToggleButton.isEnabled = false
                setChatOpen(false)
            }
        }

        project.messageBus.connect(this).subscribe(
            SecurityScanListener.TOPIC,
            SecurityScanListener { state ->
                ApplicationManager.getApplication().invokeLater {
                    applyState(state)
                }
            },
        )
        project.messageBus.connect(this).subscribe(
            FindingChatListener.TOPIC,
            FindingChatListener { thread ->
                ApplicationManager.getApplication().invokeLater {
                    if (thread.findingId == selectedFinding?.id) {
                        chatPanel.updateThread(thread)
                    }
                }
            },
        )

        applyState(scanService.currentState())
    }

    override fun dispose() = Unit

    private fun buildToolbar(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout()).apply {
            border = JBUI.Borders.compound(
                JBUI.Borders.customLineBottom(JBUI.CurrentTheme.CustomFrameDecorations.separatorForeground()),
                JBUI.Borders.empty(6, 8),
            )
            add(
                JBPanel<JBPanel<*>>(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
                    isOpaque = false
                    add(scanButton)
                    add(reportButton)
                },
                BorderLayout.WEST,
            )
            add(statusLabel, BorderLayout.CENTER)
        }

    private fun buildContent(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 0)).apply {
            add(overviewPanel, BorderLayout.NORTH)
            add(
                JBSplitter(false, 0.36f).apply {
                    firstComponent = findingsTreePanel
                    secondComponent = buildInspectorArea()
                    dividerWidth = 2
                },
                BorderLayout.CENTER,
            )
        }

    private fun buildInspectorArea(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 8)).apply {
            add(
                JBPanel<JBPanel<*>>(BorderLayout()).apply {
                    add(detailPanel, BorderLayout.CENTER)
                    add(chatDrawer, BorderLayout.EAST)
                },
                BorderLayout.CENTER,
            )
            add(
                JBPanel<JBPanel<*>>(FlowLayout(FlowLayout.RIGHT, 0, 0)).apply {
                    isOpaque = false
                    border = JBUI.Borders.empty(0, 0, 8, 0)
                    add(chatToggleButton)
                },
                BorderLayout.SOUTH,
            )
        }

    private fun applyState(state: SecurityScanState) {
        val previousSelection = selectedFinding
        findingsTreePanel.setFindings(state.findings)

        val keptSelection = previousSelection?.let { previous ->
            state.findings.firstOrNull { candidate ->
                candidate.absolutePath == previous.absolutePath &&
                    candidate.line == previous.line &&
                    candidate.column == previous.column &&
                    candidate.ruleId == previous.ruleId
            }
        }

        when {
            keptSelection != null && findingsTreePanel.selectFinding(keptSelection) -> {
                selectedFinding = keptSelection
                detailPanel.showFinding(keptSelection)
                chatPanel.showFinding(keptSelection, chatService.threadFor(keptSelection.id))
            }

            state.findings.isNotEmpty() -> {
                selectedFinding = findingsTreePanel.selectFirstFinding()
                selectedFinding?.let { finding ->
                    detailPanel.showFinding(finding)
                    chatPanel.showFinding(finding, chatService.threadFor(finding.id))
                }
            }

            else -> {
                selectedFinding = null
                findingsTreePanel.clearSelection()
                detailPanel.showState(state)
                chatPanel.showNoFinding()
                setChatOpen(false)
            }
        }

        overviewPanel.updateState(state)
        statusLabel.text = formatStatus(state)
        scanButton.isEnabled = !state.isScanning && !state.isEnriching
        reportButton.isEnabled = state.findings.isNotEmpty() && !state.isScanning
        chatToggleButton.isEnabled = selectedFinding != null
    }

    private fun formatStatus(state: SecurityScanState): String =
        when {
            state.isScanning -> "Scanning..."
            state.isEnriching -> "Agent analysis..."
            state.lastScanError != null -> "Scan needs attention"
            state.enrichmentSkippedReason != null && state.lastScanFinishedAt != null -> "Scan finished without agent enrichment"
            state.lastEnrichmentError != null && state.lastScanFinishedAt != null -> {
                val timestamp = TIME_FORMATTER.format(state.lastScanFinishedAt.atZone(ZoneId.systemDefault()))
                "Last scan at $timestamp with partial agent errors"
            }
            state.lastScanFinishedAt != null -> {
                val timestamp = TIME_FORMATTER.format(state.lastScanFinishedAt.atZone(ZoneId.systemDefault()))
                "Last scan at $timestamp"
            }

            else -> "Run a scan to populate the findings tree."
        }

    private fun showRejectedScanMessage(result: ScanRequestResult.Rejected) {
        if (result.isError) {
            Messages.showErrorDialog(project, result.message, TITLE)
        } else {
            Messages.showInfoMessage(project, result.message, TITLE)
        }
    }

    private fun exportReport() {
        val snapshot = scanService.currentState()
        if (snapshot.findings.isEmpty()) {
            Messages.showInfoMessage(project, "Run a scan before exporting a report.", TITLE)
            return
        }

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Export Security Report", true) {
                override fun run(indicator: ProgressIndicator) {
                    runCatching {
                        indicator.isIndeterminate = false
                        indicator.text = "Preparing security report"
                        indicator.fraction = 0.1

                        val narrative = generateNarrative(snapshot, indicator)
                        indicator.text = "Rendering markdown and HTML"
                        indicator.fraction = 0.75

                        val generator = SecurityReportGenerator(
                            projectName = project.name,
                            projectBasePath = project.basePath?.let { java.nio.file.Path.of(it) },
                        )
                        val document = generator.generate(snapshot, narrative)
                        val exported = generator.exportToProjectRoot(document)

                        indicator.text = "Security report exported"
                        indicator.fraction = 1.0

                        ApplicationManager.getApplication().invokeLater {
                            Messages.showInfoMessage(
                                project,
                                "Markdown: ${exported.markdownPath}\nHTML: ${exported.htmlPath}",
                                "Security report exported",
                            )
                        }
                    }.getOrElse { error ->
                        ApplicationManager.getApplication().invokeLater {
                            Messages.showErrorDialog(
                                project,
                                error.message ?: "Unable to export the security report.",
                                TITLE,
                            )
                        }
                    }
                }
            },
        )
    }

    private fun generateNarrative(
        snapshot: SecurityScanState,
        indicator: ProgressIndicator,
    ) = runCatching {
        val clientConfig = ApplicationManager.getApplication().getService(SecurityAgentSettings::class.java).toClientConfig()
            ?: return@runCatching null

        indicator.text = "Generating executive summary"
        indicator.fraction = 0.35

        ReportGeneratorAgent(
            KoogAgentRunner(
                apiKey = clientConfig.apiKey,
                baseUrl = clientConfig.baseUrl,
                modelName = clientConfig.model,
            ),
        ).generateNarrative(
            projectName = project.name,
            score = com.hackathon.securityagent.report.SecurityScoreCalculator.calculate(snapshot.findings),
            findings = snapshot.findings,
        )
    }.getOrNull()

    private fun toggleChatDrawer() {
        if (selectedFinding == null) {
            return
        }

        setChatOpen(!isChatOpen)
    }

    private fun setChatOpen(open: Boolean) {
        isChatOpen = open
        chatDrawer.isVisible = open
        chatToggleButton.text = if (open) "Close Chat" else "Open Chat"
        revalidate()
        repaint()
    }

    private companion object {
        private const val TITLE = "Security Agent"
        private val TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")

        private fun createToolbarButton(
            text: String,
            icon: Icon,
            background: JBColor,
            foreground: JBColor,
            hoverBackground: JBColor,
        ): JButton =
            JButton(text, icon).apply {
                isFocusPainted = false
                isOpaque = true
                border = JBUI.Borders.empty(8, 12)
                this.background = background
                this.foreground = foreground
                font = font.deriveFont(Font.BOLD, 12f)
                horizontalTextPosition = JButton.RIGHT
                iconTextGap = 6
                addMouseListener(
                    object : MouseAdapter() {
                        override fun mouseEntered(event: MouseEvent) {
                            if (isEnabled) {
                                this@apply.background = hoverBackground
                            }
                        }

                        override fun mouseExited(event: MouseEvent) {
                            this@apply.background = background
                        }
                    },
                )
            }
    }
}
