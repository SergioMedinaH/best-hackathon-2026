package com.hackathon.securityagent.ui

import com.hackathon.securityagent.agents.KoogAgentRunner
import com.hackathon.securityagent.agents.ReportGeneratorAgent
import com.hackathon.securityagent.chat.FindingChatListener
import com.hackathon.securityagent.chat.FindingChatService
import com.hackathon.securityagent.report.SecurityReportGenerator
import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.services.ScanRequestResult
import com.hackathon.securityagent.services.SecurityScanListener
import com.hackathon.securityagent.services.SecurityScanService
import com.hackathon.securityagent.services.SecurityScanState
import com.hackathon.securityagent.settings.SecurityAgentSettings
import com.intellij.icons.AllIcons
import com.intellij.openapi.Disposable
import com.intellij.openapi.actionSystem.ActionManager
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.DefaultActionGroup
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.DumbAwareAction
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.ui.SimpleToolWindowPanel
import com.intellij.ui.JBSplitter
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPanel
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class SecurityToolWindowPanel(
    private val project: Project,
) : SimpleToolWindowPanel(true, true), Disposable {
    private val scanService = project.service<SecurityScanService>()
    private val chatService = project.service<FindingChatService>()
    private val findingsTreePanel = FindingsTreePanel(project)
    private val detailPanel = FindingDetailPanel()
    private val overviewPanel = SecurityOverviewPanel()
    private val statusLabel = JBLabel()
    private val rescanAction = RescanAction()
    private val exportReportAction = ExportReportAction()
    private val actionToolbar = ActionManager.getInstance().createActionToolbar(
        "SecurityAgentToolWindow",
        DefaultActionGroup(rescanAction, exportReportAction),
        true,
    )

    private var selectedFinding: Finding? = null

    init {
        border = JBUI.Borders.empty()
        actionToolbar.targetComponent = this
        setToolbar(buildToolbar())
        setContent(buildContent())

        detailPanel.onSendChatMessage = { finding, prompt ->
            chatService.sendMessage(finding, prompt)
        }

        findingsTreePanel.onFindingSelected = { finding ->
            selectedFinding = finding
            if (finding != null) {
                detailPanel.showFinding(finding, chatService.threadFor(finding.id))
            } else {
                detailPanel.showState(scanService.currentState())
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
                        detailPanel.updateChatThread(thread)
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
            add(actionToolbar.component, BorderLayout.WEST)
            add(statusLabel, BorderLayout.CENTER)
        }

    private fun buildContent(): JBPanel<*> =
        JBPanel<JBPanel<*>>(BorderLayout(0, 0)).apply {
            add(overviewPanel, BorderLayout.NORTH)
            add(
                JBSplitter(false, 0.36f).apply {
                    firstComponent = findingsTreePanel
                    secondComponent = detailPanel
                    dividerWidth = 2
                },
                BorderLayout.CENTER,
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
                detailPanel.showFinding(keptSelection, chatService.threadFor(keptSelection.id))
            }

            state.findings.isNotEmpty() -> {
                selectedFinding = findingsTreePanel.selectFirstFinding()
                selectedFinding?.let { finding ->
                    detailPanel.showFinding(finding, chatService.threadFor(finding.id))
                }
            }

            else -> {
                selectedFinding = null
                findingsTreePanel.clearSelection()
                detailPanel.showState(state)
            }
        }

        overviewPanel.updateState(state)
        statusLabel.text = formatStatus(state)
        actionToolbar.updateActionsImmediately()
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

    private inner class RescanAction : DumbAwareAction("Rescan", "Run Semgrep again on the current project", AllIcons.Actions.Refresh) {
        override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

        override fun update(event: AnActionEvent) {
            val currentState = scanService.currentState()
            event.presentation.isEnabled = !currentState.isScanning && !currentState.isEnriching
        }

        override fun actionPerformed(event: AnActionEvent) {
            when (val result = scanService.requestProjectScan()) {
                ScanRequestResult.Started -> Unit
                is ScanRequestResult.Rejected -> showRejectedScanMessage(result)
            }
        }
    }

    private inner class ExportReportAction : DumbAwareAction(
        "Export report",
        "Generate a Markdown and HTML security report for the current scan",
        AllIcons.Actions.MenuSaveall,
    ) {
        override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

        override fun update(event: AnActionEvent) {
            val currentState = scanService.currentState()
            event.presentation.isEnabled = currentState.findings.isNotEmpty() && !currentState.isScanning
        }

        override fun actionPerformed(event: AnActionEvent) {
            exportReport()
        }
    }

    private companion object {
        private const val TITLE = "Security Agent"
        private val TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")
    }
}
