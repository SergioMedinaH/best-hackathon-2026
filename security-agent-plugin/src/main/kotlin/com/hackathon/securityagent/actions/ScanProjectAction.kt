package com.hackathon.securityagent.actions

import com.hackathon.securityagent.services.ScanRequestResult
import com.hackathon.securityagent.services.SecurityScanService
import com.hackathon.securityagent.ui.SecurityToolWindowFactory
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.components.service
import com.intellij.openapi.project.DumbAwareAction
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.wm.ToolWindowManager

class ScanProjectAction : DumbAwareAction() {
    init {
        templatePresentation.text = "Scan Project for Security Issues"
        templatePresentation.description = "Run Semgrep on the current project and log the findings"
    }

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(event: AnActionEvent) {
        val project = event.project
        event.presentation.isVisible = project != null
        event.presentation.isEnabled = project?.service<SecurityScanService>()?.currentState()?.let { !it.isScanning && !it.isEnriching } == true
    }

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        ToolWindowManager.getInstance(project).getToolWindow(SecurityToolWindowFactory.ID)?.show()

        when (val result = project.service<SecurityScanService>().requestProjectScan()) {
            ScanRequestResult.Started -> Unit
            is ScanRequestResult.Rejected -> {
                if (result.isError) {
                    Messages.showErrorDialog(project, result.message, TITLE)
                } else {
                    Messages.showInfoMessage(project, result.message, TITLE)
                }
            }
        }
    }

    companion object {
        private const val TITLE = "Security Agent"
    }
}
