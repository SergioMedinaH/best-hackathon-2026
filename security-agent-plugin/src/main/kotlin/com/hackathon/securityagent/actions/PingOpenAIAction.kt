package com.hackathon.securityagent.actions

import com.hackathon.securityagent.openai.OpenAIClient
import com.hackathon.securityagent.openai.OpenAIClientException
import com.hackathon.securityagent.settings.SecurityAgentConfigurable
import com.hackathon.securityagent.settings.SecurityAgentSettings
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.options.ShowSettingsUtil
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.DumbAwareAction
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages

class PingOpenAIAction : DumbAwareAction() {
    init {
        templatePresentation.text = "Ping OpenAI"
        templatePresentation.description = "Validate the stored API key and make a real OpenAI request"
    }

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(event: AnActionEvent) {
        event.presentation.isEnabledAndVisible = event.project != null
    }

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val settings = service<SecurityAgentSettings>()
        val config = settings.toClientConfig()

        if (config == null) {
            val openSettings = Messages.showYesNoDialog(
                project,
                "No OpenAI API key is configured yet. Open Security Agent settings now?",
                TITLE,
                "Open Settings",
                "Cancel",
                Messages.getWarningIcon(),
            )
            if (openSettings == Messages.YES) {
                ShowSettingsUtil.getInstance().showSettingsDialog(project, SecurityAgentConfigurable::class.java)
            }
            return
        }

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Ping OpenAI", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    indicator.text = "Sending connectivity check to OpenAI"

                    try {
                        val result = OpenAIClient(config).ping()
                        ApplicationManager.getApplication().invokeLater {
                            val body = buildString {
                                append(result.text.ifBlank { "(OpenAI returned an empty message.)" })
                                result.requestId?.let {
                                    append("\n\nRequest ID: ")
                                    append(it)
                                }
                                result.usage?.totalTokens?.let {
                                    append("\nTokens: ")
                                    append(it)
                                }
                            }
                            Messages.showInfoMessage(project, body, TITLE)
                        }
                    } catch (exception: OpenAIClientException) {
                        ApplicationManager.getApplication().invokeLater {
                            Messages.showErrorDialog(project, exception.message ?: "OpenAI request failed.", TITLE)
                        }
                    }
                }
            },
        )
    }

    private companion object {
        private const val TITLE = "Security Agent"
    }
}
