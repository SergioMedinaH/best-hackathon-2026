package com.hackathon.securityagent.settings

import com.intellij.openapi.components.service
import com.intellij.openapi.options.ConfigurationException
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.options.SearchableConfigurable
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPanel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.Dimension
import java.net.URI
import javax.swing.JComponent

class SecurityAgentConfigurable : SearchableConfigurable, Configurable.NoScroll {
    private val settings = service<SecurityAgentSettings>()
    private var panel: SecurityAgentSettingsPanel? = null

    override fun getId(): String = SecurityAgentSettings.CONFIGURABLE_ID

    override fun getDisplayName(): String = "Security Agent"

    override fun createComponent(): JComponent {
        val currentPanel = panel ?: SecurityAgentSettingsPanel().also { panel = it }
        reset()
        return currentPanel.root
    }

    override fun isModified(): Boolean {
        val currentPanel = panel ?: return false
        val state = settings.currentState()

        return currentPanel.modelField.text.trim() != state.chatModel ||
            currentPanel.baseUrlField.text.trim().trimEnd('/') != state.baseUrl.trim().trimEnd('/') ||
            currentPanel.apiKeyField.password.concatToString() != (settings.getApiKey() ?: "")
    }

    override fun apply() {
        val currentPanel = panel ?: return
        validate(currentPanel)?.let { throw ConfigurationException(it.message) }

        settings.updateState(
            chatModel = currentPanel.modelField.text.trim(),
            baseUrl = currentPanel.baseUrlField.text.trim(),
        )
        settings.setApiKey(currentPanel.apiKeyField.password.concatToString())
        currentPanel.updateStoredKeyInfo(settings.hasApiKey())
    }

    override fun reset() {
        val currentPanel = panel ?: return
        val state = settings.currentState()
        currentPanel.modelField.text = state.chatModel
        currentPanel.baseUrlField.text = state.baseUrl
        currentPanel.apiKeyField.text = settings.getApiKey().orEmpty()
        currentPanel.updateStoredKeyInfo(settings.hasApiKey())
    }

    override fun disposeUIResources() {
        panel = null
    }

    private fun validate(panel: SecurityAgentSettingsPanel): ValidationInfo? {
        if (panel.modelField.text.trim().isBlank()) {
            return ValidationInfo("Model cannot be empty.", panel.modelField)
        }

        val baseUrl = panel.baseUrlField.text.trim()
        if (baseUrl.isBlank()) {
            return ValidationInfo("Base URL cannot be empty.", panel.baseUrlField)
        }

        val uri = runCatching { URI(baseUrl) }.getOrNull()
        if (uri == null || uri.scheme !in setOf("http", "https") || uri.host.isNullOrBlank()) {
            return ValidationInfo("Base URL must be a valid http(s) URL.", panel.baseUrlField)
        }

        val apiKey = panel.apiKeyField.password.concatToString().trim()
        if (apiKey.isBlank()) {
            return ValidationInfo("OpenAI API key cannot be empty.", panel.apiKeyField)
        }

        return null
    }
}

private class SecurityAgentSettingsPanel {
    val apiKeyField = JBPasswordField()
    val modelField = JBTextField()
    val baseUrlField = JBTextField()
    private val storageInfoLabel = JBLabel()

    val root: JComponent =
        JBPanel<JBPanel<*>>(BorderLayout()).apply {
            border = JBUI.Borders.empty(12)

            val form = FormBuilder.createFormBuilder()
                .addLabeledComponent("OpenAI API Key:", apiKeyField, 1, false)
                .addComponent(storageInfoLabel)
                .addLabeledComponent("Chat Model:", modelField, 1, false)
                .addLabeledComponent("Base URL:", baseUrlField, 1, false)
                .addComponent(
                    JBLabel(
                        "<html><body style='width: 420px;'>The API key is stored with IntelliJ Password Safe. " +
                            "These settings are used by <b>Ping OpenAI</b> now and by later agentic phases.</body></html>",
                    ),
                )
                .panel

            apiKeyField.preferredSize = Dimension(320, apiKeyField.preferredSize.height)
            modelField.emptyText.text = SecurityAgentSettings.DEFAULT_CHAT_MODEL
            baseUrlField.emptyText.text = SecurityAgentSettings.DEFAULT_BASE_URL

            add(form, BorderLayout.NORTH)
        }

    fun updateStoredKeyInfo(hasStoredKey: Boolean) {
        storageInfoLabel.text = if (hasStoredKey) {
            "API key is currently stored in Password Safe."
        } else {
            "No API key stored yet."
        }
    }
}
