package com.hackathon.securityagent.settings

import com.hackathon.securityagent.openai.OpenAIClientConfig
import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.passwordSafe.PasswordSafe
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

@Service(Service.Level.APP)
@State(
    name = "SecurityAgentSettings",
    storages = [Storage("security-agent-settings.xml")],
)
class SecurityAgentSettings : PersistentStateComponent<SecurityAgentSettings.State> {
    data class State(
        var chatModel: String = DEFAULT_CHAT_MODEL,
        var baseUrl: String = DEFAULT_BASE_URL,
    )

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    fun currentState(): State = state.copy()

    fun updateState(
        chatModel: String,
        baseUrl: String,
    ) {
        state.chatModel = chatModel.ifBlank { DEFAULT_CHAT_MODEL }
        state.baseUrl = normalizeBaseUrl(baseUrl)
    }

    fun getApiKey(): String? =
        PasswordSafe.instance.getPassword(CREDENTIAL_ATTRIBUTES)?.takeIf { it.isNotBlank() }

    fun setApiKey(apiKey: String) {
        val normalizedKey = apiKey.trim()
        PasswordSafe.instance.setPassword(CREDENTIAL_ATTRIBUTES, normalizedKey.ifBlank { null })
    }

    fun hasApiKey(): Boolean = !getApiKey().isNullOrBlank()

    fun toClientConfig(): OpenAIClientConfig? {
        val apiKey = getApiKey() ?: return null
        return OpenAIClientConfig(
            apiKey = apiKey,
            baseUrl = normalizeBaseUrl(state.baseUrl),
            model = state.chatModel.ifBlank { DEFAULT_CHAT_MODEL },
        )
    }

    private fun normalizeBaseUrl(baseUrl: String): String =
        baseUrl.trim().trimEnd('/').ifBlank { DEFAULT_BASE_URL }

    companion object {
        const val CONFIGURABLE_ID = "com.hackathon.securityagent.settings"
        const val DEFAULT_CHAT_MODEL = "gpt-4.1-mini"
        const val DEFAULT_BASE_URL = "https://api.openai.com/v1"
        private val CREDENTIAL_ATTRIBUTES = CredentialAttributes(
            generateServiceName("Security Agent", "OpenAI API Key"),
        )
    }
}
