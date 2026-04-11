package com.hackathon.securityagent.chat

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.openai.OpenAIClient
import com.hackathon.securityagent.openai.OpenAIClientException
import com.hackathon.securityagent.settings.SecurityAgentSettings
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project

@Service(Service.Level.PROJECT)
class FindingChatService(
    private val project: Project,
) {
    private val promptBuilder = FindingChatPromptBuilder()

    @Volatile
    private var threads: Map<String, FindingChatThreadState> = emptyMap()

    fun threadFor(findingId: String): FindingChatThreadState =
        threads[findingId] ?: FindingChatThreadState(findingId = findingId)

    @Synchronized
    fun sendMessage(
        finding: Finding,
        prompt: String,
    ): FindingChatRequestResult {
        val normalizedPrompt = prompt.trim()
        if (normalizedPrompt.isBlank()) {
            return FindingChatRequestResult.Rejected("Write a question before sending it.", isError = false)
        }

        val currentThread = threadFor(finding.id)
        if (currentThread.isStreaming) {
            return FindingChatRequestResult.Rejected("Wait for the current response to finish streaming.", isError = false)
        }

        val clientConfig = ApplicationManager.getApplication().getService(SecurityAgentSettings::class.java).toClientConfig()
            ?: return FindingChatRequestResult.Rejected(
                "Configure an OpenAI API key in Settings > Tools > Security Agent to enable follow-up chat.",
                isError = true,
            )

        val userMessage = FindingChatMessage(role = FindingChatRole.USER, content = normalizedPrompt)
        val assistantPlaceholder = FindingChatMessage(role = FindingChatRole.ASSISTANT, content = "")
        val pendingThread = currentThread.copy(
            messages = currentThread.messages + userMessage + assistantPlaceholder,
            isStreaming = true,
            lastError = null,
        )
        updateThread(pendingThread)

        val requestMessages = promptBuilder.buildMessages(
            finding = finding,
            history = pendingThread.messages.dropLast(1),
        )

        ApplicationManager.getApplication().executeOnPooledThread {
            val client = OpenAIClient(clientConfig)
            try {
                client.streamChatCompletion(
                    messages = requestMessages,
                    temperature = 0.2,
                    maxCompletionTokens = 700,
                ) { delta ->
                    appendAssistantDelta(finding.id, delta)
                }
                finishStreaming(finding.id)
            } catch (exception: OpenAIClientException) {
                failStreaming(finding.id, exception.message ?: "Unable to answer the follow-up question.")
            } catch (exception: RuntimeException) {
                failStreaming(finding.id, exception.message ?: "Unable to answer the follow-up question.")
            }
        }

        return FindingChatRequestResult.Started
    }

    @Synchronized
    private fun appendAssistantDelta(
        findingId: String,
        delta: String,
    ) {
        if (delta.isBlank()) {
            return
        }

        val existing = threadFor(findingId)
        val updatedMessages = existing.messages.toMutableList()
        val lastIndex = updatedMessages.lastIndex
        if (lastIndex < 0) {
            return
        }

        val assistantMessage = updatedMessages[lastIndex]
        updatedMessages[lastIndex] = assistantMessage.copy(content = assistantMessage.content + delta)
        updateThread(existing.copy(messages = updatedMessages))
    }

    @Synchronized
    private fun finishStreaming(findingId: String) {
        val existing = threadFor(findingId)
        updateThread(existing.copy(isStreaming = false, lastError = null))
    }

    @Synchronized
    private fun failStreaming(
        findingId: String,
        message: String,
    ) {
        val existing = threadFor(findingId)
        LOGGER.warn("Finding follow-up chat failed for $findingId: $message")
        val updatedMessages = existing.messages.toMutableList()
        if (updatedMessages.isNotEmpty() && updatedMessages.last().role == FindingChatRole.ASSISTANT) {
            updatedMessages[updatedMessages.lastIndex] = updatedMessages.last().copy(
                content = updatedMessages.last().content.ifBlank { "Unable to answer right now: $message" },
            )
        }

        updateThread(
            existing.copy(
                messages = updatedMessages,
                isStreaming = false,
                lastError = message,
            ),
        )
    }

    private fun updateThread(thread: FindingChatThreadState) {
        threads = threads.toMutableMap().apply { put(thread.findingId, thread) }
        project.messageBus.syncPublisher(FindingChatListener.TOPIC).threadUpdated(thread)
    }

    private companion object {
        private val LOGGER = Logger.getInstance(FindingChatService::class.java)
    }
}
