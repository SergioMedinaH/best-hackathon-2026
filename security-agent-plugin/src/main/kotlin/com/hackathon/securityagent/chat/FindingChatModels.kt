package com.hackathon.securityagent.chat

import com.intellij.util.messages.Topic
import java.time.Instant

enum class FindingChatRole(
    val displayName: String,
    val openAIRole: String,
) {
    USER("You", "user"),
    ASSISTANT("Security Agent", "assistant"),
}

data class FindingChatMessage(
    val role: FindingChatRole,
    val content: String,
    val createdAt: Instant = Instant.now(),
)

data class FindingChatThreadState(
    val findingId: String,
    val messages: List<FindingChatMessage> = emptyList(),
    val isStreaming: Boolean = false,
    val lastError: String? = null,
)

sealed interface FindingChatRequestResult {
    data object Started : FindingChatRequestResult

    data class Rejected(
        val message: String,
        val isError: Boolean,
    ) : FindingChatRequestResult
}

fun interface FindingChatListener {
    fun threadUpdated(state: FindingChatThreadState)

    companion object {
        val TOPIC: Topic<FindingChatListener> = Topic.create(
            "Security Agent Finding Chat Updates",
            FindingChatListener::class.java,
        )
    }
}
