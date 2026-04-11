package com.hackathon.securityagent.agents

import ai.koog.agents.core.agent.AIAgent
import ai.koog.prompt.executor.llms.all.simpleOpenAIExecutor
import com.hackathon.securityagent.openai.ChatMessage
import com.hackathon.securityagent.openai.OpenAIClient
import com.hackathon.securityagent.openai.OpenAIClientConfig
import com.intellij.openapi.diagnostic.Logger
import kotlinx.coroutines.runBlocking

class KoogAgentRunner(
    private val apiKey: String,
    private val baseUrl: String,
    private val modelName: String,
    private val promptLoader: PromptResourceLoader = PromptResourceLoader(),
) {
    @Volatile
    private var directFallbackEnabled = false
    @Volatile
    private var koogCompatibilityChecked = false

    private val openAIClient: OpenAIClient by lazy {
        OpenAIClient(
            OpenAIClientConfig(
                apiKey = apiKey,
                baseUrl = baseUrl,
                model = modelName,
            ),
        )
    }

    fun run(
        systemPromptPath: String,
        userPrompt: String,
    ): String {
        val systemPrompt = promptLoader.load(systemPromptPath)

        ensureCompatibleRuntimeOrEnableFallback()

        if (directFallbackEnabled) {
            return runWithDirectOpenAI(systemPrompt, userPrompt)
        }

        return try {
            runWithKoog(systemPrompt, userPrompt)
        } catch (throwable: Throwable) {
            if (throwable is VirtualMachineError) {
                throw throwable
            }

            directFallbackEnabled = true
            logFallback(throwable)
            runWithDirectOpenAI(systemPrompt, userPrompt)
        }
    }

    private fun runWithKoog(
        systemPrompt: String,
        userPrompt: String,
    ): String =
        runBlocking {
            val agent = AIAgent(
                promptExecutor = simpleOpenAIExecutor(apiKey),
                systemPrompt = systemPrompt,
                llmModel = KoogModelResolver.resolve(modelName),
            )
            agent.run(userPrompt)
        }

    private fun runWithDirectOpenAI(
        systemPrompt: String,
        userPrompt: String,
    ): String =
        openAIClient.createChatCompletion(
            messages = listOf(
                ChatMessage("system", systemPrompt),
                ChatMessage("user", userPrompt),
            ),
            temperature = 0.1,
            maxCompletionTokens = 900,
        ).text

    private fun ensureCompatibleRuntimeOrEnableFallback() {
        if (koogCompatibilityChecked) {
            return
        }

        synchronized(this) {
            if (koogCompatibilityChecked) {
                return
            }

            val hasRequiredDurationMethod = runCatching {
                Class.forName("kotlin.time.Duration\$Companion")
                    .declaredMethods
                    .any { it.name.startsWith("fromRawValue-") }
            }.getOrDefault(false)

            if (!hasRequiredDurationMethod) {
                directFallbackEnabled = true
                logFallback(
                    "Koog is incompatible with the Kotlin runtime bundled in this IDE sandbox. " +
                        "Falling back to the direct OpenAI client.",
                )
            }

            koogCompatibilityChecked = true
        }
    }

    private fun logFallback(throwable: Throwable) {
        val message =
            "Koog runtime failed inside the IDE sandbox (${throwable::class.simpleName}: ${throwable.message}). " +
                "Falling back to the direct OpenAI client for this scan."
        LOGGER.warn(message, throwable)
        println("[SecurityAgent] $message")
    }

    private fun logFallback(message: String) {
        LOGGER.warn(message)
        println("[SecurityAgent] $message")
    }

    private companion object {
        private val LOGGER = Logger.getInstance(KoogAgentRunner::class.java)
    }
}
