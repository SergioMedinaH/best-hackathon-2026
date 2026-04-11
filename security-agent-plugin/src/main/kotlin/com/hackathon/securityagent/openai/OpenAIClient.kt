package com.hackathon.securityagent.openai

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.UUID

data class OpenAIClientConfig(
    val apiKey: String,
    val baseUrl: String,
    val model: String,
)

data class OpenAIChatResult(
    val text: String,
    val refusal: String? = null,
    val model: String,
    val requestId: String? = null,
    val usage: Usage? = null,
)

data class OpenAIStreamResult(
    val text: String,
    val model: String,
    val requestId: String? = null,
    val usage: Usage? = null,
)

class OpenAIClient(
    private val config: OpenAIClientConfig,
    private val httpClient: HttpClient = defaultHttpClient(),
    private val json: Json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        explicitNulls = false
    },
) {
    fun ping(): OpenAIChatResult =
        createChatCompletion(
            messages = listOf(
                ChatMessage("system", "You are a concise connectivity check for an IntelliJ plugin."),
                ChatMessage("user", "Reply in one short sentence confirming that Security Agent can reach OpenAI."),
            ),
            temperature = 0.2,
            maxCompletionTokens = 80,
        )

    fun createChatCompletion(
        messages: List<ChatMessage>,
        temperature: Double? = null,
        maxCompletionTokens: Int? = null,
    ): OpenAIChatResult {
        val request = ChatCompletionRequest(
            model = config.model,
            messages = messages,
            temperature = temperature,
            maxCompletionTokens = maxCompletionTokens,
            store = false,
        )

        val response = executeChatCompletion(request)
        return response.toChatResult()
    }

    fun createStructuredChatCompletion(
        messages: List<ChatMessage>,
        schemaName: String,
        schema: JsonObject,
        schemaDescription: String? = null,
        temperature: Double? = null,
        maxCompletionTokens: Int? = null,
    ): OpenAIChatResult {
        val request = ChatCompletionRequest(
            model = config.model,
            messages = messages,
            temperature = temperature,
            maxCompletionTokens = maxCompletionTokens,
            responseFormat = ResponseFormat.jsonSchema(
                name = schemaName,
                schema = schema,
                description = schemaDescription,
            ),
            store = false,
        )

        val response = executeChatCompletion(request)
        return response.toChatResult()
    }

    fun streamChatCompletion(
        messages: List<ChatMessage>,
        temperature: Double? = null,
        maxCompletionTokens: Int? = null,
        onDelta: (String) -> Unit,
    ): OpenAIStreamResult {
        val request = ChatCompletionRequest(
            model = config.model,
            messages = messages,
            temperature = temperature,
            maxCompletionTokens = maxCompletionTokens,
            stream = true,
            streamOptions = StreamOptions(includeUsage = true),
            store = false,
        )

        val payload = json.encodeToString(ChatCompletionRequest.serializer(), request)
        val httpRequest = buildRequest(
            path = "chat/completions",
            payload = payload,
            requestId = UUID.randomUUID().toString(),
        )

        try {
            val response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofInputStream())
            val requestId = response.headers().firstValue("x-request-id").orElse(null)

            if (!isSuccessful(response.statusCode())) {
                val rawBody = response.body().use { input -> String(input.readAllBytes(), StandardCharsets.UTF_8) }
                throw OpenAIClientException(formatErrorMessage(response.statusCode(), rawBody))
            }

            var lastChunk: ChatCompletionChunk? = null
            val accumulatedText = StringBuilder()
            response.body().bufferedReader(StandardCharsets.UTF_8).use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    val trimmed = line.trim()
                    if (!trimmed.startsWith("data:")) {
                        continue
                    }

                    val event = trimmed.removePrefix("data:").trim()
                    if (event == "[DONE]") {
                        break
                    }

                    val chunk = json.decodeFromString(ChatCompletionChunk.serializer(), event)
                    lastChunk = chunk
                    chunk.choices
                        .mapNotNull { choice -> extractText(choice.delta.content) }
                        .forEach { delta ->
                            accumulatedText.append(delta)
                            onDelta(delta)
                        }
                }
            }

            return OpenAIStreamResult(
                text = accumulatedText.toString(),
                model = lastChunk?.model ?: config.model,
                requestId = requestId,
                usage = lastChunk?.usage,
            )
        } catch (exception: IOException) {
            throw OpenAIClientException("Failed to reach OpenAI: ${exception.message}", exception)
        } catch (exception: InterruptedException) {
            Thread.currentThread().interrupt()
            throw OpenAIClientException("OpenAI request was interrupted.", exception)
        }
    }

    private fun executeChatCompletion(request: ChatCompletionRequest): ChatCompletionResponse {
        val payload = json.encodeToString(ChatCompletionRequest.serializer(), request)
        val httpRequest = buildRequest(
            path = "chat/completions",
            payload = payload,
            requestId = UUID.randomUUID().toString(),
        )

        try {
            val response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
            val rawBody = response.body()
            if (!isSuccessful(response.statusCode())) {
                throw OpenAIClientException(formatErrorMessage(response.statusCode(), rawBody))
            }

            val completionResponse = json.decodeFromString(ChatCompletionResponse.serializer(), rawBody)
            return completionResponse.copy(requestId = response.headers().firstValue("x-request-id").orElse(null))
        } catch (exception: IOException) {
            throw OpenAIClientException("Failed to reach OpenAI: ${exception.message}", exception)
        } catch (exception: InterruptedException) {
            Thread.currentThread().interrupt()
            throw OpenAIClientException("OpenAI request was interrupted.", exception)
        }
    }

    private fun buildRequest(
        path: String,
        payload: String,
        requestId: String,
    ): HttpRequest =
        HttpRequest.newBuilder()
            .uri(URI.create("${config.baseUrl.trimEnd('/')}/$path"))
            .timeout(REQUEST_TIMEOUT)
            .header("Authorization", "Bearer ${config.apiKey}")
            .header("Content-Type", JSON_MEDIA_TYPE)
            .header("X-Request-Id", requestId)
            .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
            .build()

    private fun ChatCompletionResponse.toChatResult(): OpenAIChatResult {
        val firstChoice = choices.firstOrNull()
            ?: throw OpenAIClientException("OpenAI returned no choices.")
        val message = firstChoice.message

        return OpenAIChatResult(
            text = extractText(message.content).orEmpty(),
            refusal = message.refusal,
            model = model,
            requestId = requestId,
            usage = usage,
        )
    }

    private fun formatErrorMessage(
        code: Int,
        rawBody: String,
    ): String {
        val apiMessage = runCatching {
            json.decodeFromString(OpenAIErrorEnvelope.serializer(), rawBody).error.message
        }.getOrNull()

        return if (!apiMessage.isNullOrBlank()) {
            "OpenAI request failed ($code): $apiMessage"
        } else {
            "OpenAI request failed ($code)."
        }
    }

    private fun extractText(content: JsonElement?): String? =
        when (content) {
            null,
            JsonNull,
            -> null

            is JsonPrimitive -> content.contentOrNull
            is JsonArray -> content.joinToString(separator = "") { item ->
                when (item) {
                    is JsonPrimitive -> item.contentOrNull.orEmpty()
                    is JsonObject -> item["text"]?.jsonPrimitive?.contentOrNull.orEmpty()
                    else -> ""
                }
            }.ifBlank { null }

            is JsonObject -> content["text"]?.jsonPrimitive?.contentOrNull
        }

    companion object {
        private const val JSON_MEDIA_TYPE = "application/json; charset=utf-8"
        private val REQUEST_TIMEOUT: Duration = Duration.ofSeconds(90)

        fun defaultHttpClient(): HttpClient =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .build()

        private fun isSuccessful(statusCode: Int): Boolean = statusCode in 200..299
    }
}

class OpenAIClientException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

@Serializable
data class ChatCompletionRequest(
    val model: String,
    val messages: List<ChatMessage>,
    val temperature: Double? = null,
    @SerialName("max_completion_tokens")
    val maxCompletionTokens: Int? = null,
    @SerialName("response_format")
    val responseFormat: ResponseFormat? = null,
    val stream: Boolean = false,
    @SerialName("stream_options")
    val streamOptions: StreamOptions? = null,
    val store: Boolean = false,
)

@Serializable
data class ChatMessage(
    val role: String,
    val content: String,
)

@Serializable
data class ResponseFormat(
    val type: String,
    @SerialName("json_schema")
    val jsonSchema: JsonSchemaDefinition? = null,
) {
    companion object {
        fun jsonSchema(
            name: String,
            schema: JsonObject,
            description: String? = null,
            strict: Boolean = true,
        ): ResponseFormat =
            ResponseFormat(
                type = "json_schema",
                jsonSchema = JsonSchemaDefinition(
                    name = name,
                    description = description,
                    schema = schema,
                    strict = strict,
                ),
            )
    }
}

@Serializable
data class JsonSchemaDefinition(
    val name: String,
    val description: String? = null,
    val schema: JsonObject,
    val strict: Boolean = true,
)

@Serializable
data class StreamOptions(
    @SerialName("include_usage")
    val includeUsage: Boolean = true,
)

@Serializable
data class ChatCompletionResponse(
    val id: String,
    val model: String,
    val choices: List<ChatChoice>,
    val usage: Usage? = null,
    val requestId: String? = null,
)

@Serializable
data class ChatChoice(
    val index: Int,
    val message: ChatCompletionMessage,
    @SerialName("finish_reason")
    val finishReason: String? = null,
)

@Serializable
data class ChatCompletionMessage(
    val role: String? = null,
    val content: JsonElement? = null,
    val refusal: String? = null,
)

@Serializable
data class ChatCompletionChunk(
    val id: String,
    val model: String,
    val choices: List<ChatChunkChoice> = emptyList(),
    val usage: Usage? = null,
)

@Serializable
data class ChatChunkChoice(
    val index: Int,
    val delta: ChatChunkDelta = ChatChunkDelta(),
    @SerialName("finish_reason")
    val finishReason: String? = null,
)

@Serializable
data class ChatChunkDelta(
    val role: String? = null,
    val content: JsonElement? = null,
)

@Serializable
data class Usage(
    @SerialName("prompt_tokens")
    val promptTokens: Int? = null,
    @SerialName("completion_tokens")
    val completionTokens: Int? = null,
    @SerialName("total_tokens")
    val totalTokens: Int? = null,
)

@Serializable
private data class OpenAIErrorEnvelope(
    val error: OpenAIError,
)

@Serializable
private data class OpenAIError(
    val message: String,
)

fun exampleFindingSchema(): JsonObject =
    buildJsonObject {
        put("type", JsonPrimitive("object"))
        put(
            "properties",
            buildJsonObject {
                put(
                    "severity",
                    buildJsonObject {
                        put("type", JsonPrimitive("string"))
                    },
                )
                put(
                    "explanation",
                    buildJsonObject {
                        put("type", JsonPrimitive("string"))
                    },
                )
            },
        )
        put(
            "required",
            JsonArray(listOf(JsonPrimitive("severity"), JsonPrimitive("explanation"))),
        )
        put("additionalProperties", JsonPrimitive(false))
    }
