package com.hackathon.securityagent.openai

import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class OpenAIClientTest {
    private val json = Json { ignoreUnknownKeys = true }
    private lateinit var server: TestHttpServer

    @Before
    fun setUp() {
        server = TestHttpServer()
    }

    @After
    fun tearDown() {
        if (::server.isInitialized) {
            server.stop()
        }
    }

    @Test
    fun `createChatCompletion sends auth header and parses response`() {
        server.enqueue(
            QueuedResponse(
                headers = mapOf(
                    "Content-Type" to "application/json",
                    "x-request-id" to "req_123",
                ),
                body =
                    """
                    {
                      "id": "chatcmpl_123",
                      "model": "gpt-4.1-mini",
                      "choices": [
                        {
                          "index": 0,
                          "message": {
                            "role": "assistant",
                            "content": "Security Agent reached OpenAI successfully."
                          },
                          "finish_reason": "stop"
                        }
                      ],
                      "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 8,
                        "total_tokens": 18
                      }
                    }
                    """.trimIndent(),
            ),
        )

        val client = createClient()
        val result = client.createChatCompletion(
            messages = listOf(ChatMessage("user", "ping")),
            temperature = 0.1,
        )

        val request = server.takeRequest()
        val body = json.parseToJsonElement(request.body).jsonObject

        assertEquals("/v1/chat/completions", request.path)
        assertEquals("Bearer sk-test", request.header("Authorization"))
        assertEquals("gpt-4.1-mini", body["model"]?.jsonPrimitive?.content)
        assertEquals("false", body["store"]?.jsonPrimitive?.content)
        assertEquals("Security Agent reached OpenAI successfully.", result.text)
        assertEquals("req_123", result.requestId)
        assertEquals(18, result.usage?.totalTokens)
    }

    @Test
    fun `createStructuredChatCompletion sends strict json schema response format`() {
        server.enqueue(
            QueuedResponse(
                headers = mapOf("Content-Type" to "application/json"),
                body =
                    """
                    {
                      "id": "chatcmpl_structured",
                      "model": "gpt-4.1-mini",
                      "choices": [
                        {
                          "index": 0,
                          "message": {
                            "role": "assistant",
                            "content": "{\"severity\":\"High\",\"explanation\":\"SQL injection confirmed.\"}"
                          },
                          "finish_reason": "stop"
                        }
                      ]
                    }
                    """.trimIndent(),
            ),
        )

        val client = createClient()
        client.createStructuredChatCompletion(
            messages = listOf(ChatMessage("user", "triage this finding")),
            schemaName = "security_finding",
            schema = exampleFindingSchema(),
            schemaDescription = "Structured security finding",
        )

        val request = server.takeRequest()
        val body = json.parseToJsonElement(request.body).jsonObject
        val responseFormat = body["response_format"]!!.jsonObject
        val jsonSchema = responseFormat["json_schema"]!!.jsonObject

        assertEquals("json_schema", responseFormat["type"]?.jsonPrimitive?.content)
        assertEquals("security_finding", jsonSchema["name"]?.jsonPrimitive?.content)
        assertEquals("true", jsonSchema["strict"]?.jsonPrimitive?.content)
        assertTrue(jsonSchema["schema"]!!.jsonObject.containsKey("properties"))
    }

    @Test
    fun `streamChatCompletion accumulates deltas`() {
        server.enqueue(
            QueuedResponse(
                headers = mapOf("Content-Type" to "text/event-stream"),
                body =
                    """
                    data: {"id":"chunk_1","model":"gpt-4.1-mini","choices":[{"index":0,"delta":{"content":"Hello"}}]}

                    data: {"id":"chunk_2","model":"gpt-4.1-mini","choices":[{"index":0,"delta":{"content":" world"}}],"usage":{"total_tokens":12}}

                    data: [DONE]
                    """.trimIndent(),
            ),
        )

        val deltas = mutableListOf<String>()
        val client = createClient()
        val result = client.streamChatCompletion(
            messages = listOf(ChatMessage("user", "hello")),
            onDelta = deltas::add,
        )

        val request = server.takeRequest()
        val body = json.parseToJsonElement(request.body).jsonObject

        assertEquals("true", body["stream"]?.jsonPrimitive?.content)
        assertEquals("Hello world", result.text)
        assertEquals(listOf("Hello", " world"), deltas)
        assertEquals(12, result.usage?.totalTokens)
    }

    private fun createClient(): OpenAIClient =
        OpenAIClient(
            OpenAIClientConfig(
                apiKey = "sk-test",
                baseUrl = server.baseUrl(),
                model = "gpt-4.1-mini",
            ),
        )
}

private class TestHttpServer {
    private val responses = LinkedBlockingQueue<QueuedResponse>()
    private val requests = LinkedBlockingQueue<CapturedRequest>()
    private val server: HttpServer =
        HttpServer.create(InetSocketAddress(0), 0).apply {
            createContext("/v1/chat/completions") { exchange ->
                val requestBody = exchange.requestBody.use { input -> String(input.readAllBytes(), StandardCharsets.UTF_8) }
                requests.put(
                    CapturedRequest(
                        path = exchange.requestURI.path,
                        headers = exchange.requestHeaders.toMapValues(),
                        body = requestBody,
                    ),
                )

                val response = responses.poll(5, TimeUnit.SECONDS)
                    ?: error("No queued response available for test server.")
                response.headers.forEach { (name, value) ->
                    exchange.responseHeaders.add(name, value)
                }
                val bytes = response.body.toByteArray(StandardCharsets.UTF_8)
                exchange.sendResponseHeaders(response.statusCode, bytes.size.toLong())
                exchange.responseBody.use { output ->
                    output.write(bytes)
                }
            }
            start()
        }

    fun enqueue(response: QueuedResponse) {
        responses.put(response)
    }

    fun takeRequest(): CapturedRequest =
        requests.poll(5, TimeUnit.SECONDS) ?: error("No request captured by the test server.")

    fun baseUrl(): String = "http://127.0.0.1:${server.address.port}/v1"

    fun stop() {
        server.stop(0)
    }
}

private data class QueuedResponse(
    val statusCode: Int = 200,
    val headers: Map<String, String> = emptyMap(),
    val body: String,
)

private data class CapturedRequest(
    val path: String,
    val headers: Map<String, List<String>>,
    val body: String,
) {
    fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()
}

private fun com.sun.net.httpserver.Headers.toMapValues(): Map<String, List<String>> =
    entries.associate { it.key to it.value.toList() }
