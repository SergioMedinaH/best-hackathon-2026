package com.hackathon.securityagent.agents

import kotlinx.serialization.json.Json

object StructuredJsonParser {
    @PublishedApi
    internal val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    fun extractJsonObject(raw: String): String {
        val trimmed = raw.trim()
        FENCED_JSON_PATTERN.find(trimmed)?.groupValues?.getOrNull(1)?.trim()?.let { fenced ->
            if (fenced.startsWith("{") && fenced.endsWith("}")) {
                return fenced
            }
        }

        val startIndex = trimmed.indexOf('{')
        val endIndex = trimmed.lastIndexOf('}')
        if (startIndex >= 0 && endIndex > startIndex) {
            return trimmed.substring(startIndex, endIndex + 1)
        }

        throw IllegalArgumentException("Agent response did not contain a JSON object.")
    }

    inline fun <reified T> parse(raw: String): T = json.decodeFromString(extractJsonObject(raw))

    private val FENCED_JSON_PATTERN = Regex("""```(?:json)?\s*(\{.*})\s*```""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
}
