package com.hackathon.securityagent.agents

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

class GroundingRepository(
    private val resourceLoader: PromptResourceLoader = PromptResourceLoader(),
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    private val cweEntries: Map<String, CweEntry> by lazy {
        json.decodeFromString<List<CweEntry>>(resourceLoader.load("grounding/cwe.json"))
            .associateBy { it.id.uppercase() }
    }

    private val owaspEntries: List<OwaspEntry> by lazy {
        json.decodeFromString(resourceLoader.load("grounding/owasp-top10.json"))
    }

    fun formatCweContext(cweIds: List<String>): String {
        val entries = cweIds
            .map { it.uppercase() }
            .mapNotNull(cweEntries::get)

        if (entries.isEmpty()) {
            return "No curated CWE grounding matched the current finding."
        }

        return entries.joinToString(separator = "\n") { entry ->
            "- ${entry.id}: ${entry.name}. ${entry.summary} OWASP mapping: ${entry.owasp}"
        }
    }

    fun formatOwaspContext(): String =
        owaspEntries.joinToString(separator = "\n") { entry ->
            "- ${entry.id}: ${entry.name}. ${entry.summary}"
        }
}

@Serializable
private data class CweEntry(
    val id: String,
    val name: String,
    val summary: String,
    val owasp: String,
)

@Serializable
private data class OwaspEntry(
    val id: String,
    val name: String,
    @SerialName("summary")
    val description: String,
) {
    val summary: String
        get() = description
}
