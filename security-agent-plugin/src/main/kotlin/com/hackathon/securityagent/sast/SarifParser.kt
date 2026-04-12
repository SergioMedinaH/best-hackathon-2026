package com.hackathon.securityagent.sast

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import java.nio.file.Path

class SarifParser(
    private val json: Json = Json,
) {
    fun parse(
        rawSarif: String,
        scanRoot: Path,
    ): List<Finding> {
        val normalizedScanRoot = scanRoot.toAbsolutePath().normalize()
        val root = json.parseToJsonElement(rawSarif).jsonObject

        return root.arrayValue("runs")
            .orEmpty()
            .flatMap { runElement ->
                val run = runElement.asObject() ?: return@flatMap emptyList()
                parseRun(run, normalizedScanRoot)
            }
            .sortedWith(
                compareByDescending<Finding> { it.severity.priority }
                    .thenBy { it.relativePath }
                    .thenBy { it.line },
            )
    }

    private fun parseRun(
        run: JsonObject,
        scanRoot: Path,
    ): List<Finding> {
        val rulesById = run.objectValue("tool")
            ?.objectValue("driver")
            ?.arrayValue("rules")
            .orEmpty()
            .mapNotNull { ruleElement ->
                val rule = ruleElement.asObject() ?: return@mapNotNull null
                rule.string("id")?.let { it to rule }
            }
            .toMap()

        return run.arrayValue("results")
            .orEmpty()
            .mapNotNull { resultElement ->
                val result = resultElement.asObject() ?: return@mapNotNull null
                parseFinding(result, rulesById, scanRoot)
            }
    }

    private fun parseFinding(
        result: JsonObject,
        rulesById: Map<String, JsonObject>,
        scanRoot: Path,
    ): Finding? {
        val ruleId = result.string("ruleId") ?: return null
        val rule = rulesById[ruleId]
        val physicalLocation = result.arrayValue("locations")
            ?.firstOrNull()
            ?.asObject()
            ?.objectValue("physicalLocation")
            ?: return null
        val artifactLocation = physicalLocation.objectValue("artifactLocation") ?: return null
        val region = physicalLocation.objectValue("region")
        val uri = artifactLocation.string("uri") ?: return null
        val absolutePath = resolvePath(scanRoot, uri)

        val message = result.objectValue("message")?.string("text")
            ?: result.objectValue("message")?.string("markdown")
            ?: rule?.objectValue("fullDescription")?.string("text")
            ?: rule?.objectValue("shortDescription")?.string("text")
            ?: ruleId
        val cweIds = extractCwes(rule)

        return Finding(
            ruleId = ruleId,
            severity = Severity.fromSarifLevel(
                level = result.string("level")
                    ?: rule?.objectValue("defaultConfiguration")?.string("level"),
                ruleId = ruleId,
                cweIds = cweIds,
            ),
            message = message.trim(),
            cweIds = cweIds,
            relativePath = relativeDisplayPath(scanRoot, absolutePath, uri),
            absolutePath = absolutePath,
            line = region?.int("startLine") ?: 1,
            column = region?.int("startColumn"),
        )
    }

    private fun extractCwes(rule: JsonObject?): List<String> =
        rule?.objectValue("properties")
            ?.stringArray("tags")
            .orEmpty()
            .filter { it.startsWith("CWE-", ignoreCase = true) }
            .distinct()

    private fun resolvePath(
        scanRoot: Path,
        uri: String,
    ): Path {
        val normalizedUri = uri.replace('\\', '/')
        val candidate = runCatching { Path.of(normalizedUri) }.getOrNull()

        return when {
            candidate == null -> scanRoot.resolve(normalizedUri).normalize()
            candidate.isAbsolute -> candidate.normalize()
            else -> scanRoot.resolve(candidate).normalize()
        }
    }

    private fun relativeDisplayPath(
        scanRoot: Path,
        absolutePath: Path,
        fallbackUri: String,
    ): String =
        if (absolutePath.startsWith(scanRoot)) {
            scanRoot.relativize(absolutePath).toString().replace('\\', '/')
        } else {
            fallbackUri.replace('\\', '/')
        }

    private fun JsonElement?.asObject(): JsonObject? = this as? JsonObject

    private fun JsonObject.objectValue(name: String): JsonObject? = this[name].asObject()

    private fun JsonObject.arrayValue(name: String): JsonArray? = this[name] as? JsonArray

    private fun JsonObject.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.int(name: String): Int? = string(name)?.toIntOrNull()

    private fun JsonObject.stringArray(name: String): List<String> =
        arrayValue(name)
            .orEmpty()
            .mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
}
