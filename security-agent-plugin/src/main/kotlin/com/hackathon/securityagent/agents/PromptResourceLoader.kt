package com.hackathon.securityagent.agents

import java.nio.charset.StandardCharsets

class PromptResourceLoader(
    private val classLoader: ClassLoader = PromptResourceLoader::class.java.classLoader,
) {
    fun load(path: String): String =
        classLoader.getResourceAsStream(path)?.use { inputStream ->
            inputStream.bufferedReader(StandardCharsets.UTF_8).readText()
        } ?: error("Resource not found: $path")
}
