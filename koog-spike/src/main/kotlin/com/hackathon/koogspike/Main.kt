package com.hackathon.koogspike

import ai.koog.agents.core.agent.AIAgent
import ai.koog.prompt.executor.clients.openai.OpenAIModels
import ai.koog.prompt.executor.llms.all.simpleOpenAIExecutor
import kotlinx.coroutines.runBlocking

/**
 * Phase-0 spike: prove that Koog 0.7.1 can:
 *   1. Connect to OpenAI with a real API key
 *   2. Run a single AIAgent
 *   3. Return a result we can read from Kotlin
 *
 * Tool registration is intentionally omitted in this first iteration —
 * de-risk the "Koog talks to OpenAI at all" question first, layer tools
 * on top once the baseline is green.
 *
 * If this works, the multi-agent pipeline in `agents/AgentCoordinator.kt`
 * for the real plugin is unblocked.
 *
 * If it does NOT work, plan B = LangChain4j (see plan: harmonic-greeting-deer.md).
 */
fun main() = runBlocking {
    val apiKey = System.getenv("OPENAI_API_KEY")
        ?: error("OPENAI_API_KEY not set — export it before running the spike.")

    val finding = """
        File: app.py, line 48
        Code: cur.execute(f"SELECT id FROM users WHERE name = '{username}' AND pw = '{password}'")
        SAST rule: python.lang.security.audit.formatted-sql-query
    """.trimIndent()

    println("=== Koog spike — input ===")
    println(finding)
    println()

    val agent = AIAgent(
        promptExecutor = simpleOpenAIExecutor(apiKey),
        systemPrompt = """
            You are a security triage assistant for a JetBrains IDE plugin.
            When the user shows you a SAST finding, respond with EXACTLY this format
            and nothing else:

            CWE: <id>
            SEVERITY: <Critical|High|Medium|Low>
            EXPLANATION: <one sentence explaining the exploit>
            FIX: <one sentence describing the safe replacement>
        """.trimIndent(),
        llmModel = OpenAIModels.Chat.GPT4o,
    )

    val result = agent.run("Triage this finding:\n$finding")

    println("=== Koog spike — output ===")
    println(result)
}
