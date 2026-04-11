package com.hackathon.securityagent.chat

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Path

class FindingChatPromptBuilderTest {
    private val builder = FindingChatPromptBuilder()

    @Test
    fun `buildMessages includes finding context and prior conversation`() {
        val finding = Finding(
            ruleId = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
            severity = Severity.HIGH,
            message = "shell=True allows command injection.",
            cweIds = listOf("CWE-78"),
            relativePath = "app.py",
            absolutePath = Path.of("C:/Users/sergi/Documents/Uni/Hackathon/demo-vulnerable-app/app.py"),
            line = 61,
            column = 5,
            validationStatus = ValidationStatus.CONFIRMED,
            confidence = 92,
            owaspCategory = "A03:2021 - Injection",
            validationRationale = "The validator confirmed attacker input reaches subprocess.check_output.",
            narrativeExplanation = "A malicious host value can alter the shell command.",
            exploitChain = "User input reaches shell=True without sanitization.",
            fixSummary = "Pass arguments as a list and disable shell invocation.",
            safeCodeExample = "subprocess.check_output([\"ping\", \"-n\", \"1\", host], shell=False)",
        )

        val messages = builder.buildMessages(
            finding = finding,
            history = listOf(
                FindingChatMessage(FindingChatRole.USER, "Why is this exploitable?"),
                FindingChatMessage(FindingChatRole.ASSISTANT, "Because attacker-controlled input reaches shell=True."),
            ),
        )

        assertEquals("system", messages.first().role)
        assertTrue(messages[1].content.contains("Selected finding context:"))
        assertTrue(messages[1].content.contains("shell=True allows command injection."))
        assertTrue(messages[1].content.contains("Relevant code context:"))
        assertEquals("Why is this exploitable?", messages[2].content)
        assertEquals("assistant", messages[3].role)
    }
}
