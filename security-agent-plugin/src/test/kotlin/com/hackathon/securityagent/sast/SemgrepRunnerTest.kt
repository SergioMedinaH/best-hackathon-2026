package com.hackathon.securityagent.sast

import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Path

class SemgrepRunnerTest {
    @Test
    fun `builds command with explicit filtered file targets`() {
        val runner = SemgrepRunner()
        val scanRoot = Path.of("C:/Users/sergi/Documents/Uni/Hackathon/demo-vulnerable-app")
        val appFile = scanRoot.resolve("app.py")
        val tempSarif = Path.of("C:/Temp/security-agent-semgrep-test.sarif")

        val command = runner.buildScanCommand(
            scanRoot = scanRoot,
            resolvedTarget = scanRoot,
            sarifOutputFile = tempSarif,
            includedPaths = listOf(appFile),
        )

        assertTrue(command.contains("app.py"))
        assertTrue(command.none { it.contains(".venv", ignoreCase = true) })
    }
}
