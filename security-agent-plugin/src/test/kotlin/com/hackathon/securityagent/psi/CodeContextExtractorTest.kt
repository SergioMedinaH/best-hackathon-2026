package com.hackathon.securityagent.psi

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.nio.file.Files

class CodeContextExtractorTest {
    @Test
    fun `extracts imports enclosing symbol and focused snippet`() {
        val tempFile = Files.createTempFile("security-agent-context-", ".py")
        Files.writeString(
            tempFile,
            """
            import sqlite3
            from flask import request

            def list_users(username):
                cursor = sqlite3.connect("demo.db").cursor()
                query = f"SELECT * FROM users WHERE name = '{username}'"
                return cursor.execute(query).fetchall()
            """.trimIndent(),
            StandardCharsets.UTF_8,
        )

        try {
            val finding = Finding(
                ruleId = "python.lang.security.audit.formatted-sql-query",
                severity = Severity.HIGH,
                message = "Possible SQL injection through string formatting.",
                cweIds = listOf("CWE-89"),
                relativePath = "app.py",
                absolutePath = tempFile,
                line = 6,
            )

            val context = CodeContextExtractor().extract(finding, radius = 1)

            assertEquals("def list_users", context.enclosingSymbol)
            assertEquals(5..7, context.lineWindow)
            assertTrue(context.imports.contains("import sqlite3"))
            assertTrue(context.imports.contains("from flask import request"))
            assertTrue(context.snippet.contains(">>    6 |     query = f\"SELECT * FROM users WHERE name = '{username}'\""))
        } finally {
            Files.deleteIfExists(tempFile)
        }
    }
}
