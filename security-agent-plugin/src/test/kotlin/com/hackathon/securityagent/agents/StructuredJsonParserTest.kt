package com.hackathon.securityagent.agents

import org.junit.Assert.assertEquals
import org.junit.Test

class StructuredJsonParserTest {
    @Test
    fun `extracts fenced json payload`() {
        val raw = """
            Here is the result:
            ```json
            {
              "keepFinding": true,
              "rationale": "The sink is directly reachable."
            }
            ```
        """.trimIndent()

        val extracted = StructuredJsonParser.extractJsonObject(raw)

        assertEquals(
            """
            {
              "keepFinding": true,
              "rationale": "The sink is directly reachable."
            }
            """.trimIndent(),
            extracted,
        )
    }
}
