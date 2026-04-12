package com.hackathon.securityagent.sast

import com.hackathon.securityagent.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path

class SarifParserTest {
    @Test
    fun `parses findings from semgrep sarif output`() {
        val parser = SarifParser()
        val sarif = Files.readString(Path.of("src/test/testData/sast/semgrep-scan.sarif"))
        val scanRoot = Path.of("workspace-root").toAbsolutePath().normalize()

        val findings = parser.parse(sarif, scanRoot)

        assertEquals(2, findings.size)

        val sqlInjection = findings.first()
        assertEquals("python.lang.security.audit.sql-injection", sqlInjection.ruleId)
        assertEquals(Severity.HIGH, sqlInjection.severity)
        assertEquals("demo-vulnerable-app/app.py", sqlInjection.relativePath)
        assertEquals(48, sqlInjection.line)
        assertTrue(sqlInjection.cweIds.contains("CWE-89: SQL Injection"))

        val commandInjection = findings.last()
        assertEquals(Severity.CRITICAL, commandInjection.severity)
        assertEquals(61, commandInjection.line)
        assertTrue(commandInjection.cweIds.contains("CWE-78: OS Command Injection"))
    }

    @Test
    fun `classifies weak crypto findings as low severity`() {
        val parser = SarifParser()
        val sarif =
            """
            {
              "version": "2.1.0",
              "runs": [
                {
                  "results": [
                    {
                      "ruleId": "python.lang.security.audit.weak-hash-md5",
                      "message": {
                        "text": "MD5 should not be used for security-sensitive hashing."
                      },
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": {
                              "uri": "demo-vulnerable-app/app.py"
                            },
                            "region": {
                              "startLine": 115,
                              "startColumn": 14
                            }
                          }
                        }
                      ]
                    }
                  ],
                  "tool": {
                    "driver": {
                      "name": "Semgrep OSS",
                      "rules": [
                        {
                          "id": "python.lang.security.audit.weak-hash-md5",
                          "defaultConfiguration": {
                            "level": "warning"
                          },
                          "properties": {
                            "tags": [
                              "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
                            ]
                          }
                        }
                      ]
                    }
                  }
                }
              ]
            }
            """.trimIndent()
        val scanRoot = Path.of("workspace-root").toAbsolutePath().normalize()

        val findings = parser.parse(sarif, scanRoot)

        assertEquals(1, findings.size)
        assertEquals(Severity.LOW, findings.single().severity)
    }
}
