package com.hackathon.securityagent.services

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Path

class ProjectScanFileFilterTest {
    @Test
    fun `includes application source file`() {
        assertTrue(
            ProjectScanFileFilter.shouldInclude(
                Path.of("C:/Users/sergi/Documents/Uni/Hackathon/demo-vulnerable-app/app.py"),
            ),
        )
    }

    @Test
    fun `excludes python files inside virtual environment`() {
        assertFalse(
            ProjectScanFileFilter.shouldInclude(
                Path.of("C:/Users/sergi/Documents/Uni/Hackathon/demo-vulnerable-app/.venv/Lib/site-packages/flask/app.py"),
            ),
        )
    }
}
