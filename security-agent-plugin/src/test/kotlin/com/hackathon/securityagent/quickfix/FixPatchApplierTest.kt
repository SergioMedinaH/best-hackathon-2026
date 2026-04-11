package com.hackathon.securityagent.quickfix

import com.hackathon.securityagent.model.FixPatch
import org.junit.Assert.assertEquals
import org.junit.Test

class FixPatchApplierTest {
    @Test
    fun `applies contiguous line replacement`() {
        val patch = FixPatch(
            startLine = 2,
            endLine = 3,
            originalCode = "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n    return cursor.execute(query).fetchall()",
            replacementCode = "    query = \"SELECT * FROM users WHERE name = ?\"\n    return cursor.execute(query, (username,)).fetchall()",
        )

        val result = FixPatchApplier.apply(
            """
            def list_users(username):
                query = f"SELECT * FROM users WHERE name = '{username}'"
                return cursor.execute(query).fetchall()
            """.trimIndent(),
            patch,
        )

        assertEquals(
            """
            def list_users(username):
                query = "SELECT * FROM users WHERE name = ?"
                return cursor.execute(query, (username,)).fetchall()
            """.trimIndent(),
            result.updatedText,
        )
    }

    @Test(expected = FixPatchConflictException::class)
    fun `rejects patch when source changed after scan`() {
        val patch = FixPatch(
            startLine = 1,
            endLine = 1,
            originalCode = "dangerous = request.args['name']",
            replacementCode = "dangerous = sanitize(request.args['name'])",
        )

        FixPatchApplier.apply(
            "dangerous = request.args.get('name')",
            patch,
        )
    }
}
