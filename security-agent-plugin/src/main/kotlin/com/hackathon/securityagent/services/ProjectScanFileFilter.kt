package com.hackathon.securityagent.services

import java.nio.file.Path

object ProjectScanFileFilter {
    private val excludedDirectoryNames = setOf(
        ".venv",
        "venv",
        "env",
        ".idea",
        "__pycache__",
        "site-packages",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "node_modules",
    )

    fun shouldInclude(path: Path): Boolean =
        path.normalize()
            .map(Path::toString)
            .none { segment -> excludedDirectoryNames.any { it.equals(segment, ignoreCase = true) } }
}
