package com.hackathon.securityagent.sast

import com.hackathon.securityagent.model.Finding
import java.nio.file.Path

interface SastRunner {
    val toolName: String

    fun scan(targetPath: Path): SastRunResult
}

data class SastRunResult(
    val toolName: String,
    val command: List<String>,
    val exitCode: Int,
    val findings: List<Finding>,
    val toolLog: String,
)

class SastRunnerException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
