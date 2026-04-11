package com.hackathon.securityagent.sast

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

class SemgrepRunner(
    private val executable: String = "semgrep",
    private val config: String = DEFAULT_CONFIG,
    private val parser: SarifParser = SarifParser(),
) : SastRunner {
    override val toolName: String = "Semgrep"

    override fun scan(targetPath: Path): SastRunResult = scan(targetPath, emptyList())

    fun scan(
        targetPath: Path,
        includedPaths: List<Path>,
    ): SastRunResult {
        val resolvedTarget = targetPath.toAbsolutePath().normalize()
        val scanRoot = if (Files.isDirectory(resolvedTarget)) {
            resolvedTarget
        } else {
            resolvedTarget.parent ?: throw SastRunnerException("Unable to determine the scan root for $resolvedTarget")
        }
        val sarifOutputFile = Files.createTempFile("security-agent-semgrep-", ".sarif")
        val normalizedIncludedPaths = includedPaths
            .map { it.toAbsolutePath().normalize() }
            .distinct()
        val command = buildScanCommand(
            scanRoot = scanRoot,
            resolvedTarget = resolvedTarget,
            sarifOutputFile = sarifOutputFile,
            includedPaths = normalizedIncludedPaths,
        )

        try {
            val processBuilder = ProcessBuilder(command)
                .directory(scanRoot.toFile())
                .redirectErrorStream(true)
            processBuilder.environment()["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
            processBuilder.environment()["SEMGREP_SEND_METRICS"] = "off"

            val process = processBuilder.start()
            val toolLog = process.inputStream.bufferedReader(StandardCharsets.UTF_8).use { it.readText().trim() }
            val exitCode = process.waitFor()
            val rawSarif = if (Files.exists(sarifOutputFile)) {
                Files.readString(sarifOutputFile, StandardCharsets.UTF_8)
            } else {
                ""
            }

            if (exitCode !in SUCCESSFUL_EXIT_CODES) {
                val details = buildString {
                    append("Semgrep exited with code ")
                    append(exitCode)
                    append('.')
                    if (toolLog.isNotBlank()) {
                        append('\n')
                        append(toolLog)
                    }
                }
                throw SastRunnerException(details)
            }

            val findings = if (rawSarif.isBlank()) {
                emptyList()
            } else {
                parser.parse(rawSarif, scanRoot)
            }

            return SastRunResult(
                toolName = toolName,
                command = command,
                exitCode = exitCode,
                findings = findings,
                toolLog = toolLog,
            )
        } catch (exception: IOException) {
            throw SastRunnerException(
                "Failed to start semgrep. Make sure `semgrep` is installed and available on PATH.",
                exception,
            )
        } catch (exception: InterruptedException) {
            Thread.currentThread().interrupt()
            throw SastRunnerException("Semgrep scan was interrupted.", exception)
        } finally {
            Files.deleteIfExists(sarifOutputFile)
        }
    }

    internal fun buildScanCommand(
        scanRoot: Path,
        resolvedTarget: Path,
        sarifOutputFile: Path,
        includedPaths: List<Path>,
    ): List<String> {
        val semgrepTargets = includedPaths
            .takeIf { it.isNotEmpty() }
            ?.map { path ->
                if (path.startsWith(scanRoot)) {
                    scanRoot.relativize(path).toString()
                } else {
                    path.toString()
                }
            }
            ?: listOf(resolvedTarget.toString())

        return listOf(
            executable,
            "scan",
            "--config",
            config,
            "--sarif",
            "--output",
            sarifOutputFile.toString(),
            "--metrics",
            "off",
            "--quiet",
        ) + semgrepTargets
    }

    companion object {
        private val SUCCESSFUL_EXIT_CODES = setOf(0, 1)
        private const val DEFAULT_CONFIG = "p/security-audit"
    }
}
