package com.hackathon.securityagent.services

import com.hackathon.securityagent.agents.AgentCoordinator
import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.FixPatch
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.openai.OpenAIClientConfig
import com.hackathon.securityagent.sast.SastRunResult
import com.hackathon.securityagent.sast.SastRunnerException
import com.hackathon.securityagent.sast.SemgrepRunner
import com.hackathon.securityagent.settings.SecurityAgentSettings
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.roots.ProjectFileIndex
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import java.nio.file.Path
import java.time.Instant

@Service(Service.Level.PROJECT)
class SecurityScanService(
    private val project: Project,
) {
    private val semgrepRunner = SemgrepRunner()

    @Volatile
    private var state: SecurityScanState = SecurityScanState()

    fun currentState(): SecurityScanState = state

    fun findFindingById(findingId: String): Finding? = state.findings.firstOrNull { it.id == findingId }

    fun findingsForFile(filePath: Path): List<Finding> {
        val normalizedPath = filePath.toAbsolutePath().normalize()
        return state.findings.filter { it.absolutePath.normalize() == normalizedPath }
    }

    fun markFixApplied(
        filePath: Path,
        patch: FixPatch,
    ) {
        val normalizedPath = filePath.toAbsolutePath().normalize()
        val remainingFindings = state.findings.filterNot { finding ->
            finding.absolutePath.normalize() == normalizedPath &&
                finding.line in patch.startLine..patch.endLine
        }

        updateState(
            state.copy(
                findings = remainingFindings,
            ),
        )
        restartInspections()
    }

    @Synchronized
    fun requestProjectScan(): ScanRequestResult {
        if (state.isScanning || state.isEnriching) {
            return ScanRequestResult.Rejected("A security scan is already running.", isError = false)
        }

        val projectBasePath = project.basePath
            ?: return ScanRequestResult.Rejected(
                "The project must be saved to disk before it can be scanned.",
                isError = true,
            )

        val pythonFiles = collectPythonFiles()
        if (pythonFiles.isEmpty()) {
            return ScanRequestResult.Rejected("No Python files were found in the current project.", isError = false)
        }

        val projectRoot = Path.of(projectBasePath).toAbsolutePath().normalize()
        updateState(
            state.copy(
                findings = emptyList(),
                isScanning = true,
                isEnriching = false,
                pythonFileCount = pythonFiles.size,
                enrichedFindingCount = 0,
                totalFindingsToEnrich = 0,
                lastScanError = null,
                lastEnrichmentError = null,
                enrichmentSkippedReason = null,
            ),
        )
        restartInspections()

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Security Agent Scan", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    indicator.text = "Running Semgrep on ${project.name}"

                    val startedAt = System.currentTimeMillis()
                    logInfo("Starting scan for ${project.name}. Python files detected: ${pythonFiles.size}. Target: $projectRoot")

                    try {
                        val result = semgrepRunner.scan(
                            targetPath = projectRoot,
                            includedPaths = pythonFiles.map { it.toNioPath() },
                        )
                        val elapsedMs = System.currentTimeMillis() - startedAt
                        logScanResult(project, pythonFiles.size, result, elapsedMs)

                        val baseState = SecurityScanState(
                            findings = result.findings,
                            isScanning = false,
                            isEnriching = false,
                            pythonFileCount = pythonFiles.size,
                            enrichedFindingCount = 0,
                            totalFindingsToEnrich = 0,
                            lastScanDurationMs = elapsedMs,
                            lastScanFinishedAt = Instant.now(),
                            lastScanError = null,
                            lastEnrichmentError = null,
                            enrichmentSkippedReason = null,
                            lastCommand = result.command,
                        )
                        updateState(baseState)
                        restartInspections()
                        try {
                            enrichFindingsIfConfigured(
                                baseState = baseState,
                                findings = result.findings,
                                indicator = indicator,
                            )
                        } catch (throwable: Throwable) {
                            val message = throwable.message ?: "LLM enrichment failed unexpectedly."
                            logError("Agent enrichment failed: $message", throwable)
                            updateState(
                                baseState.copy(
                                    findings = result.findings,
                                    lastEnrichmentError = message,
                                    enrichmentSkippedReason = "Agent enrichment failed. The raw Semgrep findings are still available.",
                                ),
                            )
                            restartInspections()
                        }
                    } catch (exception: SastRunnerException) {
                        val elapsedMs = System.currentTimeMillis() - startedAt
                        logError("Security scan failed: ${exception.message}", exception)
                        updateState(
                            state.copy(
                                isScanning = false,
                                pythonFileCount = pythonFiles.size,
                                lastScanDurationMs = elapsedMs,
                                lastScanFinishedAt = Instant.now(),
                                lastScanError = toFriendlyScanError(exception),
                            ),
                        )
                        restartInspections()
                    }
                }
            },
        )

        return ScanRequestResult.Started
    }

    private fun enrichFindingsIfConfigured(
        baseState: SecurityScanState,
        findings: List<Finding>,
        indicator: ProgressIndicator,
    ) {
        if (findings.isEmpty()) {
            return
        }

        val clientConfig = ApplicationManager.getApplication().getService(SecurityAgentSettings::class.java).toClientConfig()
        if (clientConfig == null) {
            updateState(
                baseState.copy(
                    enrichmentSkippedReason =
                        "Add an OpenAI API key in Settings > Tools > Security Agent to unlock validation, fixes, report narration, and follow-up chat.",
                ),
            )
            logInfo("Skipping Koog enrichment because no OpenAI API key is configured.")
            return
        }

        runKoogEnrichment(
            baseState = baseState,
            findings = findings,
            clientConfig = clientConfig,
            indicator = indicator,
        )
    }

    private fun runKoogEnrichment(
        baseState: SecurityScanState,
        findings: List<Finding>,
        clientConfig: OpenAIClientConfig,
        indicator: ProgressIndicator,
    ) {
        val totalFindings = findings.size
        logInfo("Starting agent enrichment for $totalFindings findings with model ${clientConfig.model}. Primary backend: Koog.")

        val coordinator = AgentCoordinator(
            apiKey = clientConfig.apiKey,
            baseUrl = clientConfig.baseUrl,
            modelName = clientConfig.model,
        )
        var currentFindings = findings
        var completedCount = 0
        var lastError: String? = null

        updateState(
            baseState.copy(
                findings = currentFindings,
                isEnriching = true,
                enrichedFindingCount = 0,
                totalFindingsToEnrich = totalFindings,
                enrichmentSkippedReason = null,
            ),
        )

        findings.forEachIndexed { index, finding ->
            indicator.checkCanceled()
            indicator.isIndeterminate = false
            indicator.fraction = index.toDouble() / totalFindings.toDouble()
            indicator.text = "Enriching findings with Security Agent"
            indicator.text2 = "Analyzing ${finding.ruleId} (${index + 1}/$totalFindings)"

            val enrichedFinding = try {
                coordinator.enrichFinding(finding) { partialFinding ->
                    currentFindings = currentFindings.replaceFinding(partialFinding)
                    updateState(
                        baseState.copy(
                            findings = currentFindings,
                            isEnriching = true,
                            enrichedFindingCount = completedCount,
                            totalFindingsToEnrich = totalFindings,
                            lastEnrichmentError = lastError,
                        ),
                    )
                }
            } catch (exception: Throwable) {
                lastError = exception.message ?: "Agent enrichment failed."
                logError("Agent enrichment failed for ${finding.locationDisplay}: $lastError", exception)
                finding.copy(
                    validationStatus = ValidationStatus.ERROR,
                    enrichmentError = lastError,
                    validationRationale = finding.validationRationale ?: "Agent pipeline failed before validation completed.",
                )
            }

            currentFindings = currentFindings.replaceFinding(enrichedFinding)
            completedCount += 1

            updateState(
                baseState.copy(
                    findings = currentFindings,
                    isEnriching = completedCount < totalFindings,
                    enrichedFindingCount = completedCount,
                    totalFindingsToEnrich = totalFindings,
                    lastEnrichmentError = lastError,
                ),
            )
            restartInspections()
        }

        indicator.fraction = 1.0
        indicator.text2 = "Agent enrichment finished"
        logInfo("Agent enrichment finished. Completed: $completedCount/$totalFindings.")
    }

    private fun collectPythonFiles(): List<VirtualFile> {
        val fileIndex = ProjectFileIndex.getInstance(project)
        val pythonFiles = mutableListOf<VirtualFile>()
        fileIndex.iterateContent { virtualFile ->
            if (isProjectPythonSourceFile(virtualFile, fileIndex)) {
                pythonFiles += virtualFile
            }
            true
        }
        return pythonFiles
    }

    private fun isProjectPythonSourceFile(
        virtualFile: VirtualFile,
        fileIndex: ProjectFileIndex,
    ): Boolean {
        if (virtualFile.isDirectory || !virtualFile.extension.equals("py", ignoreCase = true)) {
            return false
        }

        if (!fileIndex.isInContent(virtualFile) || fileIndex.isExcluded(virtualFile) || fileIndex.isInLibrary(virtualFile)) {
            return false
        }

        return ProjectScanFileFilter.shouldInclude(virtualFile.toNioPath())
    }

    private fun updateState(newState: SecurityScanState) {
        state = newState
        project.messageBus.syncPublisher(SecurityScanListener.TOPIC).stateUpdated(newState)
    }

    private fun restartInspections() {
        ApplicationManager.getApplication().invokeLater {
            if (!project.isDisposed) {
                DaemonCodeAnalyzer.getInstance(project).restart()
            }
        }
    }

    private fun List<Finding>.replaceFinding(updatedFinding: Finding): List<Finding> =
        map { existing ->
            if (existing.id == updatedFinding.id) {
                updatedFinding
            } else {
                existing
            }
        }

    private fun logScanResult(
        project: Project,
        pythonFileCount: Int,
        result: SastRunResult,
        elapsedMs: Long,
    ) {
        logInfo("Completed ${result.toolName} scan for ${project.name} in ${elapsedMs} ms.")
        logInfo("Command: ${result.command.joinToString(separator = " ")}")
        logInfo("Python files scanned: $pythonFileCount")
        logInfo("Exit code: ${result.exitCode}")

        if (result.toolLog.isNotBlank()) {
            result.toolLog.lineSequence()
                .filter { it.isNotBlank() }
                .forEach { logInfo("semgrep> $it") }
        }

        if (result.findings.isEmpty()) {
            logInfo("No findings detected.")
            return
        }

        logInfo("Findings detected: ${result.findings.size}")
        result.findings.forEach { finding ->
            logInfo(formatFinding(finding))
        }
    }

    private fun formatFinding(finding: Finding): String {
        val cweSuffix = finding.cweIds.firstOrNull()?.let { " | $it" }.orEmpty()
        return "[${finding.severity.displayName}] ${finding.ruleId} | ${finding.locationDisplay}$cweSuffix | ${finding.message}"
    }

    private fun toFriendlyScanError(exception: SastRunnerException): String {
        val message = exception.message.orEmpty()
        return when {
            message.contains("Failed to start semgrep", ignoreCase = true) ->
                "Semgrep could not be started. Install it and ensure `semgrep` is available on PATH. Example: `pip install semgrep`."

            message.contains("Semgrep exited with code", ignoreCase = true) ->
                "Semgrep returned an error while scanning this project. Check that `semgrep scan --config p/security-audit <path>` works in a terminal."

            else -> message.ifBlank { "Security scan failed." }
        }
    }

    private fun logInfo(message: String) {
        LOGGER.info(message)
        println("$LOG_PREFIX $message")
    }

    private fun logError(
        message: String,
        error: Throwable,
    ) {
        LOGGER.warn(message, error)
        System.err.println("$LOG_PREFIX $message")
    }

    companion object {
        private const val LOG_PREFIX = "[SecurityAgent]"
        private val LOGGER = Logger.getInstance(SecurityScanService::class.java)
    }
}
