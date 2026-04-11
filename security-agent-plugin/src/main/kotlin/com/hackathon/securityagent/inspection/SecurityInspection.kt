package com.hackathon.securityagent.inspection

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.quickfix.ApplySecurityFix
import com.hackathon.securityagent.services.SecurityScanService
import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.openapi.components.service
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiFile

class SecurityInspection : LocalInspectionTool() {
    override fun getDisplayName(): String = "Security Agent Findings"

    override fun getShortName(): String = SHORT_NAME

    override fun isAvailableForFile(file: PsiFile): Boolean {
        val virtualFile = file.virtualFile ?: return false
        if (!virtualFile.extension.equals("py", ignoreCase = true)) {
            return false
        }

        return file.project.service<SecurityScanService>().findingsForFile(virtualFile.toNioPath()).isNotEmpty()
    }

    override fun checkFile(
        file: PsiFile,
        manager: InspectionManager,
        isOnTheFly: Boolean,
    ): Array<ProblemDescriptor> {
        val virtualFile = file.virtualFile ?: return ProblemDescriptor.EMPTY_ARRAY
        val document = PsiDocumentManager.getInstance(file.project).getDocument(file) ?: return ProblemDescriptor.EMPTY_ARRAY
        val findings = file.project.service<SecurityScanService>()
            .findingsForFile(virtualFile.toNioPath())
            .filter { it.validationStatus != ValidationStatus.DISMISSED }

        if (findings.isEmpty()) {
            return ProblemDescriptor.EMPTY_ARRAY
        }

        return findings.mapNotNull { finding ->
            createDescriptor(
                file = file,
                manager = manager,
                documentLineCount = document.lineCount,
                finding = finding,
                isOnTheFly = isOnTheFly,
            )
        }.toTypedArray()
    }

    private fun createDescriptor(
        file: PsiFile,
        manager: InspectionManager,
        documentLineCount: Int,
        finding: Finding,
        isOnTheFly: Boolean,
    ): ProblemDescriptor? {
        if (documentLineCount <= 0 || finding.line <= 0 || finding.line > documentLineCount) {
            return null
        }

        val lineIndex = finding.line - 1
        val document = PsiDocumentManager.getInstance(file.project).getDocument(file) ?: return null
        val lineStart = document.getLineStartOffset(lineIndex)
        val lineEnd = document.getLineEndOffset(lineIndex)
        val effectiveEnd = when {
            lineEnd > lineStart -> lineEnd
            file.textLength > lineStart -> lineStart + 1
            else -> file.textLength
        }
        if (effectiveEnd < lineStart) {
            return null
        }

        val fixes: Array<LocalQuickFix> =
            if (finding.hasApplicableFix) {
                arrayOf(ApplySecurityFix(finding.id))
            } else {
                emptyArray()
            }

        return manager.createProblemDescriptor(
            file,
            TextRange(lineStart, effectiveEnd),
            buildDescription(finding),
            highlightTypeFor(finding.severity),
            isOnTheFly,
            *fixes,
        )
    }

    private fun buildDescription(finding: Finding): String =
        buildString {
            append("[")
            append(finding.severity.displayName)
            append("] ")
            append(finding.message)
            finding.validationRationale?.takeIf { it.isNotBlank() }?.let {
                append(" Validation: ")
                append(it.lineSequence().firstOrNull().orEmpty())
            }
        }

    private fun highlightTypeFor(severity: Severity): ProblemHighlightType =
        when (severity) {
            Severity.CRITICAL,
            Severity.HIGH,
            -> ProblemHighlightType.GENERIC_ERROR_OR_WARNING

            Severity.MEDIUM -> ProblemHighlightType.WARNING
            Severity.LOW,
            Severity.INFO,
            Severity.UNKNOWN,
            -> ProblemHighlightType.WEAK_WARNING
        }

    private companion object {
        private const val SHORT_NAME = "SecurityAgentInspection"
    }
}
