package com.hackathon.securityagent.quickfix

import com.hackathon.securityagent.services.SecurityScanService
import com.intellij.codeInsight.intention.FileModifier.SafeFieldForPreview
import com.intellij.codeInsight.intention.preview.IntentionPreviewInfo
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.components.service
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.psi.PsiDocumentManager

class ApplySecurityFix(
    @field:SafeFieldForPreview
    private val findingId: String,
) : LocalQuickFix {
    override fun getFamilyName(): String = FAMILY_NAME

    override fun getName(): String = FAMILY_NAME

    override fun generatePreview(
        project: Project,
        descriptor: ProblemDescriptor,
    ): IntentionPreviewInfo {
        val psiFile = descriptor.psiElement.containingFile ?: return IntentionPreviewInfo.EMPTY
        val finding = project.service<SecurityScanService>().findFindingById(findingId)
            ?: return IntentionPreviewInfo.Html("The stored fix is no longer available. Run a new scan.")
        val fixPatch = finding.fixPatch
            ?: return IntentionPreviewInfo.Html("This finding does not include an executable patch yet.")

        val result = runCatching {
            FixPatchApplier.apply(psiFile.text, fixPatch)
        }.getOrElse { error ->
            return IntentionPreviewInfo.Html(error.message ?: "Unable to preview the patch. Run a new scan.")
        }

        return IntentionPreviewInfo.CustomDiff(
            psiFile.fileType,
            psiFile.name,
            psiFile.text,
            result.updatedText,
        )
    }

    override fun applyFix(
        project: Project,
        descriptor: ProblemDescriptor,
    ) {
        val psiFile = descriptor.psiElement.containingFile ?: return
        val virtualFile = psiFile.virtualFile ?: return
        val finding = project.service<SecurityScanService>().findFindingById(findingId)
        val fixPatch = finding?.fixPatch

        if (finding == null || fixPatch == null) {
            Messages.showErrorDialog(project, "The stored security fix is no longer available. Run a new scan first.", TITLE)
            return
        }

        val document = PsiDocumentManager.getInstance(project).getDocument(psiFile)
        if (document == null) {
            Messages.showErrorDialog(project, "Unable to load the editor document for this file.", TITLE)
            return
        }

        val result = runCatching {
            FixPatchApplier.apply(document.text, fixPatch)
        }.getOrElse { error ->
            Messages.showErrorDialog(project, error.message ?: "Unable to apply the generated fix.", TITLE)
            return
        }

        WriteCommandAction
            .writeCommandAction(project, psiFile)
            .withName(FAMILY_NAME)
            .run<RuntimeException> {
                document.setText(result.updatedText)
                PsiDocumentManager.getInstance(project).commitDocument(document)
            }

        project.service<SecurityScanService>().markFixApplied(virtualFile.toNioPath(), fixPatch)
    }

    private companion object {
        private const val TITLE = "Security Agent"
        private const val FAMILY_NAME = "Apply AI security fix"
    }
}
