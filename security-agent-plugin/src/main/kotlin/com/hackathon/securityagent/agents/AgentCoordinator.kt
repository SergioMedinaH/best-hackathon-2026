package com.hackathon.securityagent.agents

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.FixPatch
import com.hackathon.securityagent.model.ValidationStatus
import com.hackathon.securityagent.psi.CodeContextExtractor

class AgentCoordinator(
    apiKey: String,
    baseUrl: String,
    modelName: String,
    private val contextExtractor: CodeContextExtractor = CodeContextExtractor(),
    groundingRepository: GroundingRepository = GroundingRepository(),
) {
    private val runner = KoogAgentRunner(apiKey = apiKey, baseUrl = baseUrl, modelName = modelName)
    private val triagerAgent = TriagerAgent(runner)
    private val validatorAgent = ValidatorAgent(runner, groundingRepository)
    private val explainerAgent = ExplainerAgent(runner)
    private val fixGeneratorAgent = FixGeneratorAgent(runner)

    fun enrichFinding(
        finding: Finding,
        onIntermediateUpdate: (Finding) -> Unit = {},
    ): Finding {
        val context = contextExtractor.extract(finding)
        val triage = triagerAgent.triage(finding, context)
        var workingFinding = finding.copy(
            validationRationale = "Triager: ${triage.rationale}",
        )
        onIntermediateUpdate(workingFinding)

        if (!triage.keepFinding) {
            workingFinding = workingFinding.copy(
                validationStatus = ValidationStatus.DISMISSED,
                confidence = DEFAULT_DISMISSED_CONFIDENCE,
            )
            onIntermediateUpdate(workingFinding)
            return workingFinding
        }

        val validation = validatorAgent.validate(finding, context, triage)
        workingFinding = workingFinding.copy(
            validationStatus = ValidationStatus.fromAgentValue(validation.status),
            confidence = validation.confidence.coerceIn(0, 100),
            owaspCategory = validation.owaspCategory?.ifBlank { null },
            validationRationale = listOf(
                "Triager: ${triage.rationale}",
                "Validator: ${validation.rationale}",
            ).joinToString(separator = "\n\n"),
        )
        onIntermediateUpdate(workingFinding)

        if (workingFinding.validationStatus == ValidationStatus.DISMISSED) {
            return workingFinding
        }

        val explanation = explainerAgent.explain(finding, context, validation)
        workingFinding = workingFinding.copy(
            narrativeExplanation = explanation.narrativeExplanation,
            exploitChain = explanation.exploitChain,
        )
        onIntermediateUpdate(workingFinding)

        val fix = fixGeneratorAgent.generateFix(finding, context, validation, explanation)
        workingFinding = workingFinding.copy(
            fixSummary = fix.fixSummary,
            safeCodeExample = fix.safeCodeExample,
            fixPatch = buildFixPatch(finding, fix),
        )
        onIntermediateUpdate(workingFinding)

        return workingFinding
    }

    private fun buildFixPatch(
        finding: Finding,
        response: FixGenerationResponse,
    ): FixPatch? {
        val replacementCode = (response.replacementCode ?: response.safeCodeExample)
            .trim('\n', '\r')
            .takeIf { it.isNotBlank() }
            ?: return null

        val startLine = response.patchStartLine ?: finding.line
        val endLine = response.patchEndLine ?: startLine
        if (startLine <= 0 || endLine < startLine) {
            return null
        }

        val originalCode = contextExtractor.readLineRange(finding.absolutePath, startLine, endLine)
            ?: return null

        return FixPatch(
            startLine = startLine,
            endLine = endLine,
            originalCode = originalCode,
            replacementCode = replacementCode,
        )
    }

    private companion object {
        private const val DEFAULT_DISMISSED_CONFIDENCE = 35
    }
}
