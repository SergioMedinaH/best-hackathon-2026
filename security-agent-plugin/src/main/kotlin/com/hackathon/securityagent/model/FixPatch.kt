package com.hackathon.securityagent.model

data class FixPatch(
    val startLine: Int,
    val endLine: Int,
    val originalCode: String,
    val replacementCode: String,
) {
    init {
        require(startLine > 0) { "startLine must be positive." }
        require(endLine >= startLine) { "endLine must be greater than or equal to startLine." }
    }

    val lineRangeDisplay: String
        get() = if (startLine == endLine) {
            startLine.toString()
        } else {
            "$startLine-$endLine"
        }
}
