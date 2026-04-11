package com.hackathon.securityagent.ui

import com.hackathon.securityagent.chat.FindingChatRequestResult
import com.hackathon.securityagent.chat.FindingChatRole
import com.hackathon.securityagent.chat.FindingChatThreadState
import com.hackathon.securityagent.model.Finding
import com.intellij.openapi.ui.Messages
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPanel
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Font
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import javax.swing.JButton
import javax.swing.KeyStroke

class FindingChatPanel : JBPanel<FindingChatPanel>(BorderLayout(0, 8)) {
    var onSendMessage: ((Finding, String) -> FindingChatRequestResult)? = null

    private val transcriptArea = JBTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        border = JBUI.Borders.compound(
            JBUI.Borders.customLine(JBColor(Color(0xD7DDE5), Color(0x4B5563))),
            JBUI.Borders.empty(8),
        )
        background = JBColor(Color(0xF7F9FC), Color(0x313335))
        rows = 8
    }
    private val statusLabel = JBLabel("Select a finding to start the follow-up chat.")
    private val inputArea = JBTextArea().apply {
        lineWrap = true
        wrapStyleWord = true
        rows = 3
        border = JBUI.Borders.compound(
            JBUI.Borders.customLine(JBColor(Color(0xD7DDE5), Color(0x4B5563))),
            JBUI.Borders.empty(8),
        )
    }
    private val sendButton = JButton("Ask")

    private var currentFinding: Finding? = null
    private var currentThread: FindingChatThreadState? = null

    init {
        border = JBUI.Borders.emptyTop(8)

        add(
            JBPanel<JBPanel<*>>(BorderLayout(0, 6)).apply {
                add(
                    JBLabel("Follow-up Chat").apply {
                        font = font.deriveFont(Font.BOLD)
                    },
                    BorderLayout.NORTH,
                )
                add(JBScrollPane(transcriptArea), BorderLayout.CENTER)
                add(statusLabel, BorderLayout.SOUTH)
            },
            BorderLayout.CENTER,
        )

        add(
            JBPanel<JBPanel<*>>(BorderLayout(8, 0)).apply {
                add(JBScrollPane(inputArea), BorderLayout.CENTER)
                add(sendButton, BorderLayout.EAST)
            },
            BorderLayout.SOUTH,
        )

        sendButton.addActionListener { submitMessage() }
        inputArea.registerKeyboardAction(
            { submitMessage() },
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK),
            WHEN_FOCUSED,
        )

        showNoFinding()
    }

    fun showFinding(
        finding: Finding,
        threadState: FindingChatThreadState,
    ) {
        currentFinding = finding
        currentThread = threadState
        renderThread(threadState)
    }

    fun updateThread(threadState: FindingChatThreadState) {
        if (threadState.findingId != currentFinding?.id) {
            return
        }

        currentThread = threadState
        renderThread(threadState)
    }

    fun showNoFinding() {
        currentFinding = null
        currentThread = null
        transcriptArea.text = "Ask follow-up questions about the selected security finding here."
        statusLabel.text = "Select a finding to enable the chat."
        transcriptArea.caretPosition = 0
        inputArea.text = ""
        inputArea.isEnabled = false
        sendButton.isEnabled = false
    }

    private fun submitMessage() {
        val finding = currentFinding ?: return
        val prompt = inputArea.text.trim()
        val handler = onSendMessage ?: return

        when (val result = handler.invoke(finding, prompt)) {
            FindingChatRequestResult.Started -> {
                inputArea.text = ""
                statusLabel.text = "Streaming answer..."
                inputArea.isEnabled = false
                sendButton.isEnabled = false
            }

            is FindingChatRequestResult.Rejected -> {
                if (result.isError) {
                    Messages.showErrorDialog(result.message, "Security Agent")
                } else {
                    statusLabel.text = result.message
                }
            }
        }
    }

    private fun renderThread(threadState: FindingChatThreadState) {
        transcriptArea.text =
            if (threadState.messages.isEmpty()) {
                "Ask why the finding matters, how realistic the exploit is, or whether the proposed fix is enough."
            } else {
                threadState.messages.joinToString(separator = "\n\n") { message ->
                    buildString {
                        append(message.role.displayName)
                        if (message.role == FindingChatRole.ASSISTANT && threadState.isStreaming && message == threadState.messages.last()) {
                            append(" (streaming)")
                        }
                        append('\n')
                        append(if (message.content.isBlank()) "..." else message.content)
                    }
                }
            }

        statusLabel.text =
            when {
                threadState.isStreaming -> "Streaming answer..."
                threadState.lastError != null -> threadState.lastError
                else -> "History is kept separately for this finding. Press Ctrl+Enter to send."
            }

        transcriptArea.caretPosition = transcriptArea.document.length
        inputArea.isEnabled = !threadState.isStreaming
        sendButton.isEnabled = !threadState.isStreaming
    }
}
