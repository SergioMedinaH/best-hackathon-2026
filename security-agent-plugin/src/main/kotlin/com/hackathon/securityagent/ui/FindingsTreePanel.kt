package com.hackathon.securityagent.ui

import com.hackathon.securityagent.model.Finding
import com.hackathon.securityagent.model.Severity
import com.hackathon.securityagent.model.ValidationStatus
import com.intellij.icons.AllIcons
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.ui.DoubleClickListener
import com.intellij.ui.TreeSpeedSearch
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBPanel
import com.intellij.ui.treeStructure.Tree
import com.intellij.util.ui.JBUI
import com.intellij.util.ui.tree.TreeUtil
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.nio.file.Paths
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeCellRenderer
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreePath

class FindingsTreePanel(
    private val project: Project,
) : JBPanel<FindingsTreePanel>(BorderLayout()) {
    private val rootNode = DefaultMutableTreeNode(TreeNode.Root)
    private val treeModel = DefaultTreeModel(rootNode)
    private val tree = Tree(treeModel)
    private val nodeByKey = linkedMapOf<String, DefaultMutableTreeNode>()

    var onFindingSelected: (Finding?) -> Unit = {}

    init {
        border = JBUI.Borders.empty()
        tree.isRootVisible = false
        tree.showsRootHandles = true
        tree.cellRenderer = FindingsTreeCellRenderer()
        TreeSpeedSearch(tree)

        tree.addTreeSelectionListener {
            onFindingSelected(selectedFinding())
        }

        object : DoubleClickListener() {
            override fun onDoubleClick(event: java.awt.event.MouseEvent): Boolean {
                openSelectedFinding()
                return true
            }
        }.installOn(tree)

        tree.addKeyListener(
            object : KeyAdapter() {
                override fun keyPressed(event: KeyEvent) {
                    if (event.keyCode == KeyEvent.VK_ENTER) {
                        openSelectedFinding()
                    }
                }
            },
        )

        add(JBScrollPane(tree), BorderLayout.CENTER)
    }

    fun setFindings(findings: List<Finding>) {
        rootNode.removeAllChildren()
        nodeByKey.clear()

        if (findings.isEmpty()) {
            rootNode.add(DefaultMutableTreeNode(TreeNode.Placeholder("No findings yet")))
            treeModel.reload()
            TreeUtil.expandAll(tree)
            return
        }

        findings.groupBy { it.severity }
            .toList()
            .sortedByDescending { it.first.priority }
            .forEach { (severity, items) ->
                val severityNode = DefaultMutableTreeNode(TreeNode.SeverityGroup(severity, items.size))
                rootNode.add(severityNode)

                items.forEach { finding ->
                    val findingNode = DefaultMutableTreeNode(TreeNode.FindingNode(finding))
                    severityNode.add(findingNode)
                    nodeByKey[findingKey(finding)] = findingNode
                }
            }

        treeModel.reload()
        TreeUtil.expandAll(tree)
    }

    fun selectFinding(finding: Finding): Boolean {
        val node = nodeByKey[findingKey(finding)] ?: return false
        val path = TreePath(node.path)
        tree.selectionPath = path
        TreeUtil.scrollToVisible(tree, path, false)
        return true
    }

    fun selectFirstFinding(): Finding? {
        val firstNode = nodeByKey.values.firstOrNull() ?: return null
        val path = TreePath(firstNode.path)
        tree.selectionPath = path
        TreeUtil.scrollToVisible(tree, path, false)
        return selectedFinding()
    }

    fun clearSelection() {
        tree.clearSelection()
    }

    private fun selectedFinding(): Finding? =
        ((tree.lastSelectedPathComponent as? DefaultMutableTreeNode)?.userObject as? TreeNode.FindingNode)?.finding

    private fun openSelectedFinding() {
        val finding = selectedFinding() ?: return
        val virtualFile = LocalFileSystem.getInstance().findFileByNioFile(finding.absolutePath) ?: return
        val descriptor = OpenFileDescriptor(
            project,
            virtualFile,
            (finding.line - 1).coerceAtLeast(0),
            ((finding.column ?: 1) - 1).coerceAtLeast(0),
        )
        descriptor.navigate(true)
    }

    private fun findingKey(finding: Finding): String =
        "${finding.absolutePath.normalize()}|${finding.line}|${finding.column}|${finding.ruleId}"

    private sealed interface TreeNode {
        data object Root : TreeNode

        data class Placeholder(
            val text: String,
        ) : TreeNode

        data class SeverityGroup(
            val severity: Severity,
            val count: Int,
        ) : TreeNode

        data class FindingNode(
            val finding: Finding,
        ) : TreeNode
    }

    private inner class FindingsTreeCellRenderer : DefaultTreeCellRenderer() {
        override fun getTreeCellRendererComponent(
            tree: javax.swing.JTree,
            value: Any?,
            selected: Boolean,
            expanded: Boolean,
            leaf: Boolean,
            row: Int,
            hasFocus: Boolean,
        ): Component {
            super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus)

            val userObject = (value as? DefaultMutableTreeNode)?.userObject
            toolTipText = null
            when (userObject) {
                is TreeNode.Placeholder -> {
                    text = userObject.text
                    icon = AllIcons.General.Information
                }

                is TreeNode.SeverityGroup -> {
                    text = "${userObject.severity.displayName} (${userObject.count})"
                    icon = severityIcon(userObject.severity)
                    if (!selected) {
                        foreground = severityColor(userObject.severity)
                    }
                }

                is TreeNode.FindingNode -> {
                    val finding = userObject.finding
                    val fileName = runCatching { Paths.get(finding.relativePath).fileName.toString() }.getOrElse { finding.relativePath }
                    val validationSuffix = if (finding.validationStatus == ValidationStatus.PENDING) {
                        ""
                    } else {
                        " [${finding.validationStatus.displayName}]"
                    }
                    val confidenceSuffix = finding.confidence?.let { " · $it%" }.orEmpty()
                    text = "$fileName:${finding.line} - ${finding.ruleId}$validationSuffix$confidenceSuffix"
                    toolTipText = finding.message
                    icon = findingIcon(finding)
                    if (!selected) {
                        foreground = severityColor(finding.severity)
                    }
                }
            }

            return this
        }

        private fun severityIcon(severity: Severity) =
            when (severity) {
                Severity.CRITICAL,
                Severity.HIGH,
                -> AllIcons.General.Error

                Severity.MEDIUM -> AllIcons.General.Warning
                Severity.LOW,
                Severity.INFO,
                Severity.UNKNOWN,
                -> AllIcons.General.Information
            }

        private fun findingIcon(finding: Finding) =
            when (finding.validationStatus) {
                ValidationStatus.CONFIRMED -> severityIcon(finding.severity)
                ValidationStatus.NEEDS_REVIEW -> AllIcons.General.Warning
                ValidationStatus.ERROR -> AllIcons.General.Error
                ValidationStatus.DISMISSED -> AllIcons.General.Information
                ValidationStatus.PENDING -> severityIcon(finding.severity)
            }

        private fun severityColor(severity: Severity): java.awt.Color =
            when (severity) {
                Severity.CRITICAL -> Color(0xB71C1C)
                Severity.HIGH -> Color(0xBF360C)
                Severity.MEDIUM -> Color(0xA16207)
                Severity.LOW -> Color(0x2E7D32)
                Severity.INFO -> Color(0x0288D1)
                Severity.UNKNOWN -> Color(0x607D8B)
            }
    }
}
