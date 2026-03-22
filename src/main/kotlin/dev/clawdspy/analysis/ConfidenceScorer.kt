package dev.clawdspy.analysis

import de.fraunhofer.aisec.cpg.graph.declarations.Function

object ConfidenceScorer {

    fun score(finding: RawFinding): Double {
        var confidence = 1.0

        // Longer paths = lower confidence (more room for false positives)
        val pathPenalty = (finding.pathNodes.size - 2) * 0.05
        confidence -= pathPenalty.coerceAtMost(0.5)

        // Interprocedural hops reduce confidence
        val functionBoundaries = countFunctionBoundaries(finding)
        confidence -= functionBoundaries * 0.05

        // Sanitizer present reduces severity but finding is still informational
        if (finding.sanitized) {
            confidence -= 0.3
        }

        return confidence.coerceIn(0.1, 1.0)
    }

    fun severity(finding: RawFinding): String {
        if (finding.sanitized) return "info"

        val confidence = score(finding)
        return when {
            confidence >= 0.8 -> "high"
            confidence >= 0.5 -> "medium"
            confidence >= 0.3 -> "low"
            else -> "info"
        }
    }

    private fun countFunctionBoundaries(finding: RawFinding): Int {
        var boundaries = 0
        var currentFunction: Function? = null

        for (node in finding.pathNodes) {
            val nodeFunction = findEnclosingFunction(node)
            if (nodeFunction != null && nodeFunction != currentFunction) {
                if (currentFunction != null) {
                    boundaries++
                }
                currentFunction = nodeFunction
            }
        }

        return boundaries
    }

    private fun findEnclosingFunction(node: de.fraunhofer.aisec.cpg.graph.Node): Function? {
        var current: de.fraunhofer.aisec.cpg.graph.Node? = node
        while (current != null) {
            if (current is Function) return current
            current = current.astParent
        }
        return null
    }
}
