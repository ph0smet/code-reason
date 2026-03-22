package dev.clawdspy.analysis

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.declarations.Declaration
import de.fraunhofer.aisec.cpg.graph.declarations.Parameter
import de.fraunhofer.aisec.cpg.graph.declarations.Variable
import de.fraunhofer.aisec.cpg.graph.expressions.*
import dev.clawdspy.model.EvidenceChain
import dev.clawdspy.model.EvidenceStep
import dev.clawdspy.model.LocationInfo
import dev.clawdspy.model.ReasoningInfo

class EvidenceChainBuilder {

    fun buildChain(finding: RawFinding): EvidenceChain {
        val steps = finding.pathNodes.mapIndexed { index, node ->
            EvidenceStep(
                step = index + 1,
                nodeId = node.id.toString(),
                nodeType = node::class.simpleName,
                code = node.code,
                file = node.location?.artifactLocation?.fileName,
                line = node.location?.region?.startLine,
                explanation = explainNode(node, index, finding),
            )
        }

        return EvidenceChain(
            source = toLocationInfo(finding.source),
            sink = toLocationInfo(finding.sink),
            reachable = true,
            sanitized = finding.sanitized,
            pathLength = finding.pathNodes.size,
            steps = steps,
            reasoning = buildReasoning(finding),
        )
    }

    private fun explainNode(node: Node, index: Int, finding: RawFinding): String {
        val isFirst = index == 0
        val isLast = index == finding.pathNodes.size - 1

        if (isFirst) {
            return "Taint source: ${finding.source.spec.description} — " +
                "user-controlled input enters here"
        }

        if (isLast) {
            return "Taint sink: ${finding.sink.spec.description} — " +
                "tainted value reaches dangerous operation"
        }

        return when (node) {
            is Call -> "Function call '${node.name.localName}' — tainted data flows through call"
            is Variable -> "Variable '${node.name.localName}' — tainted value assigned"
            is Parameter -> "Parameter '${node.name.localName}' — tainted value passed as argument"
            is Reference -> "Reference to '${node.name.localName}' — tainted value read"
            is BinaryOperator -> "Binary operation '${node.operatorCode}' — tainted value used in expression"
            is Literal<*> -> "Literal value — data transformation"
            is Declaration -> "Declaration '${node.name.localName}' — tainted value stored"
            is Assign -> "Assignment — tainted value propagated"
            else -> "Node '${node::class.simpleName}' — tainted data propagates"
        }
    }

    private fun buildReasoning(finding: RawFinding): ReasoningInfo {
        val sourceName = finding.source.node.code ?: finding.source.spec.fqn
        val sinkName = finding.sink.node.code ?: finding.sink.spec.fqn

        val summary = if (finding.sanitized) {
            "Data flow from '$sourceName' reaches '$sinkName' but passes through a sanitizer"
        } else {
            "Data flow from '$sourceName' reaches '$sinkName' without sanitization"
        }

        return ReasoningInfo(
            queryTreeSummary = summary,
            assumptions = buildAssumptionList(finding),
            confidence = ConfidenceScorer.score(finding),
        )
    }

    private fun buildAssumptionList(finding: RawFinding): List<String> {
        val assumptions = mutableListOf<String>()
        assumptions.add("Interprocedural analysis assumed complete DFG construction")

        if (finding.pathNodes.size > 10) {
            assumptions.add("Long taint path (${finding.pathNodes.size} nodes) — may include false positive propagation")
        }

        return assumptions
    }

    companion object {
        fun toLocationInfo(matched: MatchedNode): LocationInfo {
            return LocationInfo(
                nodeId = matched.node.id.toString(),
                code = matched.node.code,
                file = matched.node.location?.artifactLocation?.fileName,
                line = matched.node.location?.region?.startLine,
                column = matched.node.location?.region?.startColumn,
                description = matched.spec.description,
            )
        }
    }
}
