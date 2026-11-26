package io.github.blindhacker99.codereason.analysis

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.expressions.Call
import io.github.blindhacker99.codereason.model.AnalysisGap

/** A bounded walk over the CPG's existing data-flow edges, with explicit coverage diagnostics. */
data class DataflowTraversalResult(
    val reachable: List<Node>,
    val stoppedAt: List<AnalysisGap>,
    val truncated: Boolean,
)

fun traverseDataflow(start: Node, direction: String, maxNodes: Int): DataflowTraversalResult {
    require(maxNodes > 0) { "maxNodes must be positive" }
    require(direction == "forward" || direction == "backward") {
        "Direction must be 'forward' or 'backward'"
    }

    val reachable = mutableListOf<Node>()
    val gaps = linkedMapOf<String, AnalysisGap>()
    val visited = mutableSetOf(start)
    val queue = ArrayDeque<Node>()
    queue.add(start)

    while (queue.isNotEmpty() && reachable.size < maxNodes) {
        val current = queue.removeFirst()
        if (current != start) reachable.add(current)

        val neighbors = if (direction == "forward") current.nextDFG else current.prevDFG
        if (neighbors.isEmpty() && direction == "forward") {
            classifyForwardGap(current)?.let { gaps[it.nodeId] = it }
        }
        for (neighbor in neighbors) {
            if (visited.add(neighbor)) queue.add(neighbor)
        }
    }

    return DataflowTraversalResult(
        reachable = reachable,
        stoppedAt = gaps.values.toList(),
        truncated = queue.isNotEmpty(),
    )
}

/** Only label call dead ends for which the missing model is visible in the CPG. */
private fun classifyForwardGap(node: Node): AnalysisGap? {
    val call = node as? Call ?: return null
    val reason = when {
        call.name.localName in setOf("invoke", "forName", "getMethod", "getDeclaredMethod") ->
            "REFLECTION_CALL_WITHOUT_DFG"
        call.invokes.isEmpty() -> "UNRESOLVED_CALL"
        call.invokes.all { it.isInferred } -> "INFERRED_CALL_WITHOUT_DFG"
        else -> return null
    }
    return AnalysisGap(
        nodeId = call.id.toString(),
        reason = reason,
        code = call.code?.take(160),
        file = call.location?.artifactLocation?.fileName,
        line = call.location?.region?.startLine,
    )
}
