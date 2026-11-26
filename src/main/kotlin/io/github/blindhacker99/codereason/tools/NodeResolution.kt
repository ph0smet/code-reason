package io.github.blindhacker99.codereason.tools

import de.fraunhofer.aisec.cpg.graph.*

internal fun candidateNodesAtLocation(
    result: de.fraunhofer.aisec.cpg.TranslationResult,
    file: String,
    line: Int,
): List<Node> = result.nodes.filter { node ->
    node.location?.artifactLocation?.fileName?.endsWith(file) == true &&
        node.location?.region?.startLine == line
}
/** Resolve an exact node, or return all same-line candidates to make ambiguity visible. */
internal fun resolveDataflowNode(
    result: de.fraunhofer.aisec.cpg.TranslationResult,
    file: String?,
    line: Int?,
    nodeId: String?,
): Node {
    if (nodeId != null) {
        return result.nodes.find { it.id.toString() == nodeId }
            ?: throw IllegalArgumentException("Node ID $nodeId is not in the current analysis. Analyze again and resolve its location.")
    }
    require(file != null && line != null) { "Provide nodeId or both file and line." }
    val candidates = candidateNodesAtLocation(result, file, line)
    if (candidates.isEmpty()) throw IllegalArgumentException("No node found at $file:$line")
    if (candidates.size == 1) return candidates.single()
    throw IllegalArgumentException(
        "Multiple nodes at $file:$line (${candidates.size}). Call reason_resolve_location to list candidates, then select a nodeId from the current analysis."
    )
}
