package io.github.blindhacker99.codereason.tools

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.expressions.Call

/**
 * Find the best CPG node at a given file/line for data flow analysis.
 *
 * Multiple CPG nodes can exist at the same source line (e.g., a DeclarationStatement,
 * a VariableDeclaration, a Call, and References). For data flow tracing, we prefer
 * nodes that participate in DFG edges — typically Call nodes (which produce values)
 * or References (which carry values). DeclarationStatements are containers that
 * often lack direct DFG connections.
 */
internal fun findBestNodeAtLocation(
    result: de.fraunhofer.aisec.cpg.TranslationResult,
    file: String,
    line: Int,
): Node? {
    val candidates = result.nodes.filter { node ->
        node.location?.artifactLocation?.fileName?.endsWith(file) == true &&
            node.location?.region?.startLine == line
    }

    if (candidates.isEmpty()) return null
    if (candidates.size == 1) return candidates.first()

    candidates.firstOrNull { it is Call }?.let { return it }
    candidates.firstOrNull { it.nextDFG.isNotEmpty() || it.prevDFG.isNotEmpty() }?.let { return it }
    return candidates.first()
}
