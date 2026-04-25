package io.github.blindhacker99.codereason.tools

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.expressions.Call
import de.fraunhofer.aisec.cpg.passes.Description
import de.fraunhofer.aisec.cpg.query.May
import de.fraunhofer.aisec.cpg.query.dataFlow
import io.github.blindhacker99.codereason.analysis.MatchedNode
import io.github.blindhacker99.codereason.analysis.RawFinding
import io.github.blindhacker99.codereason.analysis.EvidenceChainBuilder
import io.github.blindhacker99.codereason.catalog.TaintKind
import io.github.blindhacker99.codereason.catalog.TaintSpec
import io.github.blindhacker99.codereason.catalog.VulnClass
import io.github.blindhacker99.codereason.catalog.LanguageProfile
import io.github.blindhacker99.codereason.model.EvidenceChain
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class TraceTaintPathPayload(
    @Description("Finding ID from a previous reason_scan_injections call.")
    val findingId: String? = null,
    @Description("Source file path for custom trace (alternative to findingId).")
    val sourceFile: String? = null,
    @Description("Source line number for custom trace.")
    val sourceLine: Int? = null,
    @Description("Sink file path for custom trace.")
    val sinkFile: String? = null,
    @Description("Sink line number for custom trace.")
    val sinkLine: Int? = null,
)

fun Server.addTraceTaintPathTool() {
    addTool<TraceTaintPathPayload>(
        name = "reason_trace_taint_path",
        description =
            "Trace the detailed taint propagation path between a source and sink, " +
                "showing every intermediate step with code context. " +
                "Use findingId from reason_scan_injections, or specify source/sink by file and line.",
    ) { payload ->
        val result = requireAnalysisResult()
        val chainBuilder = EvidenceChainBuilder()

        if (payload.findingId != null) {
            // Look up finding from cache and re-run detailed trace
            val finding = lastScanFindings.find { it.id == payload.findingId }
                ?: throw IllegalArgumentException("Finding not found: ${payload.findingId}. Run reason_scan_injections first.")

            // Re-find the nodes by ID
            val sourceNode = result.nodes.find { it.id.toString() == finding.source.nodeId }
                ?: throw IllegalStateException("Source node no longer found: ${finding.source.nodeId}")
            val sinkNode = result.nodes.find { it.id.toString() == finding.sink.nodeId }
                ?: throw IllegalStateException("Sink node no longer found: ${finding.sink.nodeId}")

            val chain = traceAndBuildChain(sourceNode, sinkNode, finding.vulnClass, chainBuilder)
            CallToolResult(content = listOf(TextContent(Json.encodeToString(chain))))

        } else if (payload.sourceFile != null && payload.sourceLine != null &&
            payload.sinkFile != null && payload.sinkLine != null) {
            // Custom trace by file + line
            val sourceNode = findBestNodeAtLocation(result, payload.sourceFile, payload.sourceLine)
                ?: throw IllegalArgumentException(
                    "No node found at ${payload.sourceFile}:${payload.sourceLine}"
                )
            val sinkNode = findBestNodeAtLocation(result, payload.sinkFile, payload.sinkLine)
                ?: throw IllegalArgumentException(
                    "No node found at ${payload.sinkFile}:${payload.sinkLine}"
                )

            val chain = traceAndBuildChain(sourceNode, sinkNode, "custom", chainBuilder)
            CallToolResult(content = listOf(TextContent(Json.encodeToString(chain))))

        } else {
            throw IllegalArgumentException(
                "Provide either findingId or both sourceFile/sourceLine and sinkFile/sinkLine."
            )
        }
    }
}

/**
 * Find the best CPG node at a given file/line for data flow analysis.
 *
 * Multiple CPG nodes can exist at the same source line (e.g., a DeclarationStatement,
 * a VariableDeclaration, a Call, and References). For data flow tracing, we prefer
 * nodes that participate in DFG edges — typically Call nodes (which produce values)
 * or References (which carry values). DeclarationStatements are containers that
 * often lack direct DFG connections.
 */
private fun findBestNodeAtLocation(
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

    // Prefer Call nodes — they represent function invocations that produce/consume values
    candidates.firstOrNull { it is Call }?.let { return it }

    // Then prefer nodes that have outgoing or incoming DFG edges
    candidates.firstOrNull { it.nextDFG.isNotEmpty() || it.prevDFG.isNotEmpty() }?.let { return it }

    // Fall back to first candidate
    return candidates.first()
}

private fun traceAndBuildChain(
    sourceNode: Node,
    sinkNode: Node,
    vulnClass: String,
    chainBuilder: EvidenceChainBuilder,
): EvidenceChain {
    val queryResult = dataFlow(
        startNode = sourceNode,
        direction = Forward(GraphToFollow.DFG),
        type = May,
        scope = Interprocedural(),
        predicate = { it == sinkNode },
    )

    val pathNodes = extractFirstPath(queryResult) ?: listOf(sourceNode, sinkNode)

    val dummySpec = TaintSpec(
        vulnClass = VulnClass.entries.find { it.name.equals(vulnClass, ignoreCase = true) } ?: VulnClass.SQLI,
        language = LanguageProfile.JAVA,
        fqn = "custom",
        kind = TaintKind.SOURCE,
        description = sourceNode.code ?: "source",
    )
    val dummySinkSpec = dummySpec.copy(kind = TaintKind.SINK, description = sinkNode.code ?: "sink")

    val rawFinding = RawFinding(
        source = MatchedNode(sourceNode, dummySpec),
        sink = MatchedNode(sinkNode, dummySinkSpec),
        queryTree = queryResult,
        sanitized = false,
        catalog = object : io.github.blindhacker99.codereason.catalog.SourceSinkCatalog {
            override val vulnClass = dummySpec.vulnClass
            override val language = dummySpec.language
            override val sources = listOf(dummySpec)
            override val sinks = listOf(dummySinkSpec)
            override val sanitizers = emptyList<TaintSpec>()
        },
        pathNodes = pathNodes,
    )

    return chainBuilder.buildChain(rawFinding)
}

private fun extractFirstPath(queryTree: de.fraunhofer.aisec.cpg.query.QueryTree<Boolean>): List<Node>? {
    if (!queryTree.value) return null

    for (child in queryTree.children) {
        if (child.value == true) {
            for (pathChild in child.children) {
                val pathValue = pathChild.value
                if (pathValue is List<*>) {
                    @Suppress("UNCHECKED_CAST")
                    val nodes = pathValue as? List<Node>
                    if (nodes != null && nodes.isNotEmpty()) {
                        return nodes
                    }
                }
            }
        }
    }
    return null
}
