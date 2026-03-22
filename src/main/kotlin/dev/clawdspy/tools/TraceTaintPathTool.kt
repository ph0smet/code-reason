package dev.clawdspy.tools

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.expressions.Call
import de.fraunhofer.aisec.cpg.passes.Description
import de.fraunhofer.aisec.cpg.query.May
import de.fraunhofer.aisec.cpg.query.dataFlow
import dev.clawdspy.analysis.MatchedNode
import dev.clawdspy.analysis.RawFinding
import dev.clawdspy.analysis.EvidenceChainBuilder
import dev.clawdspy.catalog.TaintKind
import dev.clawdspy.catalog.TaintSpec
import dev.clawdspy.catalog.VulnClass
import dev.clawdspy.catalog.LanguageProfile
import dev.clawdspy.model.EvidenceChain
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class TraceTaintPathPayload(
    @Description("Finding ID from a previous spy_scan_injections call.")
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
        name = "spy_trace_taint_path",
        description =
            "Trace the detailed taint propagation path between a source and sink, " +
                "showing every intermediate step with code context. " +
                "Use findingId from spy_scan_injections, or specify source/sink by file and line.",
    ) { payload ->
        val result = requireAnalysisResult()
        val chainBuilder = EvidenceChainBuilder()

        if (payload.findingId != null) {
            // Look up finding from cache and re-run detailed trace
            val finding = lastScanFindings.find { it.id == payload.findingId }
                ?: throw IllegalArgumentException("Finding not found: ${payload.findingId}. Run spy_scan_injections first.")

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
            val sourceNode = result.nodes.find { node ->
                node.location?.artifactLocation?.fileName?.endsWith(payload.sourceFile) == true &&
                    node.location?.region?.startLine == payload.sourceLine
            } ?: throw IllegalArgumentException(
                "No node found at ${payload.sourceFile}:${payload.sourceLine}"
            )
            val sinkNode = result.nodes.find { node ->
                node.location?.artifactLocation?.fileName?.endsWith(payload.sinkFile) == true &&
                    node.location?.region?.startLine == payload.sinkLine
            } ?: throw IllegalArgumentException(
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
        catalog = object : dev.clawdspy.catalog.SourceSinkCatalog {
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
