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
    @Description("Source file path (e.g. src/main/java/com/example/Foo.java). Required with sourceLine, sinkFile, sinkLine.")
    val sourceFile: String? = null,
    @Description("Source line number (1-based) where tainted data originates.")
    val sourceLine: Int? = null,
    @Description("Sink file path where tainted data is consumed.")
    val sinkFile: String? = null,
    @Description("Sink line number (1-based) where tainted data is consumed.")
    val sinkLine: Int? = null,
    @Description("Optional shortcut: finding ID from a prior reason_scan_injections call. Use this only when replaying a scanner-reported finding; otherwise prefer source/sink coordinates.")
    val findingId: String? = null,
)

fun Server.addTraceTaintPathTool() {
    addTool<TraceTaintPathPayload>(
        name = "reason_trace_taint_path",
        description =
            "Trace the data-flow path between any two points in the code, returning every " +
                "intermediate step with code context. Primary input: source and sink coordinates " +
                "(sourceFile/sourceLine + sinkFile/sinkLine) — use this whenever you know where " +
                "tainted data enters and where it is consumed, even if reason_scan_injections did " +
                "not flag the flow. As a shortcut, pass findingId to replay a scanner-reported " +
                "finding.",
    ) { payload ->
        val result = requireAnalysisResult()
        val chainBuilder = EvidenceChainBuilder()

        if (payload.sourceFile != null && payload.sourceLine != null &&
            payload.sinkFile != null && payload.sinkLine != null) {
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

        } else if (payload.findingId != null) {
            val finding = lastScanFindings.find { it.id == payload.findingId }
                ?: throw IllegalArgumentException("Finding not found: ${payload.findingId}. Run reason_scan_injections first.")

            val sourceNode = result.nodes.find { it.id.toString() == finding.source.nodeId }
                ?: throw IllegalStateException("Source node no longer found: ${finding.source.nodeId}")
            val sinkNode = result.nodes.find { it.id.toString() == finding.sink.nodeId }
                ?: throw IllegalStateException("Sink node no longer found: ${finding.sink.nodeId}")

            val chain = traceAndBuildChain(sourceNode, sinkNode, finding.vulnClass, chainBuilder)
            CallToolResult(content = listOf(TextContent(Json.encodeToString(chain))))

        } else {
            throw IllegalArgumentException(
                "Provide source and sink coordinates (all four of sourceFile, sourceLine, sinkFile, sinkLine), " +
                    "or alternatively a findingId from reason_scan_injections."
            )
        }
    }
}

internal fun traceAndBuildChain(
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

    // CPG query paths interleave Node objects with edge objects (e.g.
    // ContextSensitiveDataflow). filterIsInstance<Node>() drops the edges so
    // callers see a clean List<Node>; an unchecked cast here would silently
    // accept an edge as a Node and crash later.
    for (child in queryTree.children) {
        if (child.value == true) {
            for (pathChild in child.children) {
                val pathValue = pathChild.value
                if (pathValue is List<*>) {
                    val nodes = pathValue.filterIsInstance<Node>()
                    if (nodes.isNotEmpty()) {
                        return nodes
                    }
                }
            }
        }
    }
    return null
}
