package io.github.blindhacker99.codereason.tools

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.passes.Description
import io.github.blindhacker99.codereason.analysis.traverseDataflow
import io.github.blindhacker99.codereason.model.AnalysisGap
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class QueryDataflowPayload(
    @Description("File path (or suffix) of the starting node.")
    val file: String? = null,
    @Description("Line number of the starting node.")
    val line: Int? = null,
    @Description("Exact node ID from the current analysis. Use when file and line have multiple nodes.")
    val nodeId: String? = null,
    @Description("Direction of data flow: forward (where does data go?) or backward (where does data come from?). Default: forward.")
    val direction: String? = null,
    @Description("Maximum number of nodes to return in the reachable set. Default: 50.")
    val maxNodes: Int? = null,
)

@Serializable
data class DataflowNodeInfo(
    val nodeId: String,
    val nodeType: String?,
    val code: String?,
    val file: String?,
    val line: Int?,
    val dfgNextCount: Int,
    val dfgPrevCount: Int,
)

@Serializable
data class QueryDataflowResult(
    val startNode: DataflowNodeInfo,
    val direction: String,
    val totalReachable: Int,
    val reachableNodes: List<DataflowNodeInfo>,
    val status: String,
    val stoppedAt: List<AnalysisGap>,
    val truncated: Boolean,
)

fun Server.addQueryDataflowTool() {
    addTool<QueryDataflowPayload>(
        name = "reason_query_dataflow",
        description =
            "Query data flow reachability from a given code location. Shows all nodes reachable " +
                "via DFG edges in the specified direction. Use forward to see where data flows to " +
                "(e.g., from a source). Use backward to see where data comes from (e.g., into a sink). " +
                "Requires reason_analyze_project first. If a location is ambiguous, call reason_resolve_location and use a node ID. " +
                "A finished traversal describes the current CPG graph, not proof that an unmodeled flow is impossible.",
    ) { payload ->
        val result = requireAnalysisResult()
        val maxNodes = payload.maxNodes ?: 50
        require(maxNodes in 1..10_000) { "maxNodes must be between 1 and 10000" }
        val directionStr = (payload.direction ?: "forward").lowercase()
        val startNode = resolveDataflowNode(result, payload.file, payload.line, payload.nodeId)
        val traversal = traverseDataflow(startNode, directionStr, maxNodes)

        val startInfo = nodeToInfo(startNode)
        val reachableInfos = traversal.reachable
            .map { nodeToInfo(it) }
            .sortedWith(compareBy({ it.file }, { it.line ?: Int.MAX_VALUE }))

        val queryResult = QueryDataflowResult(
            startNode = startInfo,
            direction = directionStr,
            totalReachable = traversal.reachable.size,
            reachableNodes = reachableInfos,
            status = if (traversal.truncated || traversal.stoppedAt.isNotEmpty()) "incomplete" else "finished",
            stoppedAt = traversal.stoppedAt,
            truncated = traversal.truncated,
        )

        CallToolResult(content = listOf(TextContent(Json.encodeToString(queryResult))))
    }
}

/**
 * Find the best CPG node at a given file/line for data flow analysis.
 * Prefers Call nodes, then nodes with DFG edges.
 */
private fun nodeToInfo(node: Node): DataflowNodeInfo {
    return DataflowNodeInfo(
        nodeId = node.id.toString(),
        nodeType = node::class.simpleName,
        code = node.code?.take(100),
        file = node.location?.artifactLocation?.fileName,
        line = node.location?.region?.startLine,
        dfgNextCount = node.nextDFG.size,
        dfgPrevCount = node.prevDFG.size,
    )
}
