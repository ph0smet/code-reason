package dev.clawdspy.tools

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.expressions.Call
import de.fraunhofer.aisec.cpg.passes.Description
import de.fraunhofer.aisec.cpg.query.May
import de.fraunhofer.aisec.cpg.query.dataFlow
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class QueryDataflowPayload(
    @Description("File path (or suffix) of the starting node.")
    val file: String,
    @Description("Line number of the starting node.")
    val line: Int,
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
)

fun Server.addQueryDataflowTool() {
    addTool<QueryDataflowPayload>(
        name = "spy_query_dataflow",
        description =
            "Query data flow reachability from a given code location. Shows all nodes reachable " +
                "via DFG edges in the specified direction. Use forward to see where data flows to " +
                "(e.g., from a source). Use backward to see where data comes from (e.g., into a sink). " +
                "Requires spy_analyze_project first.",
    ) { payload ->
        val result = requireAnalysisResult()
        val maxNodes = payload.maxNodes ?: 50
        val directionStr = (payload.direction ?: "forward").lowercase()

        val startNode = findBestNodeAtLocation(result, payload.file, payload.line)
            ?: throw IllegalArgumentException("No node found at ${payload.file}:${payload.line}")

        val analysisDirection = when (directionStr) {
            "forward" -> Forward(GraphToFollow.DFG)
            "backward" -> Backward(GraphToFollow.DFG)
            else -> throw IllegalArgumentException(
                "Invalid direction: $directionStr. Use 'forward' or 'backward'."
            )
        }

        // Collect reachable nodes by traversing DFG edges
        val reachable = mutableSetOf<Node>()
        val visited = mutableSetOf<Node>()
        val queue = ArrayDeque<Node>()
        queue.add(startNode)
        visited.add(startNode)

        while (queue.isNotEmpty() && reachable.size < maxNodes) {
            val current = queue.removeFirst()
            if (current != startNode) {
                reachable.add(current)
            }

            val neighbors = when (directionStr) {
                "forward" -> current.nextDFG
                "backward" -> current.prevDFG
                else -> emptySet()
            }

            for (neighbor in neighbors) {
                if (neighbor !in visited) {
                    visited.add(neighbor)
                    queue.add(neighbor)
                }
            }
        }

        val startInfo = nodeToInfo(startNode)
        val reachableInfos = reachable
            .map { nodeToInfo(it) }
            .sortedWith(compareBy({ it.file }, { it.line ?: Int.MAX_VALUE }))

        val queryResult = QueryDataflowResult(
            startNode = startInfo,
            direction = directionStr,
            totalReachable = reachable.size,
            reachableNodes = reachableInfos,
        )

        CallToolResult(content = listOf(TextContent(Json.encodeToString(queryResult))))
    }
}

/**
 * Find the best CPG node at a given file/line for data flow analysis.
 * Prefers Call nodes, then nodes with DFG edges.
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

    candidates.firstOrNull { it is Call }?.let { return it }
    candidates.firstOrNull { it.nextDFG.isNotEmpty() || it.prevDFG.isNotEmpty() }?.let { return it }
    return candidates.first()
}

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
