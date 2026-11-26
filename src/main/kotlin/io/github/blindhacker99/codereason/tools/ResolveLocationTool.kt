package io.github.blindhacker99.codereason.tools

import de.fraunhofer.aisec.cpg.passes.Description
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class ResolveLocationPayload(
    @Description("Source file path or suffix.") val file: String,
    @Description("One-based source line.") val line: Int,
)

@Serializable
data class LocationCandidate(
    val nodeId: String,
    val nodeType: String?,
    val code: String?,
    val file: String?,
    val line: Int?,
    val dfgNextCount: Int,
    val dfgPrevCount: Int,
)

@Serializable
data class ResolveLocationResult(
    val file: String,
    val line: Int,
    val candidates: List<LocationCandidate>,
)

fun Server.addResolveLocationTool() {
    addTool<ResolveLocationPayload>(
        name = "reason_resolve_location",
        description = "List all CPG nodes at a file and line with their current-analysis IDs and data-flow edge counts. " +
            "Use an exact nodeId in reason_query_dataflow or reason_trace_taint_path when a line contains multiple nodes. " +
            "IDs are valid only until the next reason_analyze_project call.",
    ) { payload ->
        require(payload.line > 0) { "line must be positive" }
        val candidates = candidateNodesAtLocation(requireAnalysisResult(), payload.file, payload.line)
            .map { node ->
                LocationCandidate(
                    nodeId = node.id.toString(),
                    nodeType = node::class.simpleName,
                    code = node.code?.take(160),
                    file = node.location?.artifactLocation?.fileName,
                    line = node.location?.region?.startLine,
                    dfgNextCount = node.nextDFG.size,
                    dfgPrevCount = node.prevDFG.size,
                )
            }
        CallToolResult(content = listOf(TextContent(Json.encodeToString(
            ResolveLocationResult(payload.file, payload.line, candidates)
        ))))
    }
}
