package dev.clawdspy.tools

import de.fraunhofer.aisec.cpg.passes.Description
import dev.clawdspy.analysis.EntryPointFinder
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class FindEntryPointsPayload(
    @Description("Filter entry points by type: http, cli, all. Default: all.")
    val filter: String? = null,
)

@Serializable
data class EntryPointsResult(
    val totalEntryPoints: Int,
    val byType: Map<String, Int>,
    val byFramework: Map<String, Int>,
    val entryPoints: List<dev.clawdspy.analysis.EntryPoint>,
)

fun Server.addFindEntryPointsTool() {
    addTool<FindEntryPointsPayload>(
        name = "spy_find_entry_points",
        description =
            "Identify HTTP handlers, API endpoints, CLI entry points, and other attack surface " +
                "in the analyzed code. Detects Spring, Servlet, JAX-RS, Flask, and Django handlers. " +
                "Requires spy_analyze_project to be called first.",
    ) { payload ->
        val result = requireAnalysisResult()
        val finder = EntryPointFinder(result)
        val entryPoints = finder.findEntryPoints(payload.filter)

        val byType = entryPoints.groupBy { it.type }.mapValues { it.value.size }
        val byFramework = entryPoints
            .mapNotNull { it.framework }
            .groupBy { it }
            .mapValues { it.value.size }

        val response = EntryPointsResult(
            totalEntryPoints = entryPoints.size,
            byType = byType,
            byFramework = byFramework,
            entryPoints = entryPoints,
        )

        CallToolResult(
            content = listOf(TextContent(Json.encodeToString(response)))
        )
    }
}
