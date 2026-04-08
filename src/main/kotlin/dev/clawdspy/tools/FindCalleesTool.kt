package dev.clawdspy.tools

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.declarations.Function
import de.fraunhofer.aisec.cpg.passes.Description
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class FindCalleesPayload(
    @Description("Function name to find callees for. Matches by simple name or fully qualified name.")
    val functionName: String? = null,
    @Description("File path (or suffix) to locate the function. Use with line.")
    val file: String? = null,
    @Description("Line number where the function is declared. Use with file.")
    val line: Int? = null,
)

@Serializable
data class CalleeInfo(
    val calleeName: String,
    val calleeFile: String?,
    val calleeLine: Int?,
    val callSiteCode: String?,
    val callSiteLine: Int?,
)

@Serializable
data class FindCalleesResult(
    val targetFunction: String,
    val targetFile: String?,
    val targetLine: Int?,
    val totalCallees: Int,
    val callees: List<CalleeInfo>,
)

fun Server.addFindCalleesTool() {
    addTool<FindCalleesPayload>(
        name = "spy_find_callees",
        description =
            "Find all functions called by a given function. Useful for understanding what a " +
                "function does and tracing data flow forward through the call graph. " +
                "Specify either functionName or file+line. Requires spy_analyze_project first.",
    ) { payload ->
        val result = requireAnalysisResult()

        val targetFunctions = resolveTargetFunctions(result, payload.functionName, payload.file, payload.line)

        if (targetFunctions.isEmpty()) {
            throw IllegalArgumentException(
                "No function found matching: " +
                    listOfNotNull(
                        payload.functionName?.let { "name=$it" },
                        payload.file?.let { "file=$it" },
                        payload.line?.let { "line=$it" },
                    ).joinToString(", ")
            )
        }

        val allResults = targetFunctions.map { targetFunc ->
            val calleeFunctions = targetFunc.callees

            // Map each callee to its call site within the target function
            val calleeInfos = calleeFunctions.map { calleeFunc ->
                val callSite = targetFunc.calls.find { call ->
                    call.invokes.any { it == calleeFunc }
                }

                CalleeInfo(
                    calleeName = calleeFunc.name.toString(),
                    calleeFile = calleeFunc.location?.artifactLocation?.fileName,
                    calleeLine = calleeFunc.location?.region?.startLine,
                    callSiteCode = callSite?.code?.take(100),
                    callSiteLine = callSite?.location?.region?.startLine,
                )
            }.sortedBy { it.callSiteLine ?: Int.MAX_VALUE }

            FindCalleesResult(
                targetFunction = targetFunc.name.toString(),
                targetFile = targetFunc.location?.artifactLocation?.fileName,
                targetLine = targetFunc.location?.region?.startLine,
                totalCallees = calleeInfos.size,
                callees = calleeInfos,
            )
        }

        CallToolResult(content = listOf(TextContent(Json.encodeToString(allResults))))
    }
}
