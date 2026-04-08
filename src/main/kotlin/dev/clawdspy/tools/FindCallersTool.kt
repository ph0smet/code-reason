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
data class FindCallersPayload(
    @Description("Function name to find callers for. Matches by simple name or fully qualified name.")
    val functionName: String? = null,
    @Description("File path (or suffix) to locate the function. Use with line.")
    val file: String? = null,
    @Description("Line number where the function is declared. Use with file.")
    val line: Int? = null,
)

@Serializable
data class CallerInfo(
    val callerFunction: String,
    val callerFile: String?,
    val callerLine: Int?,
    val callSiteCode: String?,
    val callSiteLine: Int?,
)

@Serializable
data class FindCallersResult(
    val targetFunction: String,
    val targetFile: String?,
    val targetLine: Int?,
    val totalCallers: Int,
    val callers: List<CallerInfo>,
)

fun Server.addFindCallersTool() {
    addTool<FindCallersPayload>(
        name = "spy_find_callers",
        description =
            "Find all functions that call a given function. Useful for understanding how a " +
                "function is used and tracing data flow backwards through the call graph. " +
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
            val callerFunctions = result.callersOf(targetFunc)

            // Also find the specific call sites (Call nodes that invoke this function)
            val callSites = result.calls.filter { call ->
                call.invokes.any { it == targetFunc }
            }

            val callerInfos = callerFunctions.map { callerFunc ->
                // Find the specific call site(s) within this caller
                val callSite = callSites.find { call ->
                    callerFunc.calls.contains(call)
                }

                CallerInfo(
                    callerFunction = callerFunc.name.toString(),
                    callerFile = callerFunc.location?.artifactLocation?.fileName,
                    callerLine = callerFunc.location?.region?.startLine,
                    callSiteCode = callSite?.code?.take(100),
                    callSiteLine = callSite?.location?.region?.startLine,
                )
            }.sortedBy { it.callerFile }

            FindCallersResult(
                targetFunction = targetFunc.name.toString(),
                targetFile = targetFunc.location?.artifactLocation?.fileName,
                targetLine = targetFunc.location?.region?.startLine,
                totalCallers = callerInfos.size,
                callers = callerInfos,
            )
        }

        CallToolResult(content = listOf(TextContent(Json.encodeToString(allResults))))
    }
}

internal fun resolveTargetFunctions(
    result: de.fraunhofer.aisec.cpg.TranslationResult,
    functionName: String?,
    file: String?,
    line: Int?,
): List<Function> {
    if (functionName != null) {
        // Match by name — try exact match first, then suffix match
        val byExact = result.functions.filter { it.name.toString() == functionName }
        if (byExact.isNotEmpty()) return byExact

        val bySimpleName = result.functions.filter {
            it.name.localName == functionName || it.name.toString().endsWith(".$functionName")
        }
        return bySimpleName
    }

    if (file != null && line != null) {
        return result.functions.filter { func ->
            func.location?.artifactLocation?.fileName?.endsWith(file) == true &&
                func.location?.region?.startLine == line
        }
    }

    throw IllegalArgumentException(
        "Provide either functionName or both file and line to identify the target function."
    )
}
