package io.github.blindhacker99.codereason.tools

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.functions
import de.fraunhofer.aisec.cpg.graph.declarations.Function
import de.fraunhofer.aisec.cpg.passes.Description
import io.github.blindhacker99.codereason.analysis.CallGraphNavigator
import io.github.blindhacker99.codereason.analysis.EntryPointFinder
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class SliceCallGraphPayload(
    @Description("Function name (simple or fully qualified). Use a file and line or functionId if ambiguous.")
    val functionName: String? = null,
    @Description("Function declaration file or suffix, used with line.") val file: String? = null,
    @Description("Function declaration line, used with file.") val line: Int? = null,
    @Description("Exact function node ID from the current analysis.") val functionId: String? = null,
    @Description("forward for callees or backward for callers. Default: forward.") val direction: String? = null,
    @Description("Maximum call hops from the root, 0-30. Default: 4.") val maxDepth: Int? = null,
    @Description("Maximum functions including the root, 1-5000. Default: 100.") val maxFunctions: Int? = null,
)

@Serializable
data class FindCallPathsPayload(
    @Description("Target function name (simple or fully qualified).") val targetFunctionName: String? = null,
    @Description("Target declaration file or suffix, used with targetLine.") val targetFile: String? = null,
    @Description("Target declaration line, used with targetFile.") val targetLine: Int? = null,
    @Description("Exact target function node ID from the current analysis.") val targetFunctionId: String? = null,
    @Description("Optional source function name. Omit all source selectors to start from detected entrypoints.")
    val sourceFunctionName: String? = null,
    @Description("Source declaration file or suffix, used with sourceLine.") val sourceFile: String? = null,
    @Description("Source declaration line, used with sourceFile.") val sourceLine: Int? = null,
    @Description("Exact source function node ID from the current analysis.") val sourceFunctionId: String? = null,
    @Description("Maximum call hops, 0-30. Default: 8.") val maxDepth: Int? = null,
    @Description("Maximum paths to return, 1-100. Default: 10.") val maxPaths: Int? = null,
    @Description("Maximum call edges to explore, 1-100000. Default: 5000.") val maxExploredEdges: Int? = null,
)

fun Server.addSliceCallGraphTool() {
    addTool<SliceCallGraphPayload>(
        name = "reason_slice_call_graph",
        description = "Find a bounded transitive caller or callee slice with call-site evidence, observed unresolved calls, and explicit truncation. " +
            "This is call reachability, not attacker-controlled data flow. Requires reason_analyze_project first.",
    ) { payload ->
        val result = requireAnalysisResult()
        val root = resolveUniqueFunction(result, payload.functionName, payload.file, payload.line, payload.functionId)
        val slice = CallGraphNavigator(result).slice(
            root,
            (payload.direction ?: "forward").lowercase(),
            payload.maxDepth ?: 4,
            payload.maxFunctions ?: 100,
        )
        CallToolResult(content = listOf(TextContent(Json.encodeToString(slice))))
    }
}

fun Server.addFindCallPathsTool() {
    addTool<FindCallPathsPayload>(
        name = "reason_find_call_paths",
        description = "Find bounded call paths from a named source function or detected entrypoints to a target. " +
            "Shows call sites and observed unresolved calls; an absent path is not proof of impossibility. " +
            "These are call paths, not data-flow or taint paths. Requires reason_analyze_project first.",
    ) { payload ->
        val result = requireAnalysisResult()
        val target = resolveUniqueFunction(
            result, payload.targetFunctionName, payload.targetFile, payload.targetLine, payload.targetFunctionId
        )
        val sourceSpecified = listOf(
            payload.sourceFunctionName, payload.sourceFile, payload.sourceFunctionId
        ).any { it != null } || payload.sourceLine != null
        val sources = if (sourceSpecified) {
            listOf(resolveUniqueFunction(result, payload.sourceFunctionName, payload.sourceFile, payload.sourceLine, payload.sourceFunctionId))
        } else {
            val entries = EntryPointFinder(result).findEntryPoints()
            result.functions.filter { function ->
                entries.any { entry ->
                    entry.functionName == function.name.toString() &&
                        entry.file == function.location?.artifactLocation?.fileName &&
                        entry.line == function.location?.region?.startLine
                }
            }
        }
        require(sources.isNotEmpty()) {
            "No detected entrypoints. Supply a source function explicitly or inspect reason_find_entry_points."
        }
        val paths = CallGraphNavigator(result).paths(
            sources, target, payload.maxDepth ?: 8, payload.maxPaths ?: 10,
            payload.maxExploredEdges ?: 5_000,
        )
        CallToolResult(content = listOf(TextContent(Json.encodeToString(paths))))
    }
}

internal fun resolveUniqueFunction(
    result: TranslationResult,
    functionName: String?,
    file: String?,
    line: Int?,
    functionId: String?,
): Function {
    if (functionId != null) {
        return result.functions.find { it.id.toString() == functionId }
            ?: throw IllegalArgumentException("Function ID $functionId is not in the current analysis")
    }
    require((file == null) == (line == null)) { "Provide both file and line, or neither." }
    val byLocation = if (file != null && line != null) {
        result.functions.filter { function ->
            function.location?.artifactLocation?.fileName?.endsWith(file) == true &&
                function.location?.region?.startLine == line
        }
    } else null
    val byName = if (functionName != null) resolveTargetFunctions(result, functionName, null, null) else null
    val functions = when {
        byLocation != null && byName != null -> byLocation.filter { it in byName }
        byLocation != null -> byLocation
        byName != null -> byName
        else -> throw IllegalArgumentException("Provide a function name, file+line, or functionId")
    }
    if (functions.isEmpty()) throw IllegalArgumentException("No matching function found")
    if (functions.size > 1) {
        val choices = functions.take(20).joinToString("; ") { function ->
            "${function.id} ${function.name} ${function.location?.artifactLocation?.fileName}:${function.location?.region?.startLine}"
        }
        throw IllegalArgumentException("Ambiguous function (${functions.size} matches). Select by file+line or functionId: $choices")
    }
    return functions.single()
}
