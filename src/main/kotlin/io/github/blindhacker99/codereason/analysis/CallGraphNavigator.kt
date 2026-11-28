package io.github.blindhacker99.codereason.analysis

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.declarations.Function
import de.fraunhofer.aisec.cpg.graph.expressions.Call
import kotlinx.serialization.Serializable

@Serializable
data class CallGraphFunction(
    val nodeId: String,
    val name: String,
    val file: String?,
    val line: Int?,
)

@Serializable
data class CallGraphEdge(
    val callerId: String,
    val calleeId: String,
    val callSiteCode: String?,
    val callSiteFile: String?,
    val callSiteLine: Int?,
    val targetInferred: Boolean,
    val callSiteFound: Boolean,
)

@Serializable
data class UnresolvedCall(
    val ownerId: String,
    val code: String?,
    val file: String?,
    val line: Int?,
    val reason: String,
)

@Serializable
data class CallGraphSliceNode(
    val function: CallGraphFunction,
    val depth: Int,
    val via: CallGraphEdge?,
)

@Serializable
data class CallGraphSlice(
    val root: CallGraphFunction,
    val direction: String,
    val nodes: List<CallGraphSliceNode>,
    val unresolvedCalls: List<UnresolvedCall>,
    val truncated: Boolean,
)

@Serializable
data class CallPath(
    val functions: List<CallGraphFunction>,
    val edges: List<CallGraphEdge>,
)

@Serializable
data class CallPaths(
    val target: CallGraphFunction,
    val sourcesConsidered: List<CallGraphFunction>,
    val paths: List<CallPath>,
    val unresolvedCalls: List<UnresolvedCall>,
    val truncated: Boolean,
    val status: String,
)

/** Bounded, source-located traversal of CPG call edges. No data-flow claim is implied. */
class CallGraphNavigator(private val result: TranslationResult) {
    fun slice(root: Function, direction: String, maxDepth: Int, maxFunctions: Int): CallGraphSlice {
        require(direction == "forward" || direction == "backward") { "direction must be forward or backward" }
        require(maxDepth in 0..30) { "maxDepth must be between 0 and 30" }
        require(maxFunctions in 1..5_000) { "maxFunctions must be between 1 and 5000" }

        val seen = linkedMapOf(root to CallGraphSliceNode(info(root), 0, null))
        val queue = ArrayDeque<Function>()
        val gaps = linkedMapOf<String, UnresolvedCall>()
        queue.add(root)
        var truncated = false

        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            val depth = seen.getValue(current).depth
            unresolved(current).forEach { gaps[gapKey(it)] = it }
            val neighbors = neighbors(current, direction)
            for (neighbor in neighbors) {
                if (neighbor in seen) continue
                if (depth >= maxDepth || seen.size >= maxFunctions) {
                    truncated = true
                    continue
                }
                val edge = if (direction == "forward") edge(current, neighbor) else edge(neighbor, current)
                seen[neighbor] = CallGraphSliceNode(info(neighbor), depth + 1, edge)
                queue.add(neighbor)
            }
        }

        return CallGraphSlice(info(root), direction, seen.values.toList(), gaps.values.toList(), truncated)
    }

    fun paths(
        sources: List<Function>,
        target: Function,
        maxDepth: Int,
        maxPaths: Int,
        maxExploredEdges: Int,
    ): CallPaths {
        require(maxDepth in 0..30) { "maxDepth must be between 0 and 30" }
        require(maxPaths in 1..100) { "maxPaths must be between 1 and 100" }
        require(maxExploredEdges in 1..100_000) { "maxExploredEdges must be between 1 and 100000" }

        val found = mutableListOf<CallPath>()
        val gaps = linkedMapOf<String, UnresolvedCall>()
        var exploredEdges = 0
        var truncated = false

        fun visit(current: Function, chain: List<Function>) {
            if (current == target) {
                if (found.size < maxPaths) {
                    found.add(CallPath(chain.map(::info), chain.zipWithNext().map { (a, b) -> edge(a, b) }))
                } else truncated = true
                return
            }
            unresolved(current).forEach { gaps[gapKey(it)] = it }
            val next = neighbors(current, "forward")
            for (callee in next) {
                if (callee in chain) continue
                if (chain.size - 1 >= maxDepth || found.size >= maxPaths || exploredEdges >= maxExploredEdges) {
                    truncated = true
                    continue
                }
                exploredEdges++
                visit(callee, chain + callee)
            }
        }

        val uniqueSources = sources.distinct().sortedWith(functionOrder)
        for (source in uniqueSources) {
            if (found.size >= maxPaths || exploredEdges >= maxExploredEdges) {
                truncated = true
                break
            }
            visit(source, listOf(source))
        }
        val status = when {
            found.isNotEmpty() -> "found"
            truncated || gaps.isNotEmpty() -> "incomplete"
            else -> "not_found"
        }
        return CallPaths(info(target), uniqueSources.map(::info), found, gaps.values.toList(), truncated, status)
    }

    private fun neighbors(function: Function, direction: String): List<Function> =
        (if (direction == "forward") function.callees else result.callersOf(function))
            .distinct()
            .sortedWith(functionOrder)

    private fun edge(caller: Function, callee: Function): CallGraphEdge {
        val callSite = caller.calls.firstOrNull { call -> call.invokes.any { it == callee } }
        return CallGraphEdge(
            callerId = caller.id.toString(),
            calleeId = callee.id.toString(),
            callSiteCode = callSite?.code?.take(160),
            callSiteFile = callSite?.location?.artifactLocation?.fileName,
            callSiteLine = callSite?.location?.region?.startLine,
            targetInferred = callee.isInferred,
            callSiteFound = callSite != null,
        )
    }

    private fun unresolved(owner: Function): List<UnresolvedCall> = owner.calls.mapNotNull { call ->
        val reason = when {
            call.invokes.isEmpty() -> "NO_TARGET"
            call.invokes.all { it.isInferred } -> "INFERRED_TARGET_ONLY"
            else -> return@mapNotNull null
        }
        UnresolvedCall(
            ownerId = owner.id.toString(),
            code = call.code?.take(160),
            file = call.location?.artifactLocation?.fileName,
            line = call.location?.region?.startLine,
            reason = reason,
        )
    }

    private fun gapKey(gap: UnresolvedCall) = "${gap.ownerId}:${gap.file}:${gap.line}:${gap.code}"

    companion object {
        private val functionOrder = compareBy<Function>(
            { it.location?.artifactLocation?.fileName ?: "" },
            { it.location?.region?.startLine ?: Int.MAX_VALUE },
            { it.name.toString() },
            { it.id.toString() },
        )

        fun info(function: Function) = CallGraphFunction(
            nodeId = function.id.toString(),
            name = function.name.toString(),
            file = function.location?.artifactLocation?.fileName,
            line = function.location?.region?.startLine,
        )
    }
}
