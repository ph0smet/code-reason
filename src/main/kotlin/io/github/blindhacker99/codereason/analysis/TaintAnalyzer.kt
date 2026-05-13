package io.github.blindhacker99.codereason.analysis

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.declarations.Function
import de.fraunhofer.aisec.cpg.graph.declarations.Parameter
import de.fraunhofer.aisec.cpg.graph.expressions.Call
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.dataFlow
import de.fraunhofer.aisec.cpg.query.May
import io.github.blindhacker99.codereason.catalog.SourceSinkCatalog
import io.github.blindhacker99.codereason.catalog.TaintKind
import io.github.blindhacker99.codereason.catalog.TaintSpec

data class MatchedNode(
    val node: Node,
    val spec: TaintSpec,
)

data class RawFinding(
    val source: MatchedNode,
    val sink: MatchedNode,
    val queryTree: QueryTree<Boolean>,
    val sanitized: Boolean,
    val catalog: SourceSinkCatalog,
    val pathNodes: List<Node>,
)

class TaintAnalyzer(private val result: TranslationResult) {

    fun analyzeCatalog(catalog: SourceSinkCatalog): List<RawFinding> {
        val sourceNodes = findMatchingNodes(catalog.sources)
        val sinkNodes = findMatchingNodes(catalog.sinks)

        if (sourceNodes.isEmpty() || sinkNodes.isEmpty()) {
            return emptyList()
        }

        val findings = mutableListOf<RawFinding>()

        for (source in sourceNodes) {
            val sinkNodeSet = sinkNodes.map { it.node }.toSet()

            val queryResult = dataFlow(
                startNode = source.node,
                direction = Forward(GraphToFollow.DFG),
                type = May,
                scope = Interprocedural(),
                predicate = { candidate -> candidate in sinkNodeSet },
            )

            if (queryResult.value) {
                val hitSinks = extractHitSinks(queryResult, sinkNodes)
                for ((sink, pathNodes) in hitSinks) {
                    val sanitized = checkSanitization(pathNodes, catalog)
                    findings.add(
                        RawFinding(
                            source = source,
                            sink = sink,
                            queryTree = queryResult,
                            sanitized = sanitized,
                            catalog = catalog,
                            pathNodes = pathNodes,
                        )
                    )
                }
            }
        }

        return findings
    }

    private fun findMatchingNodes(specs: List<TaintSpec>): List<MatchedNode> {
        val matched = mutableListOf<MatchedNode>()

        for (spec in specs) {
            when (spec.kind) {
                TaintKind.SOURCE -> {
                    // Match calls that look like source functions
                    val matchingCalls = result.calls.filter { call ->
                        matchesSpec(call, spec)
                    }
                    matched.addAll(matchingCalls.map { MatchedNode(it, spec) })

                    // Also match function parameters with matching types/annotations
                    val matchingParams = result.functions.flatMap { func ->
                        func.parameters.filter { param ->
                            matchesParamSpec(param, func, spec)
                        }
                    }
                    matched.addAll(matchingParams.map { MatchedNode(it, spec) })
                }
                TaintKind.SINK -> {
                    val matchingCalls = result.calls.filter { call ->
                        matchesSpec(call, spec)
                    }
                    matched.addAll(matchingCalls.map { MatchedNode(it, spec) })
                }
                TaintKind.SANITIZER -> {
                    val matchingCalls = result.calls.filter { call ->
                        matchesSpec(call, spec)
                    }
                    matched.addAll(matchingCalls.map { MatchedNode(it, spec) })
                }
            }
        }

        return matched
    }

    private fun matchesSpec(call: Call, spec: TaintSpec): Boolean {
        val callName = call.name.toString()
        val localName = call.name.localName

        // Match by fully qualified name
        if (callName.endsWith(spec.fqn) || callName == spec.fqn) {
            return true
        }

        // Match by local name (last segment of FQN)
        val specLocalName = spec.fqn.substringAfterLast(".")
        if (localName == specLocalName) {
            // Check if any invoked function matches more closely
            val invokedMatch = call.invokes.any { invoked ->
                invoked.name.toString().endsWith(spec.fqn) ||
                    invoked.name.toString() == spec.fqn
            }
            if (invokedMatch) return true

            // Also accept local name match if we can't resolve further
            // (common when analyzing code without full classpath)
            return true
        }

        return false
    }

    private fun matchesParamSpec(param: Parameter, func: Function, spec: TaintSpec): Boolean {
        // Check if parameter type matches the source spec
        val typeName = param.type.name.toString()
        val specClass = spec.fqn.substringBeforeLast(".")
        return typeName.endsWith(specClass) || typeName == specClass
    }

    private fun extractHitSinks(
        queryTree: QueryTree<Boolean>,
        sinkNodes: List<MatchedNode>,
    ): List<Pair<MatchedNode, List<Node>>> {
        val results = mutableListOf<Pair<MatchedNode, List<Node>>>()
        val sinkNodeSet = sinkNodes.associateBy { it.node }

        extractPathsFromQueryTree(queryTree) { pathNodes ->
            val lastNode = pathNodes.lastOrNull()
            if (lastNode != null) {
                val matchedSink = sinkNodeSet[lastNode]
                if (matchedSink != null) {
                    results.add(matchedSink to pathNodes)
                }
            }
        }

        return results
    }

    private fun extractPathsFromQueryTree(
        queryTree: QueryTree<Boolean>,
        collector: (List<Node>) -> Unit,
    ) {
        // CPG query paths interleave Node objects with edge objects (e.g.
        // ContextSensitiveDataflow) since the main-SNAPSHOT API change.
        // filterIsInstance<Node>() drops the edges so downstream code sees a
        // clean List<Node>; an unchecked cast here would silently accept an
        // edge as a Node and ClassCastException at the call site.
        if (queryTree.value) {
            for (child in queryTree.children) {
                if (child.value == true) {
                    for (pathChild in child.children) {
                        val pathValue = pathChild.value
                        if (pathValue is List<*>) {
                            val nodes = pathValue.filterIsInstance<Node>()
                            if (nodes.isNotEmpty()) {
                                collector(nodes)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun checkSanitization(
        pathNodes: List<Node>,
        catalog: SourceSinkCatalog,
    ): Boolean {
        if (catalog.sanitizers.isEmpty()) return false

        // Check if any node in the taint path is a sanitizer
        return pathNodes.any { node ->
            if (node is Call) {
                catalog.sanitizers.any { sanitizerSpec ->
                    matchesSpec(node, sanitizerSpec)
                }
            } else {
                false
            }
        }
    }
}
