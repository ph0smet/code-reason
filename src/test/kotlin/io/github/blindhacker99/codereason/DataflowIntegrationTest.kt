package io.github.blindhacker99.codereason

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Regression suite for forward DFG taint propagation across four shapes:
 * direct assignment, array element write, List.add/get, Map.put/get.
 *
 * Cases 3 and 4 cover function summaries with `to: base` on inferred JDK methods.
 * These were gated on Fraunhofer-AISEC/cpg#2748 (the call-site reverse propagation
 * edge was missing); the upstream fix landed in #2781 (commit 562a692, 2026-06-05),
 * so taint now flows back to the variable through `list.add(taint); list.get(i)`.
 */
class DataflowIntegrationTest {

    private fun analyzeFile(resourcePath: String): TranslationResult {
        val file = File(javaClass.classLoader.getResource(resourcePath)!!.toURI())
        val summaries = File(javaClass.classLoader.getResource("fixtures/dfg-summaries.yml")!!.toURI())
        val config = TranslationConfiguration.builder()
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.java.JavaLanguage")
            .topLevel(file.parentFile)
            .sourceLocations(listOf(file))
            .defaultPasses()
            .registerPass<ControlDependenceGraphPass>()
            .registerPass<ProgramDependenceGraphPass>()
            .registerFunctionSummaries(summaries)
            .inferenceConfiguration(
                InferenceConfiguration.builder()
                    .inferRecords(true)
                    .inferFunctions(true)
                    .inferDfgForUnresolvedCalls(true)
                    .build()
            )
            .build()
        val ctx = TranslationContext(config)
        val analyzer = TranslationManager.builder().config(config).build()
        return analyzer.analyze(ctx).get()
    }

    private fun findSourceCallAtLine(result: TranslationResult, line: Int): Node {
        return result.calls.firstOrNull {
            it.name.localName == "source" && it.location?.region?.startLine == line
        } ?: error("No source() call at line $line")
    }

    private fun reachableViaDFG(start: Node): Set<Node> {
        val reachable = mutableSetOf<Node>()
        val visited = mutableSetOf<Node>()
        val queue = ArrayDeque<Node>()
        queue.add(start)
        visited.add(start)
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            if (current != start) reachable.add(current)
            for (neighbor in current.nextDFG) {
                if (neighbor !in visited) {
                    visited.add(neighbor)
                    queue.add(neighbor)
                }
            }
        }
        return reachable
    }

    private fun reachesSinkCallLine(reachable: Set<Node>, sinkCallLine: Int): Boolean =
        reachable.any { it.location?.region?.startLine == sinkCallLine }

    @Test
    fun `case 1 control - direct assignment propagates taint`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")
        val reachable = reachableViaDFG(findSourceCallAtLine(result, 17))
        assertTrue(reachesSinkCallLine(reachable, 19),
            "Direct assignment must propagate taint — if this fails, test wiring is broken")
    }

    @Test
    fun `case 2 array element write propagates taint`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")
        val reachable = reachableViaDFG(findSourceCallAtLine(result, 24))
        assertTrue(reachesSinkCallLine(reachable, 25),
            "Array element write should propagate taint")
    }

    @Test
    fun `case 3 List add then get propagates taint`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")
        val reachable = reachableViaDFG(findSourceCallAtLine(result, 30))
        assertTrue(reachesSinkCallLine(reachable, 31),
            "List.add → list.get(i) should propagate taint")
    }

    @Test
    fun `case 4 Map put then get propagates taint`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")
        val reachable = reachableViaDFG(findSourceCallAtLine(result, 36))
        assertTrue(reachesSinkCallLine(reachable, 37),
            "Map.put → map.get(k) should propagate taint")
    }
}
