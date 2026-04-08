package dev.clawdspy

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.declarations.Function
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import dev.clawdspy.tools.resolveTargetFunctions
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class GraphExplorationIntegrationTest {

    private fun analyzeFile(resourcePath: String): de.fraunhofer.aisec.cpg.TranslationResult {
        val file = File(javaClass.classLoader.getResource(resourcePath)!!.toURI())

        val config = TranslationConfiguration.builder()
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.java.JavaLanguage")
            .topLevel(file.parentFile)
            .sourceLocations(listOf(file))
            .defaultPasses()
            .registerPass<ControlDependenceGraphPass>()
            .registerPass<ProgramDependenceGraphPass>()
            .inferenceConfiguration(
                InferenceConfiguration.builder().inferRecords(true).build()
            )
            .debugParser(true)
            .build()

        val ctx = TranslationContext(config)
        val analyzer = TranslationManager.builder().config(config).build()
        return analyzer.analyze(ctx).get()
    }

    @Test
    fun `find callers of processOrder`() {
        val result = analyzeFile("fixtures/java/callgraph/OrderService.java")

        val targets = resolveTargetFunctions(result, "processOrder", null, null)
        assertTrue(targets.isNotEmpty(), "Should find processOrder function")

        val processOrder = targets.first()
        val callers = result.callersOf(processOrder)

        println("Callers of processOrder: ${callers.map { it.name.toString() }}")
        assertTrue(callers.any { it.name.localName == "doGet" }, "doGet should call processOrder")
    }

    @Test
    fun `find callees of processOrder`() {
        val result = analyzeFile("fixtures/java/callgraph/OrderService.java")

        val targets = resolveTargetFunctions(result, "processOrder", null, null)
        assertTrue(targets.isNotEmpty(), "Should find processOrder function")

        val processOrder = targets.first()
        val callees = processOrder.callees

        println("Callees of processOrder: ${callees.map { it.name.toString() }}")
        assertTrue(
            callees.any { it.name.localName == "validate" },
            "processOrder should call validate"
        )
        assertTrue(
            callees.any { it.name.localName == "executeQuery" },
            "processOrder should call executeQuery"
        )
    }

    @Test
    fun `find callees of doGet includes processOrder and sendResponse`() {
        val result = analyzeFile("fixtures/java/callgraph/OrderService.java")

        val targets = resolveTargetFunctions(result, "doGet", null, null)
        assertTrue(targets.isNotEmpty(), "Should find doGet function")

        val doGet = targets.first()
        val callees = doGet.callees

        println("Callees of doGet: ${callees.map { it.name.toString() }}")
        assertTrue(
            callees.any { it.name.localName == "processOrder" },
            "doGet should call processOrder"
        )
        assertTrue(
            callees.any { it.name.localName == "sendResponse" },
            "doGet should call sendResponse"
        )
    }

    @Test
    fun `dataflow forward from getParameter reaches executeQuery`() {
        val result = analyzeFile("fixtures/java/callgraph/OrderService.java")

        // Find the getParameter call node in doGet (line 11)
        val getParamCalls = result.calls.filter {
            it.name.localName == "getParameter"
        }
        assertTrue(getParamCalls.isNotEmpty(), "Should find getParameter call")

        val startNode = getParamCalls.first()

        // BFS forward through DFG
        val reachable = mutableSetOf<Node>()
        val visited = mutableSetOf<Node>()
        val queue = ArrayDeque<Node>()
        queue.add(startNode)
        visited.add(startNode)

        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            if (current != startNode) {
                reachable.add(current)
            }
            for (neighbor in current.nextDFG) {
                if (neighbor !in visited) {
                    visited.add(neighbor)
                    queue.add(neighbor)
                }
            }
        }

        println("Reachable from getParameter:")
        reachable.forEach { node ->
            println("  ${node::class.simpleName}: ${node.code?.take(60)} at ${node.location?.region?.startLine}")
        }

        // The tainted data should reach the executeQuery call
        val reachesSqlCall = reachable.any { node ->
            node.code?.contains("executeQuery") == true ||
                node.code?.contains("SELECT") == true
        }
        assertTrue(reachesSqlCall, "Data from getParameter should reach SQL execution")
    }

    @Test
    fun `resolve function by name finds correct functions`() {
        val result = analyzeFile("fixtures/java/callgraph/OrderService.java")

        val doGet = resolveTargetFunctions(result, "doGet", null, null)
        assertEquals(1, doGet.size, "Should find exactly one doGet")

        val validate = resolveTargetFunctions(result, "validate", null, null)
        assertEquals(1, validate.size, "Should find exactly one validate")

        val all = resolveTargetFunctions(result, "nonexistent", null, null)
        assertTrue(all.isEmpty(), "Should not find nonexistent function")
    }
}
