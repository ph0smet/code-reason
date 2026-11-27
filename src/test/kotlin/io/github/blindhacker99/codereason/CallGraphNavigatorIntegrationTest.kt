package io.github.blindhacker99.codereason

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.graph.functions
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import io.github.blindhacker99.codereason.analysis.CallGraphNavigator
import io.github.blindhacker99.codereason.analysis.EntryPointFinder
import io.github.blindhacker99.codereason.tools.resolveUniqueFunction
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class CallGraphNavigatorIntegrationTest {
    private fun analyze() = File(javaClass.classLoader.getResource("fixtures/java/callgraph/OrderService.java")!!.toURI()).let { file ->
        val config = TranslationConfiguration.builder()
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.java.JavaLanguage")
            .topLevel(file.parentFile)
            .sourceLocations(listOf(file))
            .defaultPasses()
            .registerPass<ControlDependenceGraphPass>()
            .registerPass<ProgramDependenceGraphPass>()
            .inferenceConfiguration(InferenceConfiguration.builder().inferRecords(true).build())
            .build()
        TranslationManager.builder().config(config).build().analyze(TranslationContext(config)).get()
    }

    @Test
    fun `forward and backward slices expose transitive functions`() {
        val result = analyze()
        val doGet = resolveUniqueFunction(result, "doGet", null, null, null)
        val executeQuery = resolveUniqueFunction(result, "OrderService.executeQuery", null, null, null)
        val navigator = CallGraphNavigator(result)

        val forward = navigator.slice(doGet, "forward", 2, 100)
        assertTrue(forward.nodes.any { it.function.name.endsWith("processOrder") && it.depth == 1 })
        assertTrue(forward.nodes.any { it.function.name.endsWith("executeQuery") && it.depth == 2 })
        assertTrue(forward.nodes.any { it.function.name.endsWith("validate") && it.depth == 2 })
        assertTrue(forward.nodes.filter { it.depth > 0 }.all { it.via != null })
        assertTrue(forward.unresolvedCalls.any { it.code?.contains("getParameter") == true })

        val backward = navigator.slice(executeQuery, "backward", 2, 100)
        assertTrue(backward.nodes.any { it.function.name.endsWith("processOrder") && it.depth == 1 })
        assertTrue(backward.nodes.any { it.function.name.endsWith("doGet") && it.depth == 2 })
    }

    @Test
    fun `entrypoint to target path includes call sites`() {
        val result = analyze()
        val entrypoints = EntryPointFinder(result).findEntryPoints()
        val sources = result.functions.filter { function ->
            entrypoints.any { it.functionName == function.name.toString() && it.line == function.location?.region?.startLine }
        }
        assertTrue(sources.any { it.name.localName == "doGet" })
        val target = resolveUniqueFunction(result, "OrderService.executeQuery", null, null, null)
        val paths = CallGraphNavigator(result).paths(sources, target, 4, 10, 100)
        val path = paths.paths.first { it.functions.first().name.endsWith("doGet") }
        assertEquals("found", paths.status)
        assertEquals(listOf("doGet", "processOrder", "executeQuery"), path.functions.map { it.name.substringAfterLast('.') })
        assertEquals(2, path.edges.size)
        assertTrue(path.edges.all { it.callSiteFound && it.callSiteLine != null })
    }

    @Test
    fun `limits are surfaced instead of silently losing paths`() {
        val result = analyze()
        val doGet = resolveUniqueFunction(result, "doGet", null, null, null)
        val target = resolveUniqueFunction(result, "OrderService.executeQuery", null, null, null)
        val navigator = CallGraphNavigator(result)
        val slice = navigator.slice(doGet, "forward", 4, 2)
        assertEquals(2, slice.nodes.size)
        assertTrue(slice.truncated)

        val paths = navigator.paths(listOf(doGet), target, 1, 10, 100)
        assertTrue(paths.paths.isEmpty())
        assertEquals("incomplete", paths.status)
        assertTrue(paths.truncated)
    }

    @Test
    fun `exact function ID resolves without a name guess`() {
        val result = analyze()
        val target = resolveUniqueFunction(result, "OrderService.executeQuery", null, null, null)
        val ambiguous = assertFailsWith<IllegalArgumentException> {
            resolveUniqueFunction(result, "executeQuery", null, null, null)
        }
        assertTrue(ambiguous.message!!.contains("Ambiguous function"))
        assertEquals(target, resolveUniqueFunction(result, "executeQuery", "OrderService.java", 25, null))
        assertEquals(target, resolveUniqueFunction(result, null, null, null, target.id.toString()))
    }
}
