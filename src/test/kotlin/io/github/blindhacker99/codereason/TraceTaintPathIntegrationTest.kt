package io.github.blindhacker99.codereason

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import io.github.blindhacker99.codereason.analysis.EvidenceChainBuilder
import io.github.blindhacker99.codereason.tools.TraceTaintPathPayload
import io.github.blindhacker99.codereason.tools.findBestNodeAtLocation
import io.github.blindhacker99.codereason.tools.traceAndBuildChain
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Smoke test for reason_trace_taint_path's source/sink coordinate input mode.
 *
 * Locks in two things: (1) the TraceTaintPathPayload field names are wired correctly,
 * so accidental reordering or renaming fails at compile time; (2) the file:line →
 * CPG node resolution + path-building pipeline produces a non-empty EvidenceChain
 * for a known-reachable flow.
 */
class TraceTaintPathIntegrationTest {

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

    @Test
    fun `file colon line input produces evidence chain for direct assignment flow`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")

        val payload = TraceTaintPathPayload(
            sourceFile = "CollectionTaint.java",
            sourceLine = 17,
            sinkFile = "CollectionTaint.java",
            sinkLine = 19,
        )

        val sourceNode = findBestNodeAtLocation(result, payload.sourceFile!!, payload.sourceLine!!)
        assertNotNull(sourceNode, "Source resolution must find a node at CollectionTaint.java:17")
        val sinkNode = findBestNodeAtLocation(result, payload.sinkFile!!, payload.sinkLine!!)
        assertNotNull(sinkNode, "Sink resolution must find a node at CollectionTaint.java:19")

        val chain = traceAndBuildChain(sourceNode, sinkNode, "custom", EvidenceChainBuilder())

        assertTrue(chain.reachable, "Direct-assignment flow is reachable; trace must report reachable=true")
        assertEquals(17, chain.source.line)
        assertEquals(19, chain.sink.line)
        assertTrue(chain.steps.isNotEmpty(), "EvidenceChain must contain at least one step")
    }

    @Test
    fun `unresolved source coordinate returns null`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")

        assertNull(
            findBestNodeAtLocation(result, "CollectionTaint.java", 9999),
            "Out-of-range line must return null so the tool can surface a clear error",
        )
    }
}
