package io.github.blindhacker99.codereason

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import io.github.blindhacker99.codereason.analysis.EvidenceChainBuilder
import io.github.blindhacker99.codereason.analysis.traverseDataflow
import io.github.blindhacker99.codereason.tools.TraceTaintPathPayload
import io.github.blindhacker99.codereason.tools.resolveDataflowNode
import io.github.blindhacker99.codereason.tools.traceAndBuildChain
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Smoke test for reason_trace_taint_path's data-flow path construction.
 *
 * Locks in two things: (1) the TraceTaintPathPayload field names are wired correctly,
 * so accidental reordering or renaming fails at compile time; (2) selecting
 * actual DFG nodes produces a non-empty EvidenceChain for a known-reachable flow.
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
    fun `selected dataflow nodes produce a real direct assignment chain`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")

        val payload = TraceTaintPathPayload(
            sourceFile = "CollectionTaint.java",
            sourceLine = 17,
            sinkFile = "CollectionTaint.java",
            sinkLine = 19,
        )

        val sourceNode = result.calls.first { it.name.localName == "source" && it.location?.region?.startLine == 17 }
        val sinkNode = traverseDataflow(sourceNode, "forward", 5_000).reachable
            .firstOrNull { it.location?.region?.startLine == payload.sinkLine }
        assertNotNull(sinkNode, "A data-bearing node at CollectionTaint.java:19 must be reachable")

        val chain = traceAndBuildChain(sourceNode, sinkNode, "custom", EvidenceChainBuilder())

        assertTrue(chain.reachable, "Direct-assignment flow is reachable; trace must report reachable=true")
        assertEquals(17, chain.source.line)
        assertEquals(19, chain.sink.line)
        assertTrue(chain.steps.isNotEmpty(), "EvidenceChain must contain at least one step")
        assertTrue(chain.steps.none { it.explanation.contains("user-controlled") || it.explanation.contains("dangerous operation") })
        assertTrue(!chain.sanitizationEvaluated)
    }

    @Test
    fun `unresolved source coordinate reports an error`() {
        val result = analyzeFile("fixtures/java/dataflow/CollectionTaint.java")

        assertFailsWith<IllegalArgumentException> {
            resolveDataflowNode(result, "CollectionTaint.java", 9999, null)
        }
    }
}
