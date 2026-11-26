package io.github.blindhacker99.codereason

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.nodes
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import io.github.blindhacker99.codereason.analysis.EvidenceChainBuilder
import io.github.blindhacker99.codereason.analysis.traverseDataflow
import io.github.blindhacker99.codereason.tools.resolveDataflowNode
import io.github.blindhacker99.codereason.tools.traceAndBuildChain
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class AnalysisResultsIntegrationTest {
    private fun analyze() = File(javaClass.classLoader.getResource("fixtures/java/dataflow/AnalysisResults.java")!!.toURI()).let { file ->
        val config = TranslationConfiguration.builder()
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.java.JavaLanguage")
            .topLevel(file.parentFile)
            .sourceLocations(listOf(file))
            .defaultPasses()
            .registerPass<ControlDependenceGraphPass>()
            .registerPass<ProgramDependenceGraphPass>()
            .inferenceConfiguration(InferenceConfiguration.builder().inferRecords(true).build())
            .debugParser(true)
            .build()
        TranslationManager.builder().config(config).build().analyze(TranslationContext(config)).get()
    }

    @Test
    fun `independent value does not produce a fabricated path`() {
        val result = analyze()
        val source = result.calls.first { it.name.localName == "input" && it.location?.region?.startLine == 6 }
        val sink = result.calls.first { it.name.localName == "sink" && it.location?.region?.startLine == 8 }
        val chain = traceAndBuildChain(source, sink, "custom", EvidenceChainBuilder())

        assertFalse(chain.reachable)
        assertEquals("incomplete", chain.status)
        assertTrue(chain.stoppedAt.isNotEmpty())
        assertEquals(0, chain.pathLength)
        assertTrue(chain.steps.isEmpty())
        assertFalse(chain.sanitizationEvaluated)
    }

    @Test
    fun `isolated value reports no path found in current graph`() {
        val result = analyze()
        val source = result.calls.first { it.name.localName == "input" && it.location?.region?.startLine == 13 }
        val sink = result.calls.first { it.name.localName == "sink" && it.location?.region?.startLine == 8 }
        val chain = traceAndBuildChain(source, sink, "custom", EvidenceChainBuilder())
        assertFalse(chain.reachable)
        assertEquals("not_found", chain.status)
        assertTrue(chain.steps.isEmpty())
    }

    @Test
    fun `bounded traversal reports truncation`() {
        val result = analyze()
        val source = result.calls.first { it.name.localName == "input" && it.location?.region?.startLine == 6 }
        val traversal = traverseDataflow(source, "forward", 1)
        assertEquals(1, traversal.reachable.size)
        assertTrue(traversal.truncated)
    }

    @Test
    fun `location ambiguity lists selectable IDs`() {
        val result = analyze()
        val error = assertFailsWith<IllegalArgumentException> {
            resolveDataflowNode(result, "AnalysisResults.java", 6, null)
        }
        assertTrue(error.message!!.contains("Multiple nodes"))
        val source = result.calls.first { it.name.localName == "input" && it.location?.region?.startLine == 6 }
        assertEquals(source, resolveDataflowNode(result, null, null, source.id.toString()))
    }

    @Test
    fun `unresolved call dead end is identified`() {
        val result = analyze()
        val call = result.calls.first { it.name.localName == "consume" && it.location?.region?.startLine == 9 }
        val traversal = traverseDataflow(call, "forward", 50)
        assertTrue(traversal.stoppedAt.any { it.nodeId == call.id.toString() })
    }

    @Test
    fun `record reproducible fixture baseline`() {
        val analysisStart = System.nanoTime()
        val result = analyze()
        val analysisMs = (System.nanoTime() - analysisStart) / 1_000_000
        val source = result.calls.first { it.name.localName == "input" && it.location?.region?.startLine == 6 }
        val sink = result.calls.first { it.name.localName == "sink" && it.location?.region?.startLine == 8 }

        val walkStart = System.nanoTime()
        val traversal = traverseDataflow(source, "forward", 5_000)
        val walkMs = (System.nanoTime() - walkStart) / 1_000_000
        val traceStart = System.nanoTime()
        val chain = traceAndBuildChain(source, sink, "custom", EvidenceChainBuilder())
        val traceMs = (System.nanoTime() - traceStart) / 1_000_000

        assertFalse(chain.reachable)
        println("BASELINE_JSON {\"fixture\":\"AnalysisResults.java\",\"nodes\":${result.nodes.size}," +
            "\"calls\":${result.calls.size},\"reachableNodes\":${traversal.reachable.size}," +
            "\"gaps\":${traversal.stoppedAt.size},\"analysisMs\":$analysisMs," +
            "\"walkMs\":$walkMs,\"traceMs\":$traceMs}")
    }
}
