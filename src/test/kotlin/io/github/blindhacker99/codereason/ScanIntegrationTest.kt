package io.github.blindhacker99.codereason

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.functions
import de.fraunhofer.aisec.cpg.graph.nodes
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import io.github.blindhacker99.codereason.analysis.ConfidenceScorer
import io.github.blindhacker99.codereason.analysis.EvidenceChainBuilder
import io.github.blindhacker99.codereason.analysis.TaintAnalyzer
import io.github.blindhacker99.codereason.catalog.CatalogRegistry
import io.github.blindhacker99.codereason.catalog.LanguageProfile
import io.github.blindhacker99.codereason.catalog.VulnClass
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertEquals

class ScanIntegrationTest {

    private fun analyzeFile(resourcePath: String): de.fraunhofer.aisec.cpg.TranslationResult {
        val file = File(javaClass.classLoader.getResource(resourcePath)!!.toURI())

        val config = TranslationConfiguration.builder()
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.java.JavaLanguage")
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage")
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
    fun `analyze vulnerable servlet - CPG is built`() {
        val result = analyzeFile("fixtures/java/sqli/VulnerableServlet.java")

        assertTrue(result.nodes.isNotEmpty(), "CPG should have nodes")
        assertTrue(result.functions.isNotEmpty(), "CPG should have functions")
        assertTrue(result.calls.isNotEmpty(), "CPG should have calls")

        println("Nodes: ${result.nodes.size}")
        println("Functions: ${result.functions.size}")
        println("Calls: ${result.calls.size}")
        println("Call names: ${result.calls.map { it.name.toString() }}")
    }

    @Test
    fun `taint analyzer finds sqli in vulnerable servlet`() {
        val result = analyzeFile("fixtures/java/sqli/VulnerableServlet.java")
        val analyzer = TaintAnalyzer(result)

        val sqliCatalogs = CatalogRegistry.getCatalogs(VulnClass.SQLI, LanguageProfile.JAVA)
        assertTrue(sqliCatalogs.isNotEmpty(), "Should have Java SQLi catalog")

        val allFindings = sqliCatalogs.flatMap { analyzer.analyzeCatalog(it) }

        println("Raw findings count: ${allFindings.size}")
        allFindings.forEach { finding ->
            println("  Source: ${finding.source.spec.fqn} -> Sink: ${finding.sink.spec.fqn}")
            println("  Sanitized: ${finding.sanitized}")
            println("  Path length: ${finding.pathNodes.size}")
            println("  Path: ${finding.pathNodes.map { "${it::class.simpleName}(${it.code?.take(30)})" }}")
        }

        assertTrue(allFindings.isNotEmpty(), "Should find at least one SQLi vulnerability")
        assertFalse(allFindings.first().sanitized, "Vulnerability should not be sanitized")
    }

    @Test
    fun `evidence chain is built for finding`() {
        val result = analyzeFile("fixtures/java/sqli/VulnerableServlet.java")
        val analyzer = TaintAnalyzer(result)
        val chainBuilder = EvidenceChainBuilder()

        val sqliCatalogs = CatalogRegistry.getCatalogs(VulnClass.SQLI, LanguageProfile.JAVA)
        val findings = sqliCatalogs.flatMap { analyzer.analyzeCatalog(it) }

        assertTrue(findings.isNotEmpty(), "Should have findings to build chain for")

        val chain = chainBuilder.buildChain(findings.first())

        println("Evidence chain:")
        println("  Source: ${chain.source.code} at ${chain.source.file}:${chain.source.line}")
        println("  Sink: ${chain.sink.code} at ${chain.sink.file}:${chain.sink.line}")
        println("  Reachable: ${chain.reachable}")
        println("  Sanitized: ${chain.sanitized}")
        println("  Path length: ${chain.pathLength}")
        println("  Steps:")
        chain.steps.forEach { step ->
            println("    ${step.step}. [${step.nodeType}] ${step.code?.take(50)} — ${step.explanation}")
        }
        println("  Confidence: ${chain.reasoning.confidence}")

        assertTrue(chain.reachable, "Taint path should be reachable")
        assertFalse(chain.sanitized, "Should not be sanitized")
        assertTrue(chain.pathLength >= 2, "Path should have at least source and sink")
        assertTrue(chain.reasoning.confidence > 0.0, "Confidence should be positive")
    }

    @Test
    fun `safe servlet has no unsanitized findings`() {
        val result = analyzeFile("fixtures/java/sqli/SafeServlet.java")
        val analyzer = TaintAnalyzer(result)

        val sqliCatalogs = CatalogRegistry.getCatalogs(VulnClass.SQLI, LanguageProfile.JAVA)
        val findings = sqliCatalogs.flatMap { analyzer.analyzeCatalog(it) }

        println("Safe servlet findings: ${findings.size}")
        findings.forEach { finding ->
            println("  Source: ${finding.source.spec.fqn} -> Sink: ${finding.sink.spec.fqn}")
            println("  Sanitized: ${finding.sanitized}")
        }

        // Either no findings, or all findings should be sanitized
        val unsanitized = findings.filter { !it.sanitized }
        assertTrue(
            unsanitized.isEmpty(),
            "Safe servlet should have no unsanitized findings, but found ${unsanitized.size}"
        )
    }
}
