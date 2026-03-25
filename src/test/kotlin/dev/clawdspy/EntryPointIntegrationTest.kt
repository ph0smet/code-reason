package dev.clawdspy

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import dev.clawdspy.analysis.EntryPointFinder
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class EntryPointIntegrationTest {

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
    fun `finds servlet entry points`() {
        val result = analyzeFile("fixtures/java/entrypoints/SampleController.java")
        val finder = EntryPointFinder(result)

        val httpEntries = finder.findEntryPoints("http")

        println("HTTP entry points found: ${httpEntries.size}")
        httpEntries.forEach { ep ->
            println("  ${ep.httpMethod} ${ep.functionName} (${ep.framework}) at ${ep.file}:${ep.line}")
            ep.parameters.forEach { p ->
                println("    param: ${p.name} (${p.type}) source=${p.source}")
            }
        }

        assertTrue(httpEntries.isNotEmpty(), "Should find HTTP entry points")

        val getHandler = httpEntries.find { it.httpMethod == "GET" }
        assertTrue(getHandler != null, "Should find GET handler (doGet)")
        assertEquals("servlet", getHandler.framework)

        val postHandler = httpEntries.find { it.httpMethod == "POST" }
        assertTrue(postHandler != null, "Should find POST handler (doPost)")
    }

    @Test
    fun `finds main method`() {
        val result = analyzeFile("fixtures/java/entrypoints/SampleController.java")
        val finder = EntryPointFinder(result)

        val cliEntries = finder.findEntryPoints("cli")

        println("CLI entry points found: ${cliEntries.size}")
        cliEntries.forEach { ep ->
            println("  ${ep.functionName} (${ep.type}) at ${ep.file}:${ep.line}")
        }

        assertTrue(cliEntries.isNotEmpty(), "Should find main method")
        assertEquals("main", cliEntries.first().type)
    }

    @Test
    fun `does not flag helper methods`() {
        val result = analyzeFile("fixtures/java/entrypoints/SampleController.java")
        val finder = EntryPointFinder(result)

        val allEntries = finder.findEntryPoints("all")

        val helperFound = allEntries.any { it.functionName.contains("helperMethod") }
        assertTrue(!helperFound, "helperMethod should not be flagged as entry point")
    }
}
