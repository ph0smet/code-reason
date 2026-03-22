package dev.clawdspy.tools

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.functions
import de.fraunhofer.aisec.cpg.graph.nodes
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import dev.clawdspy.model.AnalyzeProjectPayload
import dev.clawdspy.model.AnalyzeProjectResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import java.io.File
import kotlinx.serialization.json.Json

fun Server.addAnalyzeProjectTool() {
    addTool<AnalyzeProjectPayload>(
        name = "spy_analyze_project",
        description =
            "Analyze a project directory or source file, building the Code Property Graph with all analysis passes for vulnerability detection.",
    ) { payload ->
        val file = File(payload.path)
        require(file.exists()) { "Path does not exist: ${payload.path}" }

        val sourceFiles =
            if (file.isDirectory) {
                file.walkTopDown()
                    .filter { it.isFile && isAnalyzableFile(it, payload.languages) }
                    .map { it.absolutePath }
                    .toList()
            } else {
                listOf(file.absolutePath)
            }

        require(sourceFiles.isNotEmpty()) { "No analyzable source files found at: ${payload.path}" }

        val topLevel = if (file.isDirectory) file else file.parentFile

        val config =
            TranslationConfiguration.builder()
                .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.java.JavaLanguage")
                .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage")
                .topLevel(topLevel)
                .sourceLocations(sourceFiles.map { File(it) })
                .defaultPasses()
                .registerPass<ControlDependenceGraphPass>()
                .registerPass<ProgramDependenceGraphPass>()
                .inferenceConfiguration(
                    InferenceConfiguration.builder().inferRecords(true).build()
                )
                .debugParser(true)
                .build()

        // Clean up previous analysis if any
        globalTranslationContext?.executedFrontends?.forEach { it.cleanup() }

        val ctx = TranslationContext(config)
        val analyzer = TranslationManager.builder().config(config).build()
        val result = analyzer.analyze(ctx).get()

        globalAnalysisResult = result
        globalTranslationContext = ctx

        val analysisResult =
            AnalyzeProjectResult(
                status = "ok",
                filesAnalyzed = sourceFiles.size,
                totalNodes = result.nodes.size,
                functions = result.functions.size,
                calls = result.calls.size,
            )

        CallToolResult(
            content = listOf(TextContent(Json.encodeToString(analysisResult)))
        )
    }
}

private fun isAnalyzableFile(file: File, languages: List<String>?): Boolean {
    val ext = file.extension.lowercase()
    val supportedByLanguage =
        mapOf(
            "java" to setOf("java"),
            "python" to setOf("py"),
        )

    return if (languages != null) {
        languages.any { lang ->
            supportedByLanguage[lang.lowercase()]?.contains(ext) == true
        }
    } else {
        supportedByLanguage.values.flatten().contains(ext)
    }
}
