package io.github.blindhacker99.codereason.analysis

import de.fraunhofer.aisec.cpg.InferenceConfiguration
import de.fraunhofer.aisec.cpg.TranslationConfiguration
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationManager
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.passes.ControlDependenceGraphPass
import de.fraunhofer.aisec.cpg.passes.ProgramDependenceGraphPass
import java.io.File

data class ProjectAnalysis(val context: TranslationContext, val result: TranslationResult)

/** Shared production analysis configuration, also used by the labeled benchmark. */
fun analyzeProjectSources(sourceFiles: List<File>, topLevel: File): ProjectAnalysis {
    require(sourceFiles.isNotEmpty()) { "No source files to analyze" }
    val config =
        TranslationConfiguration.builder()
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.java.JavaLanguage")
            .optionalLanguage("de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage")
            .topLevel(topLevel)
            .sourceLocations(sourceFiles)
            .defaultPasses()
            .registerPass<ControlDependenceGraphPass>()
            .registerPass<ProgramDependenceGraphPass>()
            .inferenceConfiguration(
                InferenceConfiguration.builder().inferRecords(true).build()
            )
            .debugParser(true)
            .build()

    val context = TranslationContext(config)
    val result = TranslationManager.builder().config(config).build().analyze(context).get()
    return ProjectAnalysis(context, result)
}
