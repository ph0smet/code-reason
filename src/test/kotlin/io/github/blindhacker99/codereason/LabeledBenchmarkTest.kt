package io.github.blindhacker99.codereason

import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.functions
import de.fraunhofer.aisec.cpg.graph.nodes
import io.github.blindhacker99.codereason.analysis.RawFinding
import io.github.blindhacker99.codereason.analysis.TaintAnalyzer
import io.github.blindhacker99.codereason.analysis.analyzeProjectSources
import io.github.blindhacker99.codereason.catalog.CatalogRegistry
import io.github.blindhacker99.codereason.catalog.LanguageProfile
import io.github.blindhacker99.codereason.catalog.VulnClass
import io.github.blindhacker99.codereason.analysis.EvidenceChainBuilder
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
private data class BenchmarkLocation(val file: String, val line: Int)

@Serializable
private data class BenchmarkCase(
    val id: String,
    val path: String,
    val language: String,
    val vulnClass: String,
    val vulnerable: Boolean,
    val source: BenchmarkLocation? = null,
    val sink: BenchmarkLocation? = null,
    val generatedDistractors: Int = 0,
)

@Serializable
private data class BenchmarkManifest(val schemaVersion: Int, val cases: List<BenchmarkCase>)

@Serializable
private data class ObservedFinding(
    val source: BenchmarkLocation?,
    val sink: BenchmarkLocation?,
    val sanitized: Boolean,
    val pathLength: Int,
    val pathFiles: List<String>,
)

@Serializable
private data class BenchmarkCaseResult(
    val id: String,
    val language: String,
    val vulnClass: String,
    val expectedVulnerable: Boolean,
    val classification: String,
    val exactLocationMatch: Boolean,
    val reportedUnsanitized: Boolean,
    val unmatchedFindings: Int,
    val files: Int,
    val generatedDistractors: Int,
    val nodes: Int,
    val functions: Int,
    val calls: Int,
    val analysisMs: Double,
    val scanMs: Double,
    val rawFindingCount: Int,
    val findings: List<ObservedFinding>,
    val error: String? = null,
)

@Serializable
private data class BenchmarkSummary(
    val truePositive: Int,
    val falseNegative: Int,
    val falsePositive: Int,
    val trueNegative: Int,
    val errors: Int,
    val precision: Double?,
    val recall: Double?,
    val totalAnalysisMs: Double,
    val totalScanMs: Double,
)

@Serializable
private data class BenchmarkReport(
    val schemaVersion: Int,
    val javaVersion: String,
    val os: String,
    val results: List<BenchmarkCaseResult>,
    val summary: BenchmarkSummary,
)

/** Opt-in benchmark; run with ./gradlew benchmark. A miss is recorded, not hidden as a test failure. */
class LabeledBenchmarkTest {
    private val json = Json { prettyPrint = true }

    @Test
    fun runLabeledCorpus() {
        val root = File("src/test/resources/benchmark").canonicalFile
        val manifest = json.decodeFromString<BenchmarkManifest>(File(root, "cases.json").readText())
        assertEquals(1, manifest.schemaVersion)
        assertTrue(manifest.cases.size >= 10)
        assertEquals(manifest.cases.size, manifest.cases.map { it.id }.distinct().size)
        assertTrue(manifest.cases.any { it.language == "java" && !it.vulnerable })
        assertTrue(manifest.cases.any { it.language == "python" && !it.vulnerable })

        val results = manifest.cases.map { benchmarkCase(root, it) }
        val summary = summarize(results)
        val report = BenchmarkReport(
            schemaVersion = 1,
            javaVersion = System.getProperty("java.version"),
            os = "${System.getProperty("os.name")} ${System.getProperty("os.arch")}",
            results = results,
            summary = summary,
        )

        val output = File(System.getProperty("benchmark.output", "build/reports/benchmark/results.json"))
        output.parentFile.mkdirs()
        output.writeText(json.encodeToString(report) + "\n")
        File(output.parentFile, "results.md").writeText(markdown(report))
        println("Benchmark: TP=${summary.truePositive}, FN=${summary.falseNegative}, " +
            "FP=${summary.falsePositive}, TN=${summary.trueNegative}, errors=${summary.errors}")
        println("Results: ${output.absolutePath}")
        assertEquals(0, summary.errors, "Benchmark setup failed; inspect ${output.absolutePath}")
    }

    private fun benchmarkCase(root: File, benchmarkCase: BenchmarkCase): BenchmarkCaseResult {
        require(benchmarkCase.language in setOf("java", "python"))
        require(benchmarkCase.vulnClass in setOf("sqli", "cmdi", "xss"))
        require(!benchmarkCase.vulnerable ||
            (benchmarkCase.source != null && benchmarkCase.sink != null))
        require(benchmarkCase.generatedDistractors in 0..200)
        val dir = File(root, "cases/${benchmarkCase.path}").canonicalFile
        require(dir.parentFile == File(root, "cases").canonicalFile && dir.isDirectory)
        val analysisDir = if (benchmarkCase.generatedDistractors == 0) dir else
            generateScaleCase(dir, benchmarkCase)
        val extension = if (benchmarkCase.language == "java") "java" else "py"
        val sources = analysisDir.walkTopDown().filter { it.isFile && it.extension == extension }
            .sortedBy { it.relativeTo(analysisDir).path }.toList()
        require(sources.isNotEmpty()) { "No source files for ${benchmarkCase.id}" }
        val vulnClass = VulnClass.entries.single { it.name.equals(benchmarkCase.vulnClass, true) }
        val language = LanguageProfile.entries.single { it.name.equals(benchmarkCase.language, true) }
        val catalog = CatalogRegistry.getCatalogs(vulnClass, language).single()

        var analysisMs = 0.0
        var scanMs = 0.0
        var nodeCount = 0
        var functionCount = 0
        var callCount = 0
        var rawFindings = emptyList<RawFinding>()
        var error: String? = null
        var context: de.fraunhofer.aisec.cpg.TranslationContext? = null
        try {
            val analysisStart = System.nanoTime()
            val analysis = analyzeProjectSources(sources, analysisDir)
            analysisMs = millisecondsSince(analysisStart)
            context = analysis.context
            nodeCount = analysis.result.nodes.size
            functionCount = analysis.result.functions.size
            callCount = analysis.result.calls.size

            val scanStart = System.nanoTime()
            rawFindings = TaintAnalyzer(analysis.result).analyzeCatalog(catalog)
            scanMs = millisecondsSince(scanStart)
        } catch (e: Exception) {
            error = "${e::class.simpleName}: ${e.message}"
        } finally {
            context?.executedFrontends?.forEach { it.cleanup() }
            if (analysisDir != dir) analysisDir.deleteRecursively()
        }

        val observed = rawFindings.map { raw ->
            val source = EvidenceChainBuilder.toLocationInfo(raw.source)
            val sink = EvidenceChainBuilder.toLocationInfo(raw.sink)
            ObservedFinding(
                source = source.file?.let { BenchmarkLocation(File(it).name, source.line ?: -1) },
                sink = sink.file?.let { BenchmarkLocation(File(it).name, sink.line ?: -1) },
                sanitized = raw.sanitized,
                pathLength = raw.pathNodes.size,
                pathFiles = raw.pathNodes.mapNotNull { it.location?.artifactLocation?.fileName }
                    .map { File(it).name }.distinct(),
            )
        }.distinctBy { Triple(it.source, it.sink, it.sanitized) }
        val unsanitized = observed.filterNot { it.sanitized }
        val matched = unsanitized.any { it.source == benchmarkCase.source && it.sink == benchmarkCase.sink }
        val classification = when {
            error != null -> "error"
            benchmarkCase.vulnerable && matched -> "tp"
            benchmarkCase.vulnerable -> "fn"
            unsanitized.isNotEmpty() -> "fp"
            else -> "tn"
        }
        val unmatched = unsanitized.count { it.source != benchmarkCase.source || it.sink != benchmarkCase.sink }
        return BenchmarkCaseResult(
            id = benchmarkCase.id,
            language = benchmarkCase.language,
            vulnClass = benchmarkCase.vulnClass,
            expectedVulnerable = benchmarkCase.vulnerable,
            classification = classification,
            exactLocationMatch = matched,
            reportedUnsanitized = unsanitized.isNotEmpty(),
            unmatchedFindings = unmatched,
            files = sources.size,
            generatedDistractors = benchmarkCase.generatedDistractors,
            nodes = nodeCount,
            functions = functionCount,
            calls = callCount,
            analysisMs = analysisMs,
            scanMs = scanMs,
            rawFindingCount = rawFindings.size,
            findings = observed,
            error = error,
        )
    }

    private fun generateScaleCase(dir: File, benchmarkCase: BenchmarkCase): File {
        val parent = File("build/benchmark-generated").apply { mkdirs() }
        val target = Files.createTempDirectory(parent.toPath(), "case-").toFile()
        dir.copyRecursively(target, overwrite = true)
        repeat(benchmarkCase.generatedDistractors) { index ->
            val name = "Noise%03d".format(index)
            val file = File(target, if (benchmarkCase.language == "java") "$name.java" else "${name.lowercase()}.py")
            file.writeText(if (benchmarkCase.language == "java") {
                "package benchmark.noise; public class $name { public String echo(String value) { return value + \"$index\"; } }\n"
            } else {
                "def ${name.lowercase()}(value):\n    return str(value) + '$index'\n"
            })
        }
        return target
    }

    private fun summarize(results: List<BenchmarkCaseResult>): BenchmarkSummary {
        val counts = results.groupingBy { it.classification }.eachCount()
        val tp = counts["tp"] ?: 0
        val fp = counts["fp"] ?: 0
        val fn = counts["fn"] ?: 0
        return BenchmarkSummary(
            truePositive = tp,
            falseNegative = fn,
            falsePositive = fp,
            trueNegative = counts["tn"] ?: 0,
            errors = counts["error"] ?: 0,
            precision = if (tp + fp == 0) null else tp.toDouble() / (tp + fp),
            recall = if (tp + fn == 0) null else tp.toDouble() / (tp + fn),
            totalAnalysisMs = results.sumOf { it.analysisMs },
            totalScanMs = results.sumOf { it.scanMs },
        )
    }

    private fun markdown(report: BenchmarkReport): String = buildString {
        appendLine("# Code Reason labeled benchmark")
        appendLine()
        appendLine("JVM: ${report.javaVersion}; OS: ${report.os}. Each case is analyzed in manifest order in one JVM. Times are single-run wall clock milliseconds and include JIT and cache effects. The 100-file variants add deterministic harmless files to the labeled cross-file case.")
        appendLine()
        appendLine("| Case | Language | Class | Label | Result | Files | CPG ms | Scan ms | Unmatched findings |")
        appendLine("| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: |")
        report.results.forEach { r ->
            appendLine("| ${r.id} | ${r.language} | ${r.vulnClass} | ${if (r.expectedVulnerable) "vulnerable" else "safe"} | ${r.classification.uppercase()} | ${r.files} | ${"%.2f".format(r.analysisMs)} | ${"%.2f".format(r.scanMs)} | ${r.unmatchedFindings} |")
        }
        appendLine()
        appendLine("TP=${report.summary.truePositive}, FN=${report.summary.falseNegative}, FP=${report.summary.falsePositive}, TN=${report.summary.trueNegative}, errors=${report.summary.errors}.")
        appendLine("A positive case counts as detected only when an unsanitized finding matches both labeled source and sink file and line. Extra unmatched locations are shown separately; raw duplicate findings are retained in JSON. Precision and recall are case-level. These curated cases do not estimate performance on arbitrary repositories.")
    }

    private fun millisecondsSince(start: Long): Double =
        (System.nanoTime() - start) / 1_000_000.0
}
