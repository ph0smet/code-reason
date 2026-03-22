package dev.clawdspy.tools

import dev.clawdspy.analysis.ConfidenceScorer
import dev.clawdspy.analysis.EvidenceChainBuilder
import dev.clawdspy.analysis.TaintAnalyzer
import dev.clawdspy.catalog.CatalogRegistry
import dev.clawdspy.catalog.LanguageProfile
import dev.clawdspy.catalog.VulnClass
import dev.clawdspy.model.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import de.fraunhofer.aisec.cpg.passes.Description

@Serializable
data class ScanInjectionsPayload(
    @Description("Vulnerability classes to scan for: sqli, xss, cmdi. If omitted, scans all.")
    val vulnClasses: List<String>? = null,
    @Description("Minimum severity to include in results: low, medium, high. Default: low.")
    val severityThreshold: String? = null,
)

fun Server.addScanInjectionsTool() {
    addTool<ScanInjectionsPayload>(
        name = "spy_scan_injections",
        description =
            "Scan for injection vulnerabilities (SQLi, XSS, Command Injection) using taint analysis " +
                "with pre-configured source/sink/sanitizer definitions. Requires spy_analyze_project to be called first.",
    ) { payload ->
        val result = requireAnalysisResult()
        val analyzer = TaintAnalyzer(result)
        val chainBuilder = EvidenceChainBuilder()

        val requestedClasses = payload.vulnClasses?.map { vc ->
            VulnClass.entries.find { it.name.equals(vc, ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "Unknown vuln class: $vc. Valid: ${VulnClass.entries.map { it.name.lowercase() }}"
                )
        }

        val severityThreshold = payload.severityThreshold?.lowercase() ?: "low"
        val severityOrder = listOf("info", "low", "medium", "high", "critical")
        val minSeverityIndex = severityOrder.indexOf(severityThreshold).coerceAtLeast(0)

        val catalogs = CatalogRegistry.getCatalogs(vulnClass = null, language = null)
            .filter { requestedClasses == null || it.vulnClass in requestedClasses }

        val allFindings = mutableListOf<Finding>()
        var findingCounter = 0

        for (catalog in catalogs) {
            val rawFindings = analyzer.analyzeCatalog(catalog)

            for (raw in rawFindings) {
                val severity = ConfidenceScorer.severity(raw)
                val severityIndex = severityOrder.indexOf(severity)

                if (severityIndex < minSeverityIndex) continue

                findingCounter++
                val findingId = "finding-%03d".format(findingCounter)

                val chain = chainBuilder.buildChain(raw)
                val preview = raw.pathNodes
                    .mapNotNull { it.code?.take(40) }
                    .joinToString(" -> ")

                allFindings.add(
                    Finding(
                        id = findingId,
                        vulnClass = catalog.vulnClass.name.lowercase(),
                        cweId = catalog.vulnClass.cweId,
                        cweName = catalog.vulnClass.cweName,
                        severity = severity,
                        confidence = chain.reasoning.confidence,
                        source = chain.source,
                        sink = chain.sink,
                        sanitizerPresent = raw.sanitized,
                        summary = buildSummary(raw, chain),
                        evidenceChainPreview = preview,
                    )
                )
            }
        }

        // Store findings for later detail retrieval
        lastScanFindings = allFindings

        val bySeverity = allFindings.groupBy { it.severity }.mapValues { it.value.size }
        val byVulnClass = allFindings.groupBy { it.vulnClass }.mapValues { it.value.size }

        val scanResult = ScanResult(
            summary = ScanSummary(
                totalFindings = allFindings.size,
                bySeverity = bySeverity,
                byVulnClass = byVulnClass,
            ),
            findings = allFindings,
        )

        CallToolResult(
            content = listOf(TextContent(Json.encodeToString(scanResult)))
        )
    }
}

// Cache for findings so spy_get_finding_detail can retrieve them
var lastScanFindings: List<Finding> = emptyList()

private fun buildSummary(
    raw: dev.clawdspy.analysis.RawFinding,
    chain: dev.clawdspy.model.EvidenceChain,
): String {
    val sourceDesc = raw.source.spec.description
    val sinkDesc = raw.sink.spec.description
    val vulnName = raw.catalog.vulnClass.cweName
    val sanitizerNote = if (raw.sanitized) {
        " A sanitizer was found on the path, reducing the risk."
    } else {
        " No sanitization was found on the taint path."
    }

    return "Potential $vulnName: $sourceDesc flows to $sinkDesc " +
        "through ${chain.pathLength} nodes.$sanitizerNote"
}
