package io.github.blindhacker99.codereason.model

import de.fraunhofer.aisec.cpg.passes.Description
import kotlinx.serialization.Serializable

@Serializable
data class AnalyzeProjectPayload(
    @Description("Absolute path to the project directory or source file to analyze.")
    val path: String,
    @Description("Languages to enable for analysis. Defaults to auto-detect. Options: java, python.")
    val languages: List<String>? = null,
)

@Serializable
data class ListChecksPayload(
    @Description("Filter by language: java, python. If omitted, shows all languages.")
    val language: String? = null,
    @Description("Filter by vulnerability class: sqli, xss, cmdi. If omitted, shows all.")
    val vulnClass: String? = null,
)

@Serializable
data class CheckInfo(
    val vulnClass: String,
    val cweId: Int,
    val cweName: String,
    val language: String,
    val sourcesCount: Int,
    val sinksCount: Int,
    val sanitizersCount: Int,
    val sources: List<String>,
    val sinks: List<String>,
    val sanitizers: List<String>,
)

@Serializable
data class AnalyzeProjectResult(
    val status: String,
    val filesAnalyzed: Int,
    val totalNodes: Int,
    val functions: Int,
    val calls: Int,
)
