package io.github.blindhacker99.codereason.model

import kotlinx.serialization.Serializable

@Serializable
data class LocationInfo(
    val nodeId: String,
    val code: String? = null,
    val file: String? = null,
    val line: Int? = null,
    val column: Int? = null,
    val description: String,
)

@Serializable
data class Finding(
    val id: String,
    val vulnClass: String,
    val cweId: Int,
    val cweName: String,
    val severity: String,
    val confidence: Double,
    val source: LocationInfo,
    val sink: LocationInfo,
    val sanitizerPresent: Boolean,
    val summary: String,
    val evidenceChainPreview: String,
)

@Serializable
data class ScanSummary(
    val totalFindings: Int,
    val bySeverity: Map<String, Int>,
    val byVulnClass: Map<String, Int>,
)

@Serializable
data class ScanResult(
    val summary: ScanSummary,
    val findings: List<Finding>,
)
