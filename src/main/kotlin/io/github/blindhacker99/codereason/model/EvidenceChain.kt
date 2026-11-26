package io.github.blindhacker99.codereason.model

import kotlinx.serialization.Serializable

@Serializable
data class EvidenceStep(
    val step: Int,
    val nodeId: String,
    val nodeType: String?,
    val code: String?,
    val file: String?,
    val line: Int?,
    val explanation: String,
)

@Serializable
data class ReasoningInfo(
    val queryTreeSummary: String,
    val assumptions: List<String>,
    val confidence: Double,
)

@Serializable
data class AnalysisGap(
    val nodeId: String,
    val reason: String,
    val code: String?,
    val file: String?,
    val line: Int?,
)

@Serializable
data class EvidenceChain(
    val source: LocationInfo,
    val sink: LocationInfo,
    val reachable: Boolean,
    val sanitized: Boolean,
    val pathLength: Int,
    val steps: List<EvidenceStep>,
    val reasoning: ReasoningInfo,
    /** reachable, not_found, or incomplete. not_found means no path in the current graph. */
    val status: String = "reachable",
    val stoppedAt: List<AnalysisGap> = emptyList(),
    val truncated: Boolean = false,
    val sanitizationEvaluated: Boolean = true,
)
