package dev.clawdspy.tools

import dev.clawdspy.catalog.CatalogRegistry
import dev.clawdspy.catalog.LanguageProfile
import dev.clawdspy.catalog.VulnClass
import dev.clawdspy.model.CheckInfo
import dev.clawdspy.model.ListChecksPayload
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.Json

fun Server.addListChecksTool() {
    addTool<ListChecksPayload>(
        name = "spy_list_supported_checks",
        description =
            "List all supported vulnerability checks, including their source/sink/sanitizer definitions per language.",
    ) { payload ->
        val vulnClass =
            payload.vulnClass?.let { vc ->
                VulnClass.entries.find { it.name.equals(vc, ignoreCase = true) }
                    ?: throw IllegalArgumentException(
                        "Unknown vuln class: $vc. Valid: ${VulnClass.entries.map { it.name.lowercase() }}"
                    )
            }

        val language =
            payload.language?.let { lang ->
                LanguageProfile.entries.find { it.name.equals(lang, ignoreCase = true) }
                    ?: throw IllegalArgumentException(
                        "Unknown language: $lang. Valid: ${LanguageProfile.entries.map { it.name.lowercase() }}"
                    )
            }

        val catalogs = CatalogRegistry.getCatalogs(vulnClass, language)
        val checks =
            catalogs.map { catalog ->
                CheckInfo(
                    vulnClass = catalog.vulnClass.name.lowercase(),
                    cweId = catalog.vulnClass.cweId,
                    cweName = catalog.vulnClass.cweName,
                    language = catalog.language.name.lowercase(),
                    sourcesCount = catalog.sources.size,
                    sinksCount = catalog.sinks.size,
                    sanitizersCount = catalog.sanitizers.size,
                    sources = catalog.sources.map { "${it.fqn} — ${it.description}" },
                    sinks = catalog.sinks.map { "${it.fqn} — ${it.description}" },
                    sanitizers = catalog.sanitizers.map { "${it.fqn} — ${it.description}" },
                )
            }

        CallToolResult(
            content = listOf(TextContent(Json.encodeToString(checks)))
        )
    }
}
