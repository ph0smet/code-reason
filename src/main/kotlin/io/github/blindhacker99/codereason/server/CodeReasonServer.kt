package io.github.blindhacker99.codereason.server

import io.github.blindhacker99.codereason.tools.addAnalyzeProjectTool
import io.github.blindhacker99.codereason.tools.addFindCalleesTool
import io.github.blindhacker99.codereason.tools.addFindCallersTool
import io.github.blindhacker99.codereason.tools.addFindEntryPointsTool
import io.github.blindhacker99.codereason.tools.addGetFindingDetailTool
import io.github.blindhacker99.codereason.tools.addListChecksTool
import io.github.blindhacker99.codereason.tools.addQueryDataflowTool
import io.github.blindhacker99.codereason.tools.addScanInjectionsTool
import io.github.blindhacker99.codereason.tools.addTraceTaintPathTool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities

fun configureServer(): Server {
    val info = Implementation(name = "code-reason", version = "0.1.0")

    val options =
        ServerOptions(
            capabilities =
                ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = true),
                )
        )

    return Server(info, options).apply {
        addAnalyzeProjectTool()
        addFindEntryPointsTool()
        addScanInjectionsTool()
        addTraceTaintPathTool()
        addGetFindingDetailTool()
        addListChecksTool()
        addFindCallersTool()
        addFindCalleesTool()
        addQueryDataflowTool()
    }
}
