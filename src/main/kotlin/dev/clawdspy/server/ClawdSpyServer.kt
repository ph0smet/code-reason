package dev.clawdspy.server

import dev.clawdspy.tools.addAnalyzeProjectTool
import dev.clawdspy.tools.addGetFindingDetailTool
import dev.clawdspy.tools.addListChecksTool
import dev.clawdspy.tools.addScanInjectionsTool
import dev.clawdspy.tools.addTraceTaintPathTool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities

fun configureServer(): Server {
    val info = Implementation(name = "clawd-spy", version = "0.1.0")

    val options =
        ServerOptions(
            capabilities =
                ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = true),
                )
        )

    return Server(info, options).apply {
        addAnalyzeProjectTool()
        addScanInjectionsTool()
        addTraceTaintPathTool()
        addGetFindingDetailTool()
        addListChecksTool()
    }
}
