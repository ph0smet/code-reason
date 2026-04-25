package io.github.blindhacker99.codereason

import io.github.blindhacker99.codereason.server.configureServer
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.modelcontextprotocol.kotlin.sdk.server.StdioServerTransport
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.io.asSink
import kotlinx.io.asSource
import kotlinx.io.buffered
import picocli.CommandLine

@CommandLine.Command(name = "code-reason")
class Application : Runnable {
    @CommandLine.ArgGroup(exclusive = true, multiplicity = "0..1")
    var transport: TransportOptions? = null

    class TransportOptions {
        @CommandLine.Option(
            names = ["--stdio"],
            description = ["Run the MCP server using stdio (default option)."],
        )
        var stdio: Boolean = false

        @CommandLine.Option(
            names = ["--sse"],
            description = ["Provide the port to run SSE (Server Sent Events)."],
        )
        var ssePort: Int? = null

        @CommandLine.Option(
            names = ["--http"],
            description = ["Provide the port to run HTTP."],
        )
        var httpPort: Int? = null
    }

    @CommandLine.Option(
        names = ["--host"],
        description = ["Host address for the MCP server. Default is 0.0.0.0"],
    )
    var host: String? = null

    override fun run() {
        val host = host ?: "0.0.0.0"
        val httpPort = transport?.httpPort
        val ssePort = transport?.ssePort
        when {
            httpPort != null -> {
                runBlocking {
                    embeddedServer(CIO, host = host, port = httpPort) {
                        mcpStreamableHttp { configureServer() }
                    }.start(wait = true)
                }
            }
            ssePort != null -> {
                runBlocking {
                    embeddedServer(CIO, host = host, port = ssePort) {
                        mcp { configureServer() }
                    }.start(wait = true)
                }
            }
            else -> {
                runMcpServerUsingStdio()
            }
        }
    }
}

fun main(args: Array<String>) {
    CommandLine(Application()).execute(*args)
}

fun runMcpServerUsingStdio() {
    val server = configureServer()
    val transport =
        StdioServerTransport(System.`in`.asSource().buffered(), System.out.asSink().buffered())
    runBlocking {
        val job = Job()
        server.onClose { job.complete() }
        server.createSession(transport)
        job.join()
    }
}
