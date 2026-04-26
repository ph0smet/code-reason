# Program analysis for your coding agents.

**code-reason** is an MCP server that gives coding agents real program-analysis reasoning — so they verify data flow, trace evidence chains, and navigate call graphs from ground truth, not guesswork.

Coding agents are good at reading code, but they struggle with whole-program questions:

- *Does user-controlled input actually reach this SQL call, or does sanitization cut the flow off?*
- *Who really invokes this function across the codebase?*
- *What is the complete evidence chain from source to sink?*

These are program-analysis questions. Answering them with grep-and-guess, or with ever-larger context windows, scales poorly and produces false confidence. They are better answered with a code property graph and a few well-chosen graph queries — exposed as MCP tools the agent drives directly.

**Tech stack.** code-reason uses [Fraunhofer AISEC's Code Property Graph](https://github.com/Fraunhofer-AISEC/cpg) for multi-language data-flow, control-flow, and taint analysis, and the [Kotlin MCP SDK](https://github.com/modelcontextprotocol/kotlin-sdk) to expose those capabilities as agent-callable tools.

**Long-term vision.** Make program-analysis primitives a first-class capability for coding agents — sharpening vulnerability detection precision, eliminating tokens wasted on speculative grep-and-guess exploration, and turning vulnerability hunting into a directed, evidence-driven workflow.

## How it works

code-reason sits between the coding agent and a code property graph. The agent drives — code-reason answers.

```
   Coding agent (Claude Code, Cursor, ...)
              │  MCP over stdio
              ▼
       code-reason server
              │
              ▼
   Fraunhofer CPG (Java + Python frontends)
              │
              ▼
        Target codebase
```

A typical loop runs in three phases:

1. **Analyze.** The agent calls `reason_analyze_project`. CPG parses the target codebase into a multi-graph: abstract syntax, control flow, data flow, and evaluation order — all in one queryable structure.

2. **Query.** The agent calls one or more `reason_*` tools, each of which translates to a focused graph operation: taint propagation, call-graph traversal, data-flow reachability, evidence-chain construction.

3. **Reason.** Each tool returns a structured result (locations, paths, confidence, evidence). The agent combines those results with its own contextual reasoning and decides what to ask next.

The agent provides the *intent* and high-level reasoning; code-reason provides *ground-truth answers* against the actual graph. No grep-and-guess, no oversized context dumps.

## Tools

code-reason exposes nine MCP tools, grouped by purpose:

| Group | Tool | Purpose |
|---|---|---|
| Analysis | `reason_analyze_project` | Parse a project into a CPG |
| Discovery | `reason_find_entry_points` | Locate HTTP handlers and CLI entry points |
| Discovery | `reason_list_supported_checks` | Enumerate built-in vulnerability checks |
| Graph | `reason_find_callers` | "Who calls this function?" |
| Graph | `reason_find_callees` | "What does this function call?" |
| Graph | `reason_query_dataflow` | Forward/backward reachability over the data-flow graph |
| Vulnerability | `reason_scan_injections` | Catalog-driven taint analysis (SQLi, XSS, command injection) |
| Vulnerability | `reason_trace_taint_path` | Full source-to-sink evidence chain for a finding |
| Vulnerability | `reason_get_finding_detail` | Complete finding description and remediation |

## Prerequisites

- JDK 21

The build pulls CPG artifacts from Maven Central and Sonatype Central Snapshots (the latter for `main-SNAPSHOT` until CPG 11.x lands as a stable release on Central). No sibling checkouts required.

## Build

```
./gradlew installDist
```

The launcher lands at `build/install/code-reason/bin/code-reason`.

## Running tests

```
./gradlew test
```

Twelve integration tests run the full pipeline against small Java and Python fixtures.

## Claude Code setup

Add code-reason to your `.mcp.json` (project-scoped) or `~/.claude/.mcp.json` (global):

```json
{
  "mcpServers": {
    "code-reason": {
      "command": "/absolute/path/to/build/install/code-reason/bin/code-reason",
      "args": ["--stdio"]
    }
  }
}
```

Restart Claude Code; the `reason_*` tools will appear in its tool list.

## Example workflow

A typical agent session looks like this:

1. Agent calls `reason_analyze_project` on the target codebase to build the CPG.
2. Agent calls `reason_find_entry_points` to enumerate reachable inputs.
3. Agent calls `reason_scan_injections` to surface candidate data flows.
4. For each candidate, agent calls `reason_trace_taint_path` to confirm reachability and retrieve the evidence chain.
5. Agent reasons about exploitability from the structured result.

At any step the agent can pivot through the graph on its own using `reason_find_callers`, `reason_find_callees`, or `reason_query_dataflow`.

## Supported languages

- Java
- Python

Additional CPG frontends (C/C++, Go, TypeScript, JVM, LLVM, Ruby) can be enabled by adding the corresponding `cpg-language-*` dependency in `build.gradle.kts`.

## Status

code-reason is v0.1.0 — early, research-grade. The build is currently pinned to CPG `main-SNAPSHOT`; this will move to a stable `11.x` release once Fraunhofer publishes one to Maven Central.

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

## Acknowledgments

Built on [Fraunhofer AISEC's Code Property Graph](https://github.com/Fraunhofer-AISEC/cpg).
