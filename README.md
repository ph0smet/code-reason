# Program analysis for coding agents

**code-reason** is an [MCP](https://modelcontextprotocol.io) server that gives coding agents — like Claude Code — the program-analysis primitives they need to *reason about code* instead of guessing at it.

## What it is

Coding agents are good at reading code, but they struggle with whole-program questions:

- *Does user-controlled input actually reach this SQL call, or does sanitization cut the flow off?*
- *Who really invokes this function across the codebase?*
- *What is the complete evidence chain from source to sink?*

These are program-analysis questions. Answering them with grep-and-guess, or with ever-larger context windows, scales poorly and produces false confidence. They are better answered with a code property graph and a few well-chosen graph queries.

code-reason exposes those queries as MCP tools. The agent decides *what* to ask; code-reason mechanically answers:

- **Data-flow reachability** instead of hopeful pattern matching.
- **Call-graph navigation** instead of grep-based caller discovery.
- **Evidence chains** that demonstrate a vulnerability rather than assert one.

The philosophy is simple: the LLM provides the reasoning, code-reason provides the ground truth. Program analysis becomes a tool the agent drives, not a black-box scanner.

code-reason is built on [Fraunhofer AISEC's Code Property Graph (CPG)](https://github.com/Fraunhofer-AISEC/cpg) and supports Java and Python out of the box.

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

CPG artifacts are fetched from Maven Central — no sibling checkouts required.

## Build

```
./gradlew installDist
```

The launcher lands at `build/install/code-reason/bin/code-reason`.

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

Additional CPG frontends (C/C++, Go, TypeScript, JVM, LLVM, Ruby) can be wired in with minimal changes to `build.gradle.kts`.

## Status

code-reason is v0.1.0 — early, research-grade. Known limitations:

- Finding deduplication can surface multiple findings for a single root cause when several source specs match the same node.
- Not production-hardened; expect sharp edges.

## License

MIT. See [`LICENSE`](./LICENSE).

## Acknowledgments

Built on [Fraunhofer AISEC's Code Property Graph](https://github.com/Fraunhofer-AISEC/cpg).
